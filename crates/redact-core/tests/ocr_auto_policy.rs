//! OCR Auto-mode policy exercised against a real fixture's extracted text
//! (feature-gated: `ocr`; stub backend, so no models are required).

#![cfg(feature = "ocr")]

use image::RgbaImage;

use redact_core::Result;
use redact_core::engine::HayroDocument;
use redact_core::ocr::{OcrBackend, OcrMode, OcrOptions, ocr_page_from_doc_with_opts};
use redact_core::types::PageText;

/// Backend that never touches models — proves the render → backend → PageText
/// wiring path used by the pipeline's Auto/On/Force branches end to end.
struct StubBackend;

impl OcrBackend for StubBackend {
    fn ocr_page(
        &self,
        _rgba: &RgbaImage,
        page_index: usize,
        page_width: f32,
        page_height: f32,
        _scale: f32,
    ) -> Result<PageText> {
        Ok(PageText {
            page_index,
            text: format!("stub ocr page {page_index}"),
            spans: vec![],
            width: page_width,
            height: page_height,
        })
    }
}

fn pii_basic() -> Vec<u8> {
    let path = concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../testdata/fixtures/synthetic/pii_basic.pdf"
    );
    std::fs::read(path).expect("fixture")
}

/// Auto mode with only the quality gate (char gate disabled) on a clean
/// digital fixture: every page must keep its native text layer.
#[test]
fn auto_mode_keeps_clean_native_text() {
    let doc = HayroDocument::open(pii_basic()).expect("open fixture");
    let opts = OcrOptions {
        mode: OcrMode::Auto,
        auto_min_chars: 0,
        ..Default::default()
    };
    assert!(doc.page_count() > 0, "fixture must have pages");
    for page in 0..doc.page_count() {
        let native = doc.page_text(page).expect("page text");
        let decision = opts.page_ocr_decision(&native.text);
        assert!(
            !decision.needs_ocr,
            "page {page}: clean native text must not trigger OCR: {:?}",
            decision.quality.as_ref().map(|q| (&q.score, &q.reasons))
        );
        let q = decision.quality.expect("quality assessed above char gate");
        assert!(
            !q.is_poor(opts.min_text_layer_quality),
            "page {page}: clean native text scored poor"
        );
    }
}

/// Poor layers are selected for OCR, and a stub backend runs the same
/// render → OCR path the pipeline uses after the decision.
#[test]
fn auto_mode_triggers_ocr_for_poor_layers_via_stub_backend() {
    let opts = OcrOptions {
        mode: OcrMode::Auto,
        auto_min_chars: 0,
        ..Default::default()
    };
    // Long garbage passes a 32-char gate but fails the quality gate.
    let garbage = "%%%%$$$$####@@@@!!!!%%%%$$$$####@@@@!!!!%%%%$$$$####";
    assert!(garbage.chars().count() >= 32, "test text too short");
    let decision = opts.page_ocr_decision(garbage);
    assert!(decision.needs_ocr);
    let q = decision.quality.expect("quality assessed above char gate");
    assert!(q.is_poor(opts.min_text_layer_quality));

    let doc = HayroDocument::open(pii_basic()).expect("open fixture");
    let backend = StubBackend;
    let force = OcrOptions {
        mode: OcrMode::Force,
        scale: 1.5,
        ..Default::default()
    };
    let out = ocr_page_from_doc_with_opts(&doc, 0, &backend as &dyn OcrBackend, &force)
        .expect("stub OCR over real page");
    assert!(out.text.starts_with("stub ocr page 0"));
}
