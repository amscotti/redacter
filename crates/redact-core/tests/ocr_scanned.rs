//! Image-only (raster) fixture end-to-end: the OCR pipeline reads embedded
//! pixels back to text (feature-gated: `ocr`; C14-m2). No models are required
//! for the offline default run — when model files are absent a stub backend
//! stands in for the recognition pass, so the raster → OCR → detect wiring is
//! exercised against a real image-only page either way.

#![cfg(feature = "ocr")]

use std::sync::atomic::{AtomicUsize, Ordering};

use image::RgbaImage;
use redact_core::engine::HayroDocument;
use redact_core::ocr::{
    OcrBackend, OcrMode, OcrOptions, OcrsBackend, has_models, page_text_from_lines,
    resolve_models_dir,
};
use redact_core::{DetectOptions, PageText, Rect, Result, RunOptions, regions_for_options_with};
use redact_fixturegen::{EMAIL, PHONE, SSN, generate_ocr_scanned, load_font};

/// Backend that echoes the scanned fixture's secrets with per-word geometry,
/// standing in for a real recognition pass when models are not installed.
struct EchoStub {
    calls: AtomicUsize,
}

impl OcrBackend for EchoStub {
    fn ocr_page(
        &self,
        _rgba: &RgbaImage,
        page_index: usize,
        page_width: f32,
        page_height: f32,
        _scale: f32,
    ) -> Result<PageText> {
        self.calls.fetch_add(1, Ordering::SeqCst);
        let lines = vec![
            vec![word("SCANNED", 72.0, 72.0), word("COPY", 140.0, 72.0)],
            vec![word("Email:", 72.0, 100.0), word(EMAIL, 130.0, 100.0)],
            vec![word("SSN:", 72.0, 130.0), word(SSN, 120.0, 130.0)],
            vec![word("Phone:", 72.0, 160.0), word(PHONE, 130.0, 160.0)],
        ];
        Ok(page_text_from_lines(
            page_index,
            page_width,
            page_height,
            &lines,
        ))
    }
}

fn word(text: &str, x: f32, y: f32) -> redact_core::OcrWord {
    redact_core::OcrWord {
        text: text.to_string(),
        rect: Rect::new(x, y, 180.0, 16.0),
    }
}

#[test]
fn auto_mode_detects_secrets_in_image_only_fixture() {
    let dir = tempfile::tempdir().unwrap();
    let font = load_font(None).expect("fixture font");
    let fixture = generate_ocr_scanned(dir.path(), &font).expect("generate scanned fixture");
    let bytes = std::fs::read(dir.path().join("ocr_scanned.pdf")).expect("read scanned fixture");

    // The fixture is genuinely image-only: no text layer survives.
    let doc = HayroDocument::open(bytes.clone()).expect("open scanned fixture");
    assert_eq!(doc.page_count(), 1);
    assert!(
        doc.page_text(0).unwrap().text.is_empty(),
        "scanned fixture must have no text layer"
    );
    let (w, h) = doc.render_dimensions(0).unwrap();
    assert!(w > 0.0 && h > 0.0);

    // Auto mode must decide to OCR a page with no native text.
    let ocr = OcrOptions {
        mode: OcrMode::Auto,
        ..Default::default()
    };
    assert!(
        ocr.page_needs_ocr_text(""),
        "empty native layer must trigger Auto OCR"
    );

    // Real ocrs when models are installed; echo stub otherwise. Both run the
    // same render → OCR → detect path over the embedded raster.
    let models_present = has_models(&resolve_models_dir(None));
    let mut loader = move || -> Result<Box<dyn OcrBackend>> {
        if models_present {
            Ok(Box::new(OcrsBackend::load(None)?) as Box<dyn OcrBackend>)
        } else {
            Ok(Box::new(EchoStub {
                calls: AtomicUsize::new(0),
            }) as Box<dyn OcrBackend>)
        }
    };

    let (regions, sources) = regions_for_options_with(
        &bytes,
        &RunOptions {
            detect: DetectOptions {
                ocr,
                ..Default::default()
            },
            run_detector: true,
            ..Default::default()
        },
        &mut loader,
    )
    .expect("auto regions over scanned fixture");

    // Every secret must be found with geometry on the raster page.
    let found: Vec<(String, String)> = regions
        .iter()
        .map(|r| (r.source_text.clone(), r.category.as_str().to_string()))
        .collect();
    for (secret, category) in [(EMAIL, "email"), (SSN, "ssn"), (PHONE, "phone")] {
        let hit = regions
            .iter()
            .find(|r| r.category.as_str() == category && r.source_text.contains(secret))
            .unwrap_or_else(|| panic!("missing {secret} ({category}) in regions: {found:?}"));
        assert!(
            hit.rects.iter().all(|rect| rect.is_valid()),
            "region for {secret} must carry valid geometry"
        );
    }

    // Auto-OCR pages are labeled hybrid (native layer kept, OCR unioned).
    assert!(
        sources.iter().all(|(_, s)| *s == "hybrid"),
        "Auto-OCR pages must be hybrid: {sources:?}"
    );

    // The fixture's ground truth names the same secrets.
    assert!(
        fixture
            .meta
            .must_detect
            .iter()
            .any(|i| i.category == "email" && i.text == EMAIL),
        "scanned meta must require the email"
    );
}
