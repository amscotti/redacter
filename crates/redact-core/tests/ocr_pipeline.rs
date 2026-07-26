//! Pipeline-level OCR tests with an injected stub backend (feature-gated:
//! `ocr`; no models required). Exercises On/Auto/Force modes through
//! `regions_for_options_with` / `detect_document_with` plus the sparse-retry
//! branch of `ocr_page_from_doc_with_opts` (C13-m3).

#![cfg(feature = "ocr")]

use std::sync::atomic::{AtomicUsize, Ordering};

use image::RgbaImage;

use redact_core::engine::HayroDocument;
use redact_core::{
    ApplyOptions, Category, DetectOptions, OcrBackend, OcrMode, OcrOptions, OcrWord, PageText,
    Rect, Result, RunOptions, ocr_page_from_doc_with_opts, page_text_from_lines,
    regions_for_options_with,
};

fn pii_basic() -> Vec<u8> {
    let path = concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../testdata/fixtures/synthetic/pii_basic.pdf"
    );
    std::fs::read(path).expect("fixture")
}

/// Build a `PageText` with one span per whitespace word (rects laid out
/// across the page), so detector/search hits always map to geometry.
fn stub_page_text(page_index: usize, page_width: f32, page_height: f32, text: &str) -> PageText {
    let words: Vec<OcrWord> = text
        .split_whitespace()
        .enumerate()
        .map(|(wi, w)| OcrWord {
            text: w.to_string(),
            rect: Rect::new(10.0 + wi as f32 * 60.0, 20.0, 50.0, 12.0),
        })
        .collect();
    page_text_from_lines(page_index, page_width, page_height, &[words])
}

/// Backend returning a fixed (PII-free) text — the OCR pass "sees" only this.
struct PiiFreeStub;

impl OcrBackend for PiiFreeStub {
    fn ocr_page(
        &self,
        _rgba: &RgbaImage,
        page_index: usize,
        page_width: f32,
        page_height: f32,
        _scale: f32,
    ) -> Result<PageText> {
        Ok(stub_page_text(
            page_index,
            page_width,
            page_height,
            "lorem ipsum dolor sit amet consectetur",
        ))
    }
}

/// Backend with a per-call script of texts + a call counter (sparse-retry
/// branch calls the backend twice at different scales).
struct SequenceStub {
    texts: Vec<String>,
    calls: AtomicUsize,
}

impl OcrBackend for SequenceStub {
    fn ocr_page(
        &self,
        _rgba: &RgbaImage,
        page_index: usize,
        page_width: f32,
        page_height: f32,
        _scale: f32,
    ) -> Result<PageText> {
        let call = self.calls.fetch_add(1, Ordering::SeqCst);
        let text = self.texts[call.min(self.texts.len() - 1)].clone();
        Ok(stub_page_text(page_index, page_width, page_height, &text))
    }
}

fn loader<B: OcrBackend + 'static>(
    make: impl Fn() -> B + 'static,
) -> impl FnMut() -> Result<Box<dyn OcrBackend>> {
    move || Ok(Box::new(make()) as Box<dyn OcrBackend>)
}

fn ocr_opts(mode: OcrMode, mutate: impl FnOnce(&mut OcrOptions)) -> DetectOptions {
    let mut ocr = OcrOptions {
        mode,
        ..Default::default()
    };
    mutate(&mut ocr);
    DetectOptions {
        ocr,
        ..Default::default()
    }
}

fn run_opts(detect: DetectOptions, run_detector: bool, search_texts: Vec<&str>) -> RunOptions {
    RunOptions {
        detect,
        apply: ApplyOptions::default(),
        search_texts: search_texts.into_iter().map(String::from).collect(),
        run_detector,
        ..Default::default()
    }
}

/// Key identifying a region's painted geometry for set comparison.
fn region_key(r: &redact_core::Region) -> (usize, String, String) {
    (
        r.page_index,
        r.source_text.clone(),
        format!("{:?}", r.rects),
    )
}

/// On mode unions native + OCR detections: OCR text with zero PII must not
/// shrink coverage vs. the native-only (Off) result.
#[test]
fn on_mode_union_keeps_all_native_regions() {
    let input = pii_basic();
    let off = regions_for_options_with(
        &input,
        &run_opts(ocr_opts(OcrMode::Off, |_| {}), true, vec![]),
        &mut loader(|| PiiFreeStub),
    )
    .expect("off regions");
    assert!(!off.0.is_empty(), "fixture must produce native detections");

    let on = regions_for_options_with(
        &input,
        &run_opts(ocr_opts(OcrMode::On, |_| {}), true, vec![]),
        &mut loader(|| PiiFreeStub),
    )
    .expect("on regions");

    let on_keys: std::collections::HashSet<_> = on.0.iter().map(region_key).collect();
    for native in &off.0 {
        assert!(
            on_keys.contains(&region_key(native)),
            "On-mode union must keep native region {:?}",
            region_key(native)
        );
    }
    // Every page that actually ran OCR is labeled hybrid.
    assert!(
        on.1.iter().all(|(_, s)| *s == "hybrid"),
        "On mode with detector must label every page hybrid: {:?}",
        on.1
    );
}

/// C13-M1 regression: Auto mode OCRs the page but must NOT drop the native
/// layer — a secret the (misrecognizing) OCR pass misses still redacts.
#[test]
fn auto_mode_keeps_native_regions_when_ocr_misses_the_secret() {
    let input = pii_basic();
    // Force OCR on every page via the char gate (native text is short).
    let detect = ocr_opts(OcrMode::Auto, |o| {
        o.auto_min_chars = usize::MAX;
    });
    let (regions, sources) = regions_for_options_with(
        &input,
        &run_opts(detect, true, vec![]),
        &mut loader(|| PiiFreeStub),
    )
    .expect("auto regions");

    assert!(
        regions.iter().any(|r| r.category == Category::Ssn),
        "Auto mode must keep native SSN detections even when OCR text has none; \
         regions: {:?}",
        regions
            .iter()
            .map(|r| (r.category, &r.source_text))
            .collect::<Vec<_>>()
    );
    assert!(
        sources.iter().all(|(_, s)| *s == "hybrid"),
        "Auto pages that ran OCR must be labeled hybrid: {:?}",
        sources
    );
}

/// Force is the OCR-only search path: a string present only in OCR text must
/// map, and the page is labeled "ocr" (native text is intentionally ignored).
#[test]
fn force_mode_searches_ocr_text_only() {
    struct ForceStub;
    impl OcrBackend for ForceStub {
        fn ocr_page(
            &self,
            _rgba: &RgbaImage,
            page_index: usize,
            page_width: f32,
            page_height: f32,
            _scale: f32,
        ) -> Result<PageText> {
            Ok(stub_page_text(
                page_index,
                page_width,
                page_height,
                "the secret token is stubmarker42 end",
            ))
        }
    }

    let input = pii_basic();
    let (regions, sources) = regions_for_options_with(
        &input,
        &run_opts(
            ocr_opts(OcrMode::Force, |_| {}),
            false,
            vec!["stubmarker42"],
        ),
        &mut loader(|| ForceStub),
    )
    .expect("force search regions");

    assert_eq!(
        regions.len(),
        1,
        "search-only Force must map the OCR-only string exactly once: {:?}",
        regions
    );
    assert_eq!(regions[0].source_text, "stubmarker42");
    assert!(
        sources.iter().all(|(_, s)| *s == "ocr"),
        "Force pages are OCR-only: {:?}",
        sources
    );
}

/// On mode searches both native and OCR text; a needle found by both layers
/// at the same place must map to exactly ONE region. The two layers' search
/// results are unioned like detect regions, so one physical occurrence is not
/// painted twice / listed twice in the certificate.
#[test]
fn on_mode_search_regions_are_deduped_across_layers() {
    struct FixedStub {
        text: String,
        rect: Rect,
    }
    impl OcrBackend for FixedStub {
        fn ocr_page(
            &self,
            _rgba: &RgbaImage,
            page_index: usize,
            page_width: f32,
            page_height: f32,
            _scale: f32,
        ) -> Result<PageText> {
            // Only page 0 carries the needle (at native geometry); other pages
            // return empty OCR text.
            if page_index != 0 {
                return Ok(stub_page_text(page_index, page_width, page_height, ""));
            }
            let words = vec![OcrWord {
                text: self.text.clone(),
                rect: self.rect,
            }];
            Ok(page_text_from_lines(
                page_index,
                page_width,
                page_height,
                &[words],
            ))
        }
    }

    let input = pii_basic();
    let doc = HayroDocument::open(input.clone()).expect("open fixture");
    let needle = "jane.doe@example.com";
    let mut native_occurrences = 0usize;
    let mut native_rect = None;
    for p in 0..doc.page_count() {
        let pt = doc.page_text(p).expect("page text");
        let hits = redact_core::geometry::regions_for_search_text(&pt, needle);
        native_occurrences += hits.len();
        if p == 0 {
            native_rect = hits.first().map(|r| r.rects[0]);
        }
    }
    assert!(native_occurrences > 0, "fixture must contain the needle");
    let rect = native_rect.expect("page 0 native needle geometry");

    // OCR stub returns the same needle at the exact same geometry as native
    // page 0, so both layers find the same physical occurrence there.
    let (regions, _) = regions_for_options_with(
        &input,
        &run_opts(ocr_opts(OcrMode::On, |_| {}), false, vec![needle]),
        &mut loader(move || FixedStub {
            text: needle.to_string(),
            rect,
        }),
    )
    .expect("on search regions");

    let hits: Vec<_> = regions.iter().filter(|r| r.source_text == needle).collect();
    assert_eq!(
        hits.len(),
        native_occurrences,
        "each physical occurrence must be listed exactly once (native + OCR \
         duplicates must be unioned away): {:?}",
        regions
    );
}

/// Sparse retry runs the backend a second time and keeps the longer pass
/// when quality ties (C13-M2 retry-selection).
#[test]
fn sparse_retry_runs_twice_and_keeps_longer_pass() {
    let doc = HayroDocument::open(pii_basic()).expect("open fixture");
    let stub = SequenceStub {
        texts: vec!["shorttext".into(), "amuchlongerpieceofcleantext".into()],
        calls: AtomicUsize::new(0),
    };
    let opts = OcrOptions {
        mode: OcrMode::Force,
        sparse_retry_chars: 1000, // force the retry branch
        ..Default::default()
    };
    let out =
        ocr_page_from_doc_with_opts(&doc, 0, &stub as &dyn OcrBackend, &opts).expect("retried OCR");
    assert_eq!(stub.calls.load(Ordering::SeqCst), 2, "retry must run twice");
    assert_eq!(out.text, "amuchlongerpieceofcleantext");
}

/// A hallucinating high-scale pass (more chars, garbage) must NOT displace an
/// accurate shorter pass — quality beats raw length (C13-M2).
#[test]
fn sparse_retry_prefers_quality_over_length() {
    let doc = HayroDocument::open(pii_basic()).expect("open fixture");
    let stub = SequenceStub {
        texts: vec![
            "SSN123456789".into(),
            "%%%%$$$$####@@@@!!!!%%%%$$$$####@@@@!!!!".into(),
        ],
        calls: AtomicUsize::new(0),
    };
    let opts = OcrOptions {
        mode: OcrMode::Force,
        sparse_retry_chars: 1000,
        ..Default::default()
    };
    let out =
        ocr_page_from_doc_with_opts(&doc, 0, &stub as &dyn OcrBackend, &opts).expect("retried OCR");
    assert_eq!(stub.calls.load(Ordering::SeqCst), 2);
    assert_eq!(out.text, "SSN123456789", "accurate short pass must win");
}

/// A score-0 retry (pure punctuation, no alphanumerics) must NOT displace an
/// empty first pass — zero-quality garbage is never better than nothing.
#[test]
fn sparse_retry_never_replaces_empty_with_punctuation() {
    let doc = HayroDocument::open(pii_basic()).expect("open fixture");
    let stub = SequenceStub {
        texts: vec!["".into(), "%%%%$$$$####@@@@!!!!".into()],
        calls: AtomicUsize::new(0),
    };
    let opts = OcrOptions {
        mode: OcrMode::Force,
        sparse_retry_chars: 1000, // force the retry branch
        ..Default::default()
    };
    let out =
        ocr_page_from_doc_with_opts(&doc, 0, &stub as &dyn OcrBackend, &opts).expect("retried OCR");
    assert_eq!(stub.calls.load(Ordering::SeqCst), 2, "retry must run twice");
    assert_eq!(
        out.text, "",
        "score-0 punctuation retry must not displace the empty first pass"
    );
}

/// The retry length floor is 50% more characters than the first pass, not
/// merely one more (comment/code mismatch): 12 chars is not 50% more than
/// 10, so the shorter first pass must win; exactly 15 (the floor) may.
#[test]
fn sparse_retry_floor_needs_fifty_percent_more_chars() {
    let doc = HayroDocument::open(pii_basic()).expect("open fixture");
    let opts = OcrOptions {
        mode: OcrMode::Force,
        sparse_retry_chars: 1000,
        ..Default::default()
    };
    // 10 chars → floor is 15; 12 is not enough.
    let stub = SequenceStub {
        texts: vec!["aabbccddee".into(), "aabbccddeeff".into()],
        calls: AtomicUsize::new(0),
    };
    let out =
        ocr_page_from_doc_with_opts(&doc, 0, &stub as &dyn OcrBackend, &opts).expect("retried OCR");
    assert_eq!(stub.calls.load(Ordering::SeqCst), 2, "retry must run twice");
    assert_eq!(
        out.text, "aabbccddee",
        "12 chars is not 50% more than 10; first pass must win"
    );
    // Exactly at the floor (15 chars ≥ 10 + 5) the retry wins.
    let stub = SequenceStub {
        texts: vec!["aabbccddee".into(), "aabbccddeefffff".into()],
        calls: AtomicUsize::new(0),
    };
    let out =
        ocr_page_from_doc_with_opts(&doc, 0, &stub as &dyn OcrBackend, &opts).expect("retried OCR");
    assert_eq!(
        out.text, "aabbccddeefffff",
        "15 chars is 50% more than 10; retry must win"
    );
}

/// Default near-empty gate: non-empty first-pass output retries nothing.
#[test]
fn no_retry_when_output_is_not_sparse() {
    let doc = HayroDocument::open(pii_basic()).expect("open fixture");
    let stub = SequenceStub {
        texts: vec!["shorttext".into()],
        calls: AtomicUsize::new(0),
    };
    let opts = OcrOptions {
        mode: OcrMode::Force,
        ..Default::default() // sparse_retry_chars = 0
    };
    let out = ocr_page_from_doc_with_opts(&doc, 0, &stub as &dyn OcrBackend, &opts)
        .expect("single-pass OCR");
    assert_eq!(
        stub.calls.load(Ordering::SeqCst),
        1,
        "no retry on non-empty"
    );
    assert_eq!(out.text, "shorttext");
}

/// An invalid retry scale is an explicit error, not a silent no-op clamp
/// (C13-n4).
#[test]
fn invalid_retry_scale_errors() {
    let doc = HayroDocument::open(pii_basic()).expect("open fixture");
    let stub = SequenceStub {
        texts: vec!["".into()], // empty first pass → retry branch
        calls: AtomicUsize::new(0),
    };
    let opts = OcrOptions {
        mode: OcrMode::Force,
        retry_scale: 0.0,
        ..Default::default()
    };
    let err = ocr_page_from_doc_with_opts(&doc, 0, &stub as &dyn OcrBackend, &opts)
        .expect_err("retry_scale 0 must be rejected");
    assert!(
        format!("{err}").contains("retry_scale"),
        "error should name retry_scale: {err}"
    );
}

/// text_sources labels follow what actually ran: Off stays native, Auto stays
/// native when the decision says no OCR, and Force is ocr everywhere.
#[test]
fn text_sources_labels_match_what_ran() {
    let input = pii_basic();
    let mut load = loader(|| PiiFreeStub);

    // Off mode with a clean digital fixture → all native.
    let (_, off_sources) = regions_for_options_with(
        &input,
        &run_opts(ocr_opts(OcrMode::Off, |_| {}), true, vec![]),
        &mut load,
    )
    .expect("off");
    assert!(
        off_sources.iter().all(|(_, s)| *s == "native"),
        "Off must stay native: {:?}",
        off_sources
    );

    // Auto with the quality gate only (char gate disabled) on a clean digital
    // fixture → the decision keeps every page native.
    let (_, auto_sources) = regions_for_options_with(
        &input,
        &run_opts(
            ocr_opts(OcrMode::Auto, |o| {
                o.auto_min_chars = 0;
            }),
            true,
            vec![],
        ),
        &mut load,
    )
    .expect("auto-clean");
    assert!(
        auto_sources.iter().all(|(_, s)| *s == "native"),
        "clean digital pages must stay native under Auto: {:?}",
        auto_sources
    );
}
