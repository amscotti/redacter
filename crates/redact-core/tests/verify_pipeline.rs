//! Edge-case verification against real redacted PDFs + synthetic byte fixtures.

use redact_core::{
    ApplyOptions, Category, MatchSource, RAW_SCAN_MIN_LEN, Rect, Region, RunOptions, apply_regions,
    looks_like_incremental_save, mask_pdf_stream_bodies, run_pipeline, verify_output,
};

fn pii_basic() -> Vec<u8> {
    let path = concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../testdata/fixtures/synthetic/pii_basic.pdf"
    );
    std::fs::read(path).expect("fixture")
}

#[test]
fn redacted_output_is_full_save_not_incremental() {
    let input = pii_basic();
    let result = run_pipeline(
        &input,
        &RunOptions {
            run_detector: true,
            apply: ApplyOptions::default(),
            ..Default::default()
        },
    )
    .expect("pipeline");

    assert!(
        !looks_like_incremental_save(&result.output),
        "output must not be an incremental update"
    );
    assert!(
        result
            .verification
            .checks
            .iter()
            .any(|c| c.id == "full-save" && c.passed),
        "full-save check must pass: {:?}",
        result.verification.checks
    );
    // No /Prev in the file at all for our writer.
    assert!(
        !result.output.windows(5).any(|w| w == b"/Prev"),
        "must not contain /Prev"
    );
}

#[test]
fn all_five_verification_checks_present() {
    let input = pii_basic();
    let result = run_pipeline(
        &input,
        &RunOptions {
            run_detector: true,
            apply: ApplyOptions::default(),
            search_texts: vec!["jane.doe@example.com".into()],
            ..Default::default()
        },
    )
    .expect("pipeline");

    let ids: Vec<_> = result
        .verification
        .checks
        .iter()
        .map(|c| c.id.as_str())
        .collect();
    for need in [
        "text-removal",
        "metadata-clean",
        "annotations-removed",
        "raw-byte-scan",
        "full-save",
    ] {
        assert!(ids.contains(&need), "missing check {need}: {ids:?}");
    }
    assert!(result.verification.passed);
}

#[test]
fn raw_byte_scan_fails_when_secret_injected_outside_stream() {
    let input = pii_basic();
    let mut out = apply_regions(
        &input,
        &[Region {
            page_index: 0,
            rects: vec![Rect::new(100.0, 100.0, 50.0, 12.0)],
            source_text: "jane.doe@example.com".into(),
            category: Category::Email,
            confidence: 1.0,
            included: true,
            source: MatchSource::Regex,
        }],
        &ApplyOptions::default(),
    )
    .expect("apply");

    // Inject secret as a PDF comment outside any stream (simulates leftover clear text).
    out.extend_from_slice(b"\n% LEAKED: jane.doe@example.com\n");

    let v = verify_output(
        &out,
        &[Region {
            page_index: 0,
            rects: vec![],
            source_text: "jane.doe@example.com".into(),
            category: Category::Email,
            confidence: 1.0,
            included: true,
            source: MatchSource::Regex,
        }],
    )
    .expect("verify");

    let raw = v
        .checks
        .iter()
        .find(|c| c.id == "raw-byte-scan")
        .expect("raw-byte-scan");
    assert!(!raw.passed, "should fail raw-byte-scan: {}", raw.detail);
    assert!(!v.passed);
}

#[test]
fn stream_mask_does_not_flag_secret_only_in_stream_body() {
    // Crafted PDF: secret lives only in a content stream body.
    let secret = "123-45-6789";
    assert!(secret.len() >= RAW_SCAN_MIN_LEN);

    let mut pdf = Vec::new();
    pdf.extend_from_slice(b"%PDF-1.4\n");
    pdf.extend_from_slice(b"1 0 obj\n<< /Length 20 >>\nstream\n");
    pdf.extend_from_slice(secret.as_bytes());
    pdf.extend_from_slice(b"\nendstream\nendobj\n");
    pdf.extend_from_slice(b"trailer\n<< /Size 1 >>\nstartxref\n0\n%%EOF\n");

    let masked = mask_pdf_stream_bodies(&pdf);
    assert!(
        !masked.windows(secret.len()).any(|w| w == secret.as_bytes()),
        "masked buffer must not contain secret"
    );
}

#[test]
fn excluded_regions_are_not_verified_as_secrets() {
    let input = pii_basic();
    // Redact nothing (empty included set) — should still produce a full image PDF.
    let regions = vec![Region {
        page_index: 0,
        rects: vec![Rect::new(0.0, 0.0, 10.0, 10.0)],
        source_text: "jane.doe@example.com".into(),
        category: Category::Email,
        confidence: 1.0,
        included: false, // excluded
        source: MatchSource::Regex,
    }];
    let out = apply_regions(&input, &regions, &ApplyOptions::default()).unwrap();
    let v = verify_output(&out, &regions).unwrap();
    // No included secrets → text-removal / raw-byte-scan should pass (nothing to prove).
    assert!(
        v.checks
            .iter()
            .find(|c| c.id == "text-removal")
            .unwrap()
            .passed
    );
    assert!(
        v.checks
            .iter()
            .find(|c| c.id == "raw-byte-scan")
            .unwrap()
            .passed
    );
}
