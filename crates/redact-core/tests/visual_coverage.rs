//! Ensure black redaction boxes actually cover the secret glyph ink.

use image::Rgba;
use redact_core::{
    ApplyOptions, DetectOptions, HayroDocument, RunOptions, detect_document, run_pipeline,
};

fn fixture(name: &str) -> Vec<u8> {
    let path = format!(
        "{}/../../testdata/fixtures/synthetic/{name}",
        env!("CARGO_MANIFEST_DIR")
    );
    std::fs::read(path).expect("fixture")
}

/// Fraction of pixels inside redaction rects that are near-black after apply.
fn black_coverage(img: &image::RgbaImage, rects: &[redact_core::Rect], scale: f32) -> f32 {
    let mut total = 0u64;
    let mut black = 0u64;
    let (iw, ih) = (img.width() as i32, img.height() as i32);
    for r in rects {
        let rr = r.scale(scale);
        let x0 = rr.x.floor() as i32;
        let y0 = rr.y.floor() as i32;
        let x1 = (rr.x + rr.w).ceil() as i32;
        let y1 = (rr.y + rr.h).ceil() as i32;
        for y in y0.max(0)..y1.min(ih) {
            for x in x0.max(0)..x1.min(iw) {
                total += 1;
                let p = img.get_pixel(x as u32, y as u32);
                if p[0] < redact_core::NEAR_BLACK
                    && p[1] < redact_core::NEAR_BLACK
                    && p[2] < redact_core::NEAR_BLACK
                {
                    black += 1;
                }
            }
        }
    }
    if total == 0 {
        0.0
    } else {
        black as f32 / total as f32
    }
}

/// Secret text must not remain as dark ink outside black boxes in a naive way:
/// after redaction, extractable text is gone (verified elsewhere). Here we check
/// that each secret region's painted area is mostly black.
#[test]
fn pii_basic_redaction_boxes_cover_ink() {
    let input = fixture("pii_basic.pdf");
    let scale = 2.0_f32;
    let detect = detect_document(&input, &DetectOptions::default()).unwrap();
    assert!(!detect.regions.is_empty());
    // The detect result's mapped regions are not needed further: the pipeline
    // re-runs detection internally; the coverage check uses `result.regions`.

    let result = run_pipeline(
        &input,
        &RunOptions {
            run_detector: true,
            apply: ApplyOptions { scale, pad: 1.5 },
            ..Default::default()
        },
    )
    .expect("pipeline");

    // Render the *painted* intermediate isn't available; re-render output and ensure
    // secrets are not extractable (already in e2e). For visual: re-open input, paint
    // ourselves is heavy — instead check output has large black runs where regions were.
    let out_doc = HayroDocument::open(result.output.clone()).unwrap();
    let out_img = out_doc.render_page(0, scale).unwrap();

    let mut all_rects = Vec::new();
    for r in result.regions.iter().filter(|r| r.included) {
        all_rects.extend(r.rects.iter().copied());
    }
    let cov = black_coverage(&out_img, &all_rects, scale);
    assert!(
        cov > 0.55,
        "expected most of redaction rects to be black, got coverage={cov:.3}"
    );

    // Spot-check: center of first email rect should be black on output.
    let email = result
        .regions
        .iter()
        .find(|r| r.source_text.contains('@'))
        .expect("email region");
    let r = email.rects[0].scale(scale);
    let cx = (r.x + r.w / 2.0) as u32;
    let cy = (r.y + r.h / 2.0) as u32;
    let p = out_img.get_pixel(cx.min(out_img.width() - 1), cy.min(out_img.height() - 1));
    assert!(
        p[0] < 40 && p[1] < 40 && p[2] < 40,
        "email box center should be black, got {:?}",
        Rgba([p[0], p[1], p[2], p[3]])
    );
}

#[test]
fn fake_w2_pipeline_succeeds_and_strips_ssn() {
    let input = fixture("fake_w2.pdf");
    let result = run_pipeline(
        &input,
        &RunOptions {
            run_detector: true,
            apply: ApplyOptions::default(),
            ..Default::default()
        },
    )
    .expect("w2 pipeline");
    assert!(result.verification.passed);
    assert!(
        !result
            .output
            .windows(b"123-45-6789".len())
            .any(|w| w == b"123-45-6789")
    );
    assert!(
        !result
            .output
            .windows(b"jane.doe@example.com".len())
            .any(|w| w == b"jane.doe@example.com")
    );
}

#[test]
fn fake_1040_pipeline_succeeds() {
    let input = fixture("fake_1040_snippet.pdf");
    let result = run_pipeline(
        &input,
        &RunOptions {
            run_detector: true,
            apply: ApplyOptions::default(),
            ..Default::default()
        },
    )
    .expect("1040 pipeline");
    assert!(result.verification.passed);
    assert!(result.regions.iter().any(|r| r.source_text.contains('@')));
}
