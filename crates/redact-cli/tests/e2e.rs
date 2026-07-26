//! Black-box e2e tests against real PDF fixtures.

use std::path::PathBuf;

use assert_cmd::Command;
use predicates::prelude::*;
use redact_core::{
    Category, FindingsFile, MatchSource, Rect, Region, assert_redacted, certificate_from_json,
    verify_output,
};

fn fixture(name: &str) -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../testdata/fixtures/synthetic")
        .join(name)
}

fn redact_bin() -> Command {
    Command::cargo_bin("redact").unwrap()
}

#[test]
fn e2e_cli_help() {
    redact_bin()
        .arg("--help")
        .assert()
        .success()
        .stdout(predicate::str::contains("Offline PDF redaction"));
}

#[test]
fn e2e_manual_text() {
    let dir = tempfile::tempdir().unwrap();
    let out = dir.path().join("out.pdf");
    let cert = dir.path().join("cert.json");

    redact_bin()
        .args([
            "run",
            fixture("pii_basic.pdf").to_str().unwrap(),
            "-o",
            out.to_str().unwrap(),
            "--cert",
            cert.to_str().unwrap(),
            "--text",
            "jane.doe@example.com",
            "--text",
            "123-45-6789",
            "--yes",
            "--no-detect",
        ])
        .assert()
        .success();

    let bytes = std::fs::read(&out).unwrap();
    let v = assert_redacted(&bytes, &["jane.doe@example.com", "123-45-6789"]).unwrap();
    assert!(v.passed, "{v:?}");

    let cert_json = std::fs::read_to_string(&cert).unwrap();
    let c = certificate_from_json(&cert_json).unwrap();
    assert_eq!(c.format, "redact-certificate/v1");
    assert!(c.verification.passed);
    assert!(!c.redactions.is_empty());
    // Certificate must not contain plaintext secrets.
    assert!(!cert_json.contains("jane.doe@example.com"));
    assert!(!cert_json.contains("123-45-6789"));
}

#[test]
fn e2e_search_text_line_split_and_missing() {
    let dir = tempfile::tempdir().unwrap();
    let out = dir.path().join("out.pdf");
    let cert = dir.path().join("cert.json");

    // In pii_basic.pdf the raw text contains "example.com" contiguously while
    // the spaced text splits it ("exam ple.com"), so only the raw-text
    // fallback can map it. The run must succeed (F1 fallback + F2 found).
    redact_bin()
        .args([
            "run",
            fixture("pii_basic.pdf").to_str().unwrap(),
            "-o",
            out.to_str().unwrap(),
            "--cert",
            cert.to_str().unwrap(),
            "--text",
            "example.com",
            "--yes",
            "--no-detect",
        ])
        .assert()
        .success();

    let bytes = std::fs::read(&out).unwrap();
    let v = assert_redacted(&bytes, &["example.com"]).unwrap();
    assert!(v.passed, "{v:?}");

    // A search string found nowhere must fail closed (F2): an explicit
    // redaction command must not export a passing certificate with the
    // secret still visible.
    redact_bin()
        .args([
            "run",
            fixture("pii_basic.pdf").to_str().unwrap(),
            "-o",
            out.to_str().unwrap(),
            "--text",
            "needle-that-does-not-exist-anywhere",
            "--yes",
            "--no-detect",
        ])
        .assert()
        .failure();
}

#[test]
fn e2e_full_detector_pipeline() {
    let dir = tempfile::tempdir().unwrap();
    let out = dir.path().join("out.pdf");
    let cert = dir.path().join("cert.json");

    redact_bin()
        .args([
            "run",
            fixture("pii_basic.pdf").to_str().unwrap(),
            "-o",
            out.to_str().unwrap(),
            "--cert",
            cert.to_str().unwrap(),
            "--yes",
        ])
        .assert()
        .success();

    let bytes = std::fs::read(&out).unwrap();
    for secret in [
        "jane.doe@example.com",
        "123-45-6789",
        "4111 1111 1111 1111",
        "415-555-0132",
        "GB82 WEST 1234 5698 7654 32",
    ] {
        assert!(
            !bytes.windows(secret.len()).any(|w| w == secret.as_bytes()),
            "secret still in raw bytes: {secret}"
        );
    }
    let v = assert_redacted(
        &bytes,
        &[
            "jane.doe@example.com",
            "123-45-6789",
            "4111 1111 1111 1111",
            "415-555-0132",
        ],
    )
    .unwrap();
    assert!(v.passed, "{v:?}");
}

#[test]
fn e2e_detect_findings_json() {
    let dir = tempfile::tempdir().unwrap();
    let findings_path = dir.path().join("findings.json");

    redact_bin()
        .args([
            "detect",
            fixture("pii_basic.pdf").to_str().unwrap(),
            "-o",
            findings_path.to_str().unwrap(),
        ])
        .assert()
        .success();

    let f = FindingsFile::from_json(&std::fs::read_to_string(&findings_path).unwrap()).unwrap();
    assert!(f.items.iter().any(|i| i.category == "email"));
    assert!(f.items.iter().any(|i| i.category == "ssn"));
    assert!(f.items.iter().any(|i| i.category == "credit-card"));
}

#[test]
fn e2e_findings_exclude_then_redact() {
    let dir = tempfile::tempdir().unwrap();
    let findings_path = dir.path().join("findings.json");
    let out = dir.path().join("out.pdf");

    redact_bin()
        .args([
            "detect",
            fixture("pii_basic.pdf").to_str().unwrap(),
            "-o",
            findings_path.to_str().unwrap(),
        ])
        .assert()
        .success();

    let mut f = FindingsFile::from_json(&std::fs::read_to_string(&findings_path).unwrap()).unwrap();
    // Exclude email, keep the rest.
    for item in &mut f.items {
        if item.category == "email" {
            item.included = false;
        }
    }
    std::fs::write(&findings_path, f.to_json().unwrap()).unwrap();

    redact_bin()
        .args([
            "redact",
            fixture("pii_basic.pdf").to_str().unwrap(),
            "--findings",
            findings_path.to_str().unwrap(),
            "-o",
            out.to_str().unwrap(),
        ])
        .assert()
        .success();

    let bytes = std::fs::read(&out).unwrap();
    // SSN must be gone from raw bytes; email may remain visible as pixels but
    // after full-page rasterization text extract should not have SSN.
    assert!(
        !bytes
            .windows(b"123-45-6789".len())
            .any(|w| w == b"123-45-6789")
    );

    // m5: the excluded email rects must remain *unredacted* (non-black). Probe
    // by asking verify's pixel check to confirm the email rects are black — it
    // must fail, proving the exclusion left the region untouched.
    let email_items: Vec<_> = f.items.iter().filter(|i| i.category == "email").collect();
    assert!(
        !email_items.is_empty(),
        "fixture must contain email findings"
    );
    for item in email_items {
        let probe = verify_output(
            &bytes,
            &[Region {
                page_index: item.page,
                rects: item.rects.clone(),
                source_text: item.text.clone(),
                category: Category::Email,
                confidence: item.confidence,
                included: true,
                source: MatchSource::Manual,
            }],
        )
        .unwrap();
        let pixel = probe
            .checks
            .iter()
            .find(|c| c.id == "pixel-removal")
            .unwrap();
        assert!(
            !pixel.passed,
            "excluded email item {} must stay unredacted: {}",
            item.id, pixel.detail
        );
    }
}

#[test]
fn e2e_multipage() {
    let dir = tempfile::tempdir().unwrap();
    let out = dir.path().join("out.pdf");
    let cert = dir.path().join("cert.json");

    redact_bin()
        .args([
            "run",
            fixture("multipage_mixed.pdf").to_str().unwrap(),
            "-o",
            out.to_str().unwrap(),
            "--cert",
            cert.to_str().unwrap(),
            "--yes",
        ])
        .assert()
        .success();

    let bytes = std::fs::read(&out).unwrap();
    assert!(
        !bytes
            .windows(b"jane.doe@example.com".len())
            .any(|w| w == b"jane.doe@example.com")
    );
    assert!(
        !bytes
            .windows(b"123-45-6789".len())
            .any(|w| w == b"123-45-6789")
    );
}

#[test]
fn e2e_clean_document() {
    // m2: a run that finds nothing to redact must be refused (like `redact`
    // with an empty findings file), not silently rebuild the document as
    // image-only pages — the old rebuild destroyed the text layer of an
    // untouched document and still issued a certificate.
    let dir = tempfile::tempdir().unwrap();
    let out = dir.path().join("out.pdf");
    let cert = dir.path().join("cert.json");

    redact_bin()
        .args([
            "run",
            fixture("clean_lorem.pdf").to_str().unwrap(),
            "-o",
            out.to_str().unwrap(),
            "--cert",
            cert.to_str().unwrap(),
            "--yes",
        ])
        .assert()
        .failure()
        .stderr(predicate::str::contains("no included regions to redact"));

    assert!(!out.exists(), "no output must be written on refusal");
    assert!(!cert.exists(), "no certificate must be written on refusal");
}

#[test]
fn e2e_output_has_no_prev_incremental_chain() {
    let dir = tempfile::tempdir().unwrap();
    let out = dir.path().join("out.pdf");

    redact_bin()
        .args([
            "run",
            fixture("pii_basic.pdf").to_str().unwrap(),
            "-o",
            out.to_str().unwrap(),
            "--yes",
        ])
        .assert()
        .success();

    let bytes = std::fs::read(&out).unwrap();
    assert!(
        !bytes.windows(5).any(|w| w == b"/Prev"),
        "full save must not leave a /Prev incremental chain"
    );
    assert!(
        !redact_core::looks_like_incremental_save(&bytes),
        "verifier full-save heuristic"
    );
}

#[test]
fn e2e_verify_command() {
    let dir = tempfile::tempdir().unwrap();
    let out = dir.path().join("out.pdf");
    let findings = dir.path().join("findings.json");

    redact_bin()
        .args([
            "detect",
            fixture("pii_basic.pdf").to_str().unwrap(),
            "-o",
            findings.to_str().unwrap(),
        ])
        .assert()
        .success();

    redact_bin()
        .args([
            "redact",
            fixture("pii_basic.pdf").to_str().unwrap(),
            "--findings",
            findings.to_str().unwrap(),
            "-o",
            out.to_str().unwrap(),
        ])
        .assert()
        .success();

    redact_bin()
        .args([
            "verify",
            out.to_str().unwrap(),
            "--findings",
            findings.to_str().unwrap(),
        ])
        .assert()
        .success()
        .stdout(predicate::str::contains("PASS"));
}

// --- C12: exit-code contract (0 ok / 1 operational / 2 usage+IO) ---

#[test]
fn e2e_exit_code_usage_and_io_is_2() {
    let dir = tempfile::tempdir().unwrap();
    let in_pdf = fixture("pii_basic.pdf");
    let out = dir.path().join("out.pdf");

    // clap parse error → 2 (usage).
    redact_bin().arg("--no-such-flag").assert().code(2);
    // Missing input file → I/O error → 2.
    redact_bin()
        .args([
            "run",
            "/nonexistent/definitely-missing.pdf",
            "-o",
            out.to_str().unwrap(),
            "--yes",
        ])
        .assert()
        .code(2);
    // `redact` with no --findings/--text/--rect → 2 (usage).
    redact_bin()
        .args([
            "redact",
            in_pdf.to_str().unwrap(),
            "-o",
            out.to_str().unwrap(),
        ])
        .assert()
        .code(2);
    // `run` without --yes → 2 (usage).
    redact_bin()
        .args(["run", in_pdf.to_str().unwrap(), "-o", out.to_str().unwrap()])
        .assert()
        .code(2);
    // Out-of-range --min-confidence → clap usage → 2.
    redact_bin()
        .args([
            "detect",
            in_pdf.to_str().unwrap(),
            "--min-confidence",
            "1.5",
        ])
        .assert()
        .code(2);

    // `verify` with no inputs → 2 (usage) — needs a real output file so the
    // read succeeds and the missing-arg bail is what exits.
    redact_bin()
        .args([
            "run",
            in_pdf.to_str().unwrap(),
            "-o",
            out.to_str().unwrap(),
            "--text",
            "jane.doe@example.com",
            "--yes",
            "--no-detect",
        ])
        .assert()
        .success();
    redact_bin()
        .args(["verify", out.to_str().unwrap()])
        .assert()
        .code(2);
}

#[test]
fn e2e_malformed_input_data_is_usage_error() {
    let dir = tempfile::tempdir().unwrap();
    let in_pdf = fixture("pii_basic.pdf");
    let out = dir.path().join("out.pdf");
    let bad = dir.path().join("bad.json");
    std::fs::write(&bad, "{ not json").unwrap();

    redact_bin()
        .args([
            "redact",
            in_pdf.to_str().unwrap(),
            "--findings",
            bad.to_str().unwrap(),
            "-o",
            out.to_str().unwrap(),
        ])
        .assert()
        .code(2);

    redact_bin()
        .args([
            "verify",
            in_pdf.to_str().unwrap(),
            "--findings",
            bad.to_str().unwrap(),
        ])
        .assert()
        .code(2);

    // Malformed certificate file → 2.
    redact_bin()
        .args([
            "verify",
            in_pdf.to_str().unwrap(),
            "--cert",
            bad.to_str().unwrap(),
        ])
        .assert()
        .code(2);
}

#[test]
fn e2e_stale_findings_exit_1() {
    let dir = tempfile::tempdir().unwrap();
    let in_pdf = fixture("pii_basic.pdf");
    let findings = dir.path().join("findings.json");

    redact_bin()
        .args([
            "detect",
            in_pdf.to_str().unwrap(),
            "-o",
            findings.to_str().unwrap(),
        ])
        .assert()
        .success();

    // Byte-modified copy of the same fixture: sha256 differs → stale geometry
    // must be refused as an operational failure (exit 1, not usage 2).
    let mut modified = std::fs::read(&in_pdf).unwrap();
    modified.push(0);
    let altered = dir.path().join("altered.pdf");
    std::fs::write(&altered, &modified).unwrap();
    let out = dir.path().join("out.pdf");

    redact_bin()
        .args([
            "redact",
            altered.to_str().unwrap(),
            "--findings",
            findings.to_str().unwrap(),
            "-o",
            out.to_str().unwrap(),
        ])
        .assert()
        .code(1)
        .stderr(predicate::str::contains("different input"));
    assert!(
        !out.exists(),
        "no output must be written on staleness refusal"
    );
}

#[test]
fn e2e_cert_mismatch_exit_1() {
    let dir = tempfile::tempdir().unwrap();
    let out = dir.path().join("out.pdf");
    let cert = dir.path().join("cert.json");

    redact_bin()
        .args([
            "run",
            fixture("pii_basic.pdf").to_str().unwrap(),
            "-o",
            out.to_str().unwrap(),
            "--cert",
            cert.to_str().unwrap(),
            "--text",
            "jane.doe@example.com",
            "--yes",
            "--no-detect",
        ])
        .assert()
        .success();

    // Tamper with the output after certification: verify must fail with 1.
    let mut bytes = std::fs::read(&out).unwrap();
    bytes.push(0);
    std::fs::write(&out, &bytes).unwrap();

    redact_bin()
        .args([
            "verify",
            out.to_str().unwrap(),
            "--cert",
            cert.to_str().unwrap(),
        ])
        .assert()
        .code(1)
        .stderr(predicate::str::contains("certificate does not match"));
}

#[test]
fn e2e_manual_rect() {
    let dir = tempfile::tempdir().unwrap();
    let out = dir.path().join("out.pdf");

    redact_bin()
        .args([
            "redact",
            fixture("pii_basic.pdf").to_str().unwrap(),
            "--rect",
            "0:10,10,50,20",
            "-o",
            out.to_str().unwrap(),
        ])
        .assert()
        .success();

    let bytes = std::fs::read(&out).unwrap();
    assert!(!bytes.is_empty());
    assert!(
        !bytes.windows(5).any(|w| w == b"/Prev"),
        "full save must not leave a /Prev incremental chain"
    );
    // The painted rect must be black in an independent re-render of the output.
    let v = verify_output(
        &bytes,
        &[Region {
            page_index: 0,
            rects: vec![Rect::new(10.0, 10.0, 50.0, 20.0)],
            source_text: "manual".into(),
            category: Category::Custom,
            confidence: 1.0,
            included: true,
            source: MatchSource::Manual,
        }],
    )
    .unwrap();
    let pixel = v.checks.iter().find(|c| c.id == "pixel-removal").unwrap();
    assert!(pixel.passed, "rect must be painted black: {}", pixel.detail);
}

#[test]
fn e2e_findings_plus_text_merge_path() {
    let dir = tempfile::tempdir().unwrap();
    let in_pdf = fixture("pii_basic.pdf");
    let findings = dir.path().join("findings.json");
    let out = dir.path().join("out.pdf");

    redact_bin()
        .args([
            "detect",
            in_pdf.to_str().unwrap(),
            "-o",
            findings.to_str().unwrap(),
        ])
        .assert()
        .success();

    // Exclude every findings item: the explicit --text search must still be
    // redacted in the merged findings+search path (C12-m1/m2).
    let mut f = FindingsFile::from_json(&std::fs::read_to_string(&findings).unwrap()).unwrap();
    for item in &mut f.items {
        item.included = false;
    }
    std::fs::write(&findings, f.to_json().unwrap()).unwrap();

    redact_bin()
        .args([
            "redact",
            in_pdf.to_str().unwrap(),
            "--findings",
            findings.to_str().unwrap(),
            "--text",
            "jane.doe@example.com",
            "-o",
            out.to_str().unwrap(),
        ])
        .assert()
        .success();

    let bytes = std::fs::read(&out).unwrap();
    assert!(
        !bytes
            .windows(b"jane.doe@example.com".len())
            .any(|w| w == b"jane.doe@example.com"),
        "search text must be redacted even when every findings item is excluded"
    );
}

// --- C12-2: input==output clobber guard (incl. canonically-equivalent paths) ---

#[test]
fn e2e_detect_refuses_inplace_output() {
    let dir = tempfile::tempdir().unwrap();
    let in_pdf = dir.path().join("in.pdf");
    std::fs::copy(fixture("pii_basic.pdf"), &in_pdf).unwrap();
    let original = std::fs::read(&in_pdf).unwrap();

    // `detect in.pdf -o in.pdf` must refuse (exit 2) and leave the source PDF
    // untouched — otherwise the findings JSON would clobber the document.
    redact_bin()
        .args([
            "detect",
            in_pdf.to_str().unwrap(),
            "-o",
            in_pdf.to_str().unwrap(),
        ])
        .assert()
        .code(2)
        .stderr(predicate::str::contains("output must differ from input"));
    assert_eq!(
        std::fs::read(&in_pdf).unwrap(),
        original,
        "source PDF must be untouched"
    );
}

#[test]
fn e2e_redact_refuses_canonically_equivalent_output() {
    let dir = tempfile::tempdir().unwrap();
    let in_pdf = dir.path().join("in.pdf");
    std::fs::copy(fixture("pii_basic.pdf"), &in_pdf).unwrap();

    // `dir/in.pdf` vs `dir/./in.pdf` differ lexically but are the same file;
    // the guard must catch them (bare PathBuf equality would not).
    let equiv = dir.path().join(".").join("in.pdf");
    // Compare STRING forms: `Path::eq` is component-wise and normalizes
    // `.` away, so the PathBufs themselves would compare equal.
    assert_ne!(
        in_pdf.to_str().unwrap(),
        equiv.to_str().unwrap(),
        "paths must differ lexically"
    );

    redact_bin()
        .args([
            "redact",
            in_pdf.to_str().unwrap(),
            "-o",
            equiv.to_str().unwrap(),
        ])
        .assert()
        .code(2)
        .stderr(predicate::str::contains("output must differ from input"));

    redact_bin()
        .args([
            "run",
            in_pdf.to_str().unwrap(),
            "-o",
            equiv.to_str().unwrap(),
            "--text",
            "jane.doe@example.com",
            "--yes",
            "--no-detect",
        ])
        .assert()
        .code(2)
        .stderr(predicate::str::contains("output must differ from input"));
}

#[cfg(unix)]
#[test]
fn e2e_redact_refuses_symlinked_output() {
    use std::os::unix::fs::symlink;

    let dir = tempfile::tempdir().unwrap();
    let in_pdf = dir.path().join("in.pdf");
    std::fs::copy(fixture("pii_basic.pdf"), &in_pdf).unwrap();
    let link = dir.path().join("link.pdf");
    symlink(&in_pdf, &link).unwrap();

    redact_bin()
        .args([
            "redact",
            in_pdf.to_str().unwrap(),
            "-o",
            link.to_str().unwrap(),
        ])
        .assert()
        .code(2)
        .stderr(predicate::str::contains("output must differ from input"));
}

// --- n4: `run --no-detect` with nothing given is a usage error (exit 2) ---

#[test]
fn e2e_run_no_detect_without_regions_is_usage() {
    let dir = tempfile::tempdir().unwrap();
    let out = dir.path().join("out.pdf");

    // --no-detect with no --text/--rect has nothing to redact: "nothing
    // given" is usage (2), not the operational "no included regions" (1).
    redact_bin()
        .args([
            "run",
            fixture("pii_basic.pdf").to_str().unwrap(),
            "-o",
            out.to_str().unwrap(),
            "--yes",
            "--no-detect",
        ])
        .assert()
        .code(2)
        .stderr(predicate::str::contains("--no-detect requires --text"));
    assert!(!out.exists(), "no output must be written on usage refusal");
}
