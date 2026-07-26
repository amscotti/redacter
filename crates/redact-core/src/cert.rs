//! Hash-based redaction certificate.

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::error::{RedactError, Result};
use crate::types::{Category, Region};
use crate::verify::VerificationResult;

pub const CERT_FORMAT: &str = "redact-certificate/v1";
const TOOL_NAME: &str = "redact";
const TOOL_VERSION: &str = env!("CARGO_PKG_VERSION");

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Certificate {
    pub format: String,
    #[serde(rename = "createdAt")]
    pub created_at: String,
    pub tool: ToolInfo,
    pub input: FileInfo,
    pub output: FileInfo,
    pub redactions: Vec<RedactionRecord>,
    pub verification: VerificationResult,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ToolInfo {
    pub name: String,
    pub version: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FileInfo {
    pub sha256: String,
    #[serde(rename = "pageCount")]
    pub page_count: usize,
}

/// One redacted item: *what* was covered (page, category, confidence, hash of
/// the covered text). Per the v1 spec the certificate carries hashes only —
/// geometry (rects) lives in the findings file, not in the certificate.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RedactionRecord {
    #[serde(rename = "pageIndex")]
    pub page_index: usize,
    pub category: String,
    pub confidence: f32,
    #[serde(rename = "textSha256")]
    pub text_sha256: String,
}

pub fn sha256_hex(data: &[u8]) -> String {
    let mut h = Sha256::new();
    h.update(data);
    hex_encode(&h.finalize())
}

fn hex_encode(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut s = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        s.push(HEX[(b >> 4) as usize] as char);
        s.push(HEX[(b & 0x0f) as usize] as char);
    }
    s
}

pub fn build_certificate(
    input: &[u8],
    output: &[u8],
    input_page_count: usize,
    output_page_count: usize,
    regions: &[Region],
    verification: VerificationResult,
) -> Result<Certificate> {
    if !verification.passed {
        return Err(RedactError::Certificate(
            "refusing to certify a failed verification".into(),
        ));
    }
    // The full-save invariant implies the page set is preserved; a mismatch
    // signals a structural change (a dropped or duplicated page) that would
    // invalidate every `redactions[].pageIndex` relative to the output.
    if input_page_count != output_page_count {
        return Err(RedactError::Certificate(format!(
            "page-count mismatch: input {input_page_count} != output {output_page_count}"
        )));
    }
    let redactions = regions
        .iter()
        // Mirror verify_output: regions with empty source_text are skipped
        // there (they have no secret to verify), so certifying a hash of the
        // empty string would attest a record that was never verified.
        .filter(|r| r.included && !r.source_text.is_empty())
        .map(|r| {
            // A page_index at/above the page count attests a redaction on a
            // page that doesn't exist — corrupt/tampered input must not be
            // certified (the full-save invariant makes input/output counts
            // equal, so the input count is the authoritative bound).
            if r.page_index >= input_page_count {
                return Err(RedactError::Certificate(format!(
                    "redaction page index {} is out of range (page count {input_page_count})",
                    r.page_index
                )));
            }
            let confidence = r.confidence;
            if !confidence.is_finite() {
                return Err(RedactError::Certificate(format!(
                    "non-finite redaction confidence {confidence} cannot be certified"
                )));
            }
            Ok(RedactionRecord {
                page_index: r.page_index,
                category: r.category.as_str().to_string(),
                // Non-finite f32 would serialize to JSON null; clamp finite
                // values to the meaningful [0.0, 1.0] range so the artifact
                // always round-trips through JSON.
                confidence: (confidence.clamp(0.0, 1.0) * 1000.0).round() / 1000.0,
                text_sha256: sha256_hex(r.source_text.as_bytes()),
            })
        })
        .collect::<Result<Vec<_>>>()?;

    // The certificate carries only the redaction hashes as secrets; the
    // verification block must not become a side-channel for plaintext. A
    // *passing* VerificationResult may still carry `detail` strings whose
    // content is outside this module's control — a future check that embeds a
    // plaintext secret in a passing detail would silently leak into the
    // certificate artifact. Strip the detail from every check on the copy we
    // embed, so only the structural pass/fail + id survive (C08-major-1).
    let verification = sanitize_verification(&verification);

    Ok(Certificate {
        format: CERT_FORMAT.into(),
        created_at: chrono_like_now()?,
        tool: ToolInfo {
            name: TOOL_NAME.into(),
            version: TOOL_VERSION.into(),
        },
        input: FileInfo {
            sha256: sha256_hex(input),
            page_count: input_page_count,
        },
        output: FileInfo {
            sha256: sha256_hex(output),
            page_count: output_page_count,
        },
        redactions,
        verification,
    })
}

/// Minimal ISO-8601 UTC timestamp without chrono dependency. Returns an error
/// if the system clock is unavailable (before `UNIX_EPOCH`) rather than
/// embedding a misleading epoch sentinel in the certificate.
fn chrono_like_now() -> Result<String> {
    use std::time::{SystemTime, UNIX_EPOCH};
    let secs = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|_| RedactError::Certificate("system clock is before UNIX_EPOCH".into()))?
        .as_secs();
    let days = secs / 86_400;
    let rem = secs % 86_400;
    let (hh, mm, ss) = (rem / 3600, (rem % 3600) / 60, rem % 60);
    let (y, m, d) = civil_from_days(days as i64);
    Ok(format!("{y:04}-{m:02}-{d:02}T{hh:02}:{mm:02}:{ss:02}Z"))
}

/// Days since 1970-01-01 → (year, month, day). Howard Hinnant's algorithm.
fn civil_from_days(z: i64) -> (i64, u32, u32) {
    let z = z + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z.rem_euclid(146_097);
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let y = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = (doy - (153 * mp + 2) / 5 + 1) as u32;
    let m = if mp < 10 { mp + 3 } else { mp - 9 } as u32;
    (if m <= 2 { y + 1 } else { y }, m, d)
}

/// Strip `detail` strings from a `VerificationResult` so the copy embedded in
/// a certificate cannot leak plaintext via check details (C08-major-1).
///
/// The structural pass/fail status and check ids are retained for audit; the
/// free-form `detail` text (which today is safe but is not guaranteed to
/// remain so) is blanked.
fn sanitize_verification(v: &VerificationResult) -> VerificationResult {
    VerificationResult {
        passed: v.passed,
        checks: v
            .checks
            .iter()
            .map(|c| crate::verify::CheckResult {
                id: c.id.clone(),
                passed: c.passed,
                detail: String::new(),
            })
            .collect(),
    }
}

pub fn certificate_to_json(cert: &Certificate) -> Result<String> {
    serde_json::to_string_pretty(cert).map_err(|e| RedactError::Certificate(e.to_string()))
}

pub fn certificate_from_json(s: &str) -> Result<Certificate> {
    let cert: Certificate =
        serde_json::from_str(s).map_err(|e| RedactError::Certificate(e.to_string()))?;
    if cert.format != CERT_FORMAT {
        return Err(RedactError::Certificate(format!(
            "unsupported certificate format {:?} (expected {CERT_FORMAT})",
            cert.format
        )));
    }
    // Reject certificates that claim a failed verification — the build path
    // refuses to certify failures, so a cert with verification.passed=false
    // (or an absent verification block) must be corrupt or tampered.
    if !cert.verification.passed {
        return Err(RedactError::Certificate(
            "certificate claims verification failed — refusing to accept".into(),
        ));
    }
    // The build path refuses to certify a page-count mismatch (it would
    // invalidate every `redactions[].pageIndex` relative to the output), so a
    // cert that disagrees with itself must be corrupt or tampered.
    if cert.input.page_count != cert.output.page_count {
        return Err(RedactError::Certificate(format!(
            "certificate page-count mismatch: input {} != output {}",
            cert.input.page_count, cert.output.page_count
        )));
    }
    // `passed` is derived from `checks.iter().all(|c| c.passed)` in verify, so
    // a cert claiming passed=true while an individual check reports failed is
    // self-contradictory — corrupt or hand-crafted.
    if cert.verification.checks.iter().any(|c| !c.passed) {
        return Err(RedactError::Certificate(
            "certificate verification.passed=true but a check reports failed — refusing to accept"
                .into(),
        ));
    }
    // Validate SHA-256 fields are exactly 64 lowercase hex chars so a
    // corrupted or subtly-mangled hash is rejected as corrupt rather than
    // silently reporting "no match".
    if !is_valid_sha256_hex(&cert.input.sha256) {
        return Err(RedactError::Certificate(
            "certificate input.sha256 is not a valid 64-char lowercase hex string".into(),
        ));
    }
    if !is_valid_sha256_hex(&cert.output.sha256) {
        return Err(RedactError::Certificate(
            "certificate output.sha256 is not a valid 64-char lowercase hex string".into(),
        ));
    }
    for r in &cert.redactions {
        if !is_valid_sha256_hex(&r.text_sha256) {
            return Err(RedactError::Certificate(format!(
                "certificate redaction {:?} has invalid textSha256",
                r.text_sha256
            )));
        }
        // The build path rejects page indices at/above the page count, so a
        // cert attesting a redaction on a page that doesn't exist must be
        // corrupt or tampered.
        if r.page_index >= cert.input.page_count {
            return Err(RedactError::Certificate(format!(
                "certificate redaction page index {} is out of range (page count {})",
                r.page_index, cert.input.page_count
            )));
        }
        // Mirror the build path's confidence invariant: the build clamps to
        // [0.0, 1.0] and rejects non-finite values, so a finite-but-out-of-
        // range (e.g. 1e30) or NaN/inf confidence cannot round-trip from a
        // genuine build and signals a corrupt or hand-crafted cert.
        if !r.confidence.is_finite() || !(0.0..=1.0).contains(&r.confidence) {
            return Err(RedactError::Certificate(format!(
                "certificate redaction has out-of-range confidence {}",
                r.confidence
            )));
        }
        // Reject unknown category values: the build path fills `category` from
        // `Category::as_str()`, so a value that doesn't round-trip through a
        // known `Category` means the cert is corrupt or hand-crafted.
        if !Category::all_str().contains(&r.category.as_str()) {
            return Err(RedactError::Certificate(format!(
                "certificate redaction has unknown category {:?}",
                r.category
            )));
        }
    }
    Ok(cert)
}

/// Validate that a string is exactly 64 lowercase hex characters (SHA-256).
fn is_valid_sha256_hex(s: &str) -> bool {
    s.len() == 64
        && s.bytes()
            .all(|b| b.is_ascii_hexdigit() && !b.is_ascii_uppercase())
}

/// Re-hash an output artifact and compare against the certificate's embedded
/// output hash — the check that lets a cert attest a *specific* file. A cert
/// swapped next to (or emitted alongside) different bytes will not match.
pub fn certificate_matches_output(cert: &Certificate, output: &[u8]) -> bool {
    sha256_hex(output) == cert.output.sha256
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sha256_known_vector() {
        // SHA-256 of "abc" (FIPS 180-4 test vector).
        assert_eq!(
            sha256_hex(b"abc"),
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
        );
        assert_eq!(
            sha256_hex(b""),
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        );
    }

    #[test]
    fn civil_from_days_known_dates() {
        assert_eq!(civil_from_days(0), (1970, 1, 1));
        // 2024-01-01 is 19,723 days after 1970-01-01.
        assert_eq!(civil_from_days(19_723), (2024, 1, 1));
        // Leap day 2024-02-29 = 19,723 + 59 days.
        assert_eq!(civil_from_days(19_723 + 59), (2024, 2, 29));
        // 1970-12-31 (364 days, no leap).
        assert_eq!(civil_from_days(364), (1970, 12, 31));
    }

    #[test]
    fn certificate_json_round_trip() {
        let cert = Certificate {
            format: CERT_FORMAT.into(),
            created_at: "2026-08-02T00:00:00Z".into(),
            tool: ToolInfo {
                name: "redact".into(),
                version: "0.1.0".into(),
            },
            input: FileInfo {
                sha256: sha256_hex(b"in"),
                page_count: 1,
            },
            output: FileInfo {
                sha256: sha256_hex(b"out"),
                page_count: 1,
            },
            redactions: vec![RedactionRecord {
                page_index: 0,
                category: "ssn".into(),
                confidence: 0.9,
                text_sha256: sha256_hex(b"123-45-6789"),
            }],
            verification: VerificationResult {
                passed: true,
                checks: vec![],
            },
        };
        let json = certificate_to_json(&cert).unwrap();
        let back = certificate_from_json(&json).unwrap();
        assert_eq!(back.format, CERT_FORMAT);
        assert_eq!(back.redactions[0].text_sha256, sha256_hex(b"123-45-6789"));
        assert!(back.verification.passed);
        assert!(!json.contains("123-45-6789"), "no plaintext in cert JSON");
    }

    fn region(secret: &str, confidence: f32) -> Region {
        Region {
            page_index: 0,
            rects: vec![],
            source_text: secret.into(),
            category: crate::types::Category::Ssn,
            confidence,
            included: true,
            source: crate::types::MatchSource::Regex,
        }
    }

    fn passed() -> VerificationResult {
        VerificationResult {
            passed: true,
            checks: vec![],
        }
    }

    #[test]
    fn build_certificate_hashes_match_bytes_and_secrets() {
        let input = b"raw input pdf bytes";
        let output = b"redacted output pdf bytes";
        let secret = "123-45-6789";
        let cert =
            build_certificate(input, output, 3, 3, &[region(secret, 0.5)], passed()).unwrap();
        assert_eq!(cert.input.sha256, sha256_hex(input));
        assert_eq!(cert.output.sha256, sha256_hex(output));
        assert_eq!(
            cert.redactions[0].text_sha256,
            sha256_hex(secret.as_bytes())
        );
    }

    #[test]
    fn certificate_matches_output_detects_swapped_bytes() {
        let cert = build_certificate(b"in", b"out", 1, 1, &[region("x", 1.0)], passed()).unwrap();
        assert!(certificate_matches_output(&cert, b"out"));
        assert!(!certificate_matches_output(&cert, b"tampered"));
    }

    #[test]
    fn build_certificate_fails_closed_on_failed_verification() {
        let v = VerificationResult {
            passed: false,
            checks: vec![],
        };
        assert!(build_certificate(b"in", b"out", 1, 1, &[region("x", 1.0)], v).is_err());
    }

    #[test]
    fn build_certificate_rejects_non_finite_confidence() {
        for bad in [f32::NAN, f32::INFINITY, f32::NEG_INFINITY] {
            let err = build_certificate(b"in", b"out", 1, 1, &[region("x", bad)], passed())
                .expect_err("non-finite confidence must not certify");
            assert!(matches!(err, RedactError::Certificate(_)), "{err:?}");
        }
        // Extreme finite values are clamped to [0.0, 1.0] instead of
        // overflowing to inf and serializing as JSON null.
        let cert = build_certificate(b"in", b"out", 1, 1, &[region("x", 1e30)], passed()).unwrap();
        assert_eq!(cert.redactions[0].confidence, 1.0);
    }

    #[test]
    fn certificate_from_json_rejects_uppercase_hex() {
        let cert = Certificate {
            format: CERT_FORMAT.into(),
            created_at: "2026-08-02T00:00:00Z".into(),
            tool: ToolInfo {
                name: "redact".into(),
                version: "0.1.0".into(),
            },
            input: FileInfo {
                sha256: "B".repeat(64),
                page_count: 1,
            },
            output: FileInfo {
                sha256: sha256_hex(b"out"),
                page_count: 1,
            },
            redactions: vec![],
            verification: passed(),
        };
        let json = certificate_to_json(&cert).unwrap();
        let err = certificate_from_json(&json).expect_err("uppercase hex must be rejected");
        assert!(matches!(err, RedactError::Certificate(_)), "{err:?}");
    }

    #[test]
    fn certificate_from_json_rejects_failed_verification() {
        let cert = Certificate {
            format: CERT_FORMAT.into(),
            created_at: "2026-08-02T00:00:00Z".into(),
            tool: ToolInfo {
                name: "redact".into(),
                version: "0.1.0".into(),
            },
            input: FileInfo {
                sha256: sha256_hex(b"in"),
                page_count: 1,
            },
            output: FileInfo {
                sha256: sha256_hex(b"out"),
                page_count: 1,
            },
            redactions: vec![],
            verification: VerificationResult {
                passed: false,
                checks: vec![],
            },
        };
        let json = certificate_to_json(&cert).unwrap();
        let err = certificate_from_json(&json).expect_err("failed verification must be rejected");
        assert!(matches!(err, RedactError::Certificate(_)), "{err:?}");
    }

    #[test]
    fn certificate_from_json_rejects_unknown_category() {
        let cert = Certificate {
            format: CERT_FORMAT.into(),
            created_at: "2026-08-02T00:00:00Z".into(),
            tool: ToolInfo {
                name: "redact".into(),
                version: "0.1.0".into(),
            },
            input: FileInfo {
                sha256: sha256_hex(b"in"),
                page_count: 1,
            },
            output: FileInfo {
                sha256: sha256_hex(b"out"),
                page_count: 1,
            },
            redactions: vec![RedactionRecord {
                page_index: 0,
                category: "unknown-category".into(),
                confidence: 0.9,
                text_sha256: sha256_hex(b"secret"),
            }],
            verification: passed(),
        };
        let json = certificate_to_json(&cert).unwrap();
        let err = certificate_from_json(&json).expect_err("unknown category must be rejected");
        assert!(matches!(err, RedactError::Certificate(_)), "{err:?}");
    }

    #[test]
    fn build_certificate_rejects_page_count_mismatch() {
        let err = build_certificate(b"in", b"out", 3, 4, &[region("x", 1.0)], passed())
            .expect_err("page-count mismatch must be rejected");
        assert!(matches!(err, RedactError::Certificate(_)), "{err:?}");
    }

    #[test]
    fn build_certificate_strips_verification_detail() {
        // C08-major-1: a passing VerificationResult with a detail string must
        // have its detail blanked in the certificate so no plaintext can leak
        // through the verification block.
        let v = VerificationResult {
            passed: true,
            checks: vec![crate::verify::CheckResult {
                id: "text-removal".into(),
                passed: true,
                detail: "verified removal of 123-45-6789".into(),
            }],
        };
        let cert = build_certificate(b"in", b"out", 1, 1, &[region("x", 1.0)], v).unwrap();
        assert!(
            cert.verification.checks.iter().all(|c| c.detail.is_empty()),
            "details must be blanked in the certificate"
        );
        let json = certificate_to_json(&cert).unwrap();
        assert!(
            !json.contains("123-45-6789"),
            "no plaintext in cert JSON via verification detail"
        );
    }

    #[test]
    fn certificate_from_json_rejects_unknown_format() {
        let mut cert = Certificate {
            format: CERT_FORMAT.into(),
            created_at: "2026-08-02T00:00:00Z".into(),
            tool: ToolInfo {
                name: "redact".into(),
                version: "0.1.0".into(),
            },
            input: FileInfo {
                sha256: sha256_hex(b"in"),
                page_count: 1,
            },
            output: FileInfo {
                sha256: sha256_hex(b"out"),
                page_count: 1,
            },
            redactions: vec![],
            verification: passed(),
        };
        let json = certificate_to_json(&cert).unwrap();
        assert!(certificate_from_json(&json).is_ok());
        cert.format = "redact-certificate/v2".into();
        let json = certificate_to_json(&cert).unwrap();
        let err = certificate_from_json(&json).expect_err("v2 must be rejected");
        assert!(matches!(err, RedactError::Certificate(_)), "{err:?}");
    }

    #[test]
    fn build_certificate_rejects_out_of_range_page_index() {
        // Region on page 2 of a 2-page input — page 2 doesn't exist
        // (0-based), so certifying it would attest an unverifiable redaction.
        let mut r = region("x", 1.0);
        r.page_index = 2;
        let err = build_certificate(b"in", b"out", 2, 2, &[r], passed())
            .expect_err("out-of-range page index must not certify");
        assert!(matches!(err, RedactError::Certificate(_)), "{err:?}");
        // The last valid page (index 1) is fine.
        let mut ok = region("x", 1.0);
        ok.page_index = 1;
        assert!(build_certificate(b"in", b"out", 2, 2, &[ok], passed()).is_ok());
    }

    #[test]
    fn build_certificate_skips_empty_source_text_regions() {
        // verify_output filters out empty-text regions (no secret to check);
        // the certificate must not attest them either — a hash of the empty
        // string would be a certified record that was never verified.
        let mut empty = region("x", 1.0);
        empty.source_text = String::new();
        let cert = build_certificate(
            b"in",
            b"out",
            1,
            1,
            &[empty, region("real-secret", 0.9)],
            passed(),
        )
        .unwrap();
        assert_eq!(
            cert.redactions.len(),
            1,
            "empty-text region must be filtered"
        );
        assert_eq!(cert.redactions[0].text_sha256, sha256_hex(b"real-secret"));
    }

    #[test]
    fn certificate_from_json_rejects_page_count_mismatch() {
        let cert = Certificate {
            format: CERT_FORMAT.into(),
            created_at: "2026-08-02T00:00:00Z".into(),
            tool: ToolInfo {
                name: "redact".into(),
                version: "0.1.0".into(),
            },
            input: FileInfo {
                sha256: sha256_hex(b"in"),
                page_count: 1,
            },
            output: FileInfo {
                sha256: sha256_hex(b"out"),
                page_count: 2,
            },
            redactions: vec![],
            verification: passed(),
        };
        let json = certificate_to_json(&cert).unwrap();
        let err = certificate_from_json(&json).expect_err("page-count mismatch must be rejected");
        assert!(matches!(err, RedactError::Certificate(_)), "{err:?}");
    }

    #[test]
    fn certificate_from_json_rejects_out_of_range_page_index() {
        let cert = Certificate {
            format: CERT_FORMAT.into(),
            created_at: "2026-08-02T00:00:00Z".into(),
            tool: ToolInfo {
                name: "redact".into(),
                version: "0.1.0".into(),
            },
            input: FileInfo {
                sha256: sha256_hex(b"in"),
                page_count: 1,
            },
            output: FileInfo {
                sha256: sha256_hex(b"out"),
                page_count: 1,
            },
            redactions: vec![RedactionRecord {
                page_index: 1,
                category: "ssn".into(),
                confidence: 0.9,
                text_sha256: sha256_hex(b"secret"),
            }],
            verification: passed(),
        };
        let json = certificate_to_json(&cert).unwrap();
        let err =
            certificate_from_json(&json).expect_err("out-of-range page index must be rejected");
        assert!(matches!(err, RedactError::Certificate(_)), "{err:?}");
    }

    #[test]
    fn certificate_from_json_rejects_out_of_range_confidence() {
        // Build clamps finite confidence to [0.0, 1.0] and rejects non-finite;
        // a cert carrying 1e30 / NaN / 1.5 cannot come from a genuine build.
        for conf in [1e30f32, 1.5f32, -0.1f32, f32::NAN, f32::INFINITY] {
            let cert = Certificate {
                format: CERT_FORMAT.into(),
                created_at: "2026-08-02T00:00:00Z".into(),
                tool: ToolInfo {
                    name: "redact".into(),
                    version: "0.1.0".into(),
                },
                input: FileInfo {
                    sha256: sha256_hex(b"in"),
                    page_count: 1,
                },
                output: FileInfo {
                    sha256: sha256_hex(b"out"),
                    page_count: 1,
                },
                redactions: vec![RedactionRecord {
                    page_index: 0,
                    category: "ssn".into(),
                    confidence: conf,
                    text_sha256: sha256_hex(b"secret"),
                }],
                verification: passed(),
            };
            let json = certificate_to_json(&cert).unwrap();
            let err =
                certificate_from_json(&json).expect_err("out-of-range confidence must be rejected");
            assert!(matches!(err, RedactError::Certificate(_)), "{err:?}");
        }
        // In-range confidence still accepted.
        let ok = Certificate {
            format: CERT_FORMAT.into(),
            created_at: "2026-08-02T00:00:00Z".into(),
            tool: ToolInfo {
                name: "redact".into(),
                version: "0.1.0".into(),
            },
            input: FileInfo {
                sha256: sha256_hex(b"in"),
                page_count: 1,
            },
            output: FileInfo {
                sha256: sha256_hex(b"out"),
                page_count: 1,
            },
            redactions: vec![RedactionRecord {
                page_index: 0,
                category: "ssn".into(),
                confidence: 0.0,
                text_sha256: sha256_hex(b"secret"),
            }],
            verification: passed(),
        };
        assert!(certificate_from_json(&certificate_to_json(&ok).unwrap()).is_ok());
    }

    #[test]
    fn certificate_from_json_rejects_failed_check_in_passing_verification() {
        // verify derives passed = all checks passed, so passed=true with a
        // failed check is self-contradictory — corrupt or hand-crafted.
        let cert = Certificate {
            format: CERT_FORMAT.into(),
            created_at: "2026-08-02T00:00:00Z".into(),
            tool: ToolInfo {
                name: "redact".into(),
                version: "0.1.0".into(),
            },
            input: FileInfo {
                sha256: sha256_hex(b"in"),
                page_count: 1,
            },
            output: FileInfo {
                sha256: sha256_hex(b"out"),
                page_count: 1,
            },
            redactions: vec![],
            verification: VerificationResult {
                passed: true,
                checks: vec![crate::verify::CheckResult {
                    id: "text-removal".into(),
                    passed: false,
                    detail: String::new(),
                }],
            },
        };
        let json = certificate_to_json(&cert).unwrap();
        let err = certificate_from_json(&json)
            .expect_err("failed check under passed=true must be rejected");
        assert!(matches!(err, RedactError::Certificate(_)), "{err:?}");
    }
}
