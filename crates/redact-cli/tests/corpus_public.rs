//! Optional corpus e2e against John Snow Labs synthetic PDF de-id dataset.
//!
//! Dataset: https://github.com/JohnSnowLabs/pdf-deid-dataset
//! (synthetic medical PDFs; no real patient data)
//!
//! Not run by default (`#[ignore]`). Enable with:
//!   mise run corpus:fetch
//!   mise run test:corpus
//!
//! Or:
//!   E2E_CORPUS=1 cargo test -p redact-cli --test corpus_public -- --ignored --nocapture
//!
//! Score floor (Easy subset vs GT string lists):
//!   micro-recall ≥ 0.90, micro-precision ≥ 0.95 (see `corpus_deid_gt_score`).

use std::collections::{HashMap, HashSet};
use std::path::{Path, PathBuf};
use std::time::Duration;

use assert_cmd::Command;
use tempfile::tempdir;

fn corpus_subset_dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../testdata/corpus/jsl-pdf-deid/subset")
}

fn list_pdfs(dir: &Path) -> Vec<PathBuf> {
    let mut out = Vec::new();
    let Ok(rd) = std::fs::read_dir(dir) else {
        return out;
    };
    for entry in rd.flatten() {
        let p = entry.path();
        if p.extension()
            .and_then(|e| e.to_str())
            .is_some_and(|e| e.eq_ignore_ascii_case("pdf"))
        {
            out.push(p);
        }
    }
    out.sort();
    out
}

fn redact_bin() -> Command {
    Command::cargo_bin("redact").unwrap()
}

/// Skip quietly when the subset is missing.
fn require_subset() -> Option<Vec<PathBuf>> {
    let dir = corpus_subset_dir();
    if !dir.is_dir() {
        eprintln!(
            "skip: corpus subset not found at {} — run ./scripts/fetch_public_corpus.sh",
            dir.display()
        );
        return None;
    }
    let pdfs = list_pdfs(&dir);
    if pdfs.is_empty() {
        eprintln!(
            "skip: no PDFs in {} — run ./scripts/fetch_public_corpus.sh",
            dir.display()
        );
        return None;
    }
    Some(pdfs)
}

#[test]
#[ignore = "optional JSL pdf-deid corpus; run with mise run test:corpus"]
fn corpus_deid_detect_smoke() {
    let Some(pdfs) = require_subset() else {
        return;
    };

    let tmp = tempdir().unwrap();
    let mut ok = 0usize;
    let mut soft_fail = 0usize;
    let mut with_findings = 0usize;

    for pdf in &pdfs {
        let findings = tmp.path().join(format!(
            "{}.findings.json",
            pdf.file_stem().unwrap().to_string_lossy()
        ));
        let assert = redact_bin()
            .args([
                "detect",
                pdf.to_str().unwrap(),
                "-o",
                findings.to_str().unwrap(),
            ])
            .timeout(Duration::from_secs(120))
            .assert();

        if assert.try_success().is_ok() {
            ok += 1;
            assert!(
                findings.is_file(),
                "detect should write findings for {}",
                pdf.display()
            );
            if let Ok(raw) = std::fs::read_to_string(&findings)
                && let Ok(v) = serde_json::from_str::<serde_json::Value>(&raw)
            {
                let n = v
                    .get("items")
                    .and_then(|i| i.as_array())
                    .map(|a| a.len())
                    .unwrap_or(0);
                if n > 0 {
                    with_findings += 1;
                    eprintln!(
                        "  {} -> {n} findings",
                        pdf.file_name().unwrap().to_string_lossy()
                    );
                }
            }
        } else {
            soft_fail += 1;
            eprintln!(
                "warn: detect failed (soft) for {} — continuing",
                pdf.display()
            );
        }
    }

    assert!(
        ok > 0,
        "expected at least one PDF to detect successfully; soft_fail={soft_fail}"
    );
    eprintln!(
        "corpus detect: ok={ok} with_findings={with_findings} soft_fail={soft_fail} total={}",
        pdfs.len()
    );
}

#[test]
#[ignore = "optional JSL pdf-deid corpus; run with mise run test:corpus"]
fn corpus_deid_redact_and_verify_smoke() {
    let Some(pdfs) = require_subset() else {
        return;
    };

    let limit = std::env::var("CORPUS_REDACT_LIMIT")
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or(5usize);

    let tmp = tempdir().unwrap();
    let mut ran = 0usize;
    let mut redacted_nonzero = 0usize;

    for pdf in pdfs.iter().take(limit) {
        let out = tmp.path().join(format!(
            "{}.redacted.pdf",
            pdf.file_stem().unwrap().to_string_lossy()
        ));
        let cert = tmp.path().join(format!(
            "{}.cert.json",
            pdf.file_stem().unwrap().to_string_lossy()
        ));

        let result = redact_bin()
            .args([
                "run",
                pdf.to_str().unwrap(),
                "-o",
                out.to_str().unwrap(),
                "--cert",
                cert.to_str().unwrap(),
                "--yes",
            ])
            .timeout(Duration::from_secs(180))
            .output()
            .expect("spawn redact");

        if !result.status.success() {
            eprintln!(
                "warn: redact failed for {} status={} stderr={}",
                pdf.display(),
                result.status,
                String::from_utf8_lossy(&result.stderr)
            );
            continue;
        }

        assert!(out.is_file(), "missing output for {}", pdf.display());
        assert!(cert.is_file(), "missing cert for {}", pdf.display());

        let bytes = std::fs::read(&out).unwrap();
        assert!(
            !bytes.windows(5).any(|w| w == b"/Prev"),
            "output must not be incremental for {}",
            pdf.display()
        );

        let cert_json = std::fs::read_to_string(&cert).unwrap();
        let c = redact_core::certificate_from_json(&cert_json).expect("cert json");
        assert_eq!(c.format, "redact-certificate/v1");
        assert!(
            c.verification.passed,
            "verification failed for {}: {:?}",
            pdf.display(),
            c.verification.checks
        );
        if !c.redactions.is_empty() {
            redacted_nonzero += 1;
        }
        eprintln!(
            "  {} -> {} redaction(s), verified",
            pdf.file_name().unwrap().to_string_lossy(),
            c.redactions.len()
        );
        ran += 1;
    }

    assert!(
        ran > 0,
        "expected at least one successful redact+verify on corpus subset"
    );
    eprintln!("corpus redact+verify: ran={ran} with_redactions={redacted_nonzero} (limit={limit})");
}

fn corpus_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../testdata/corpus/jsl-pdf-deid")
}

fn gt_path() -> PathBuf {
    corpus_root().join("ground_truth/pdf_deid_gts_easy.json")
}

fn normalize(s: &str) -> String {
    s.split_whitespace()
        .collect::<Vec<_>>()
        .join(" ")
        .to_ascii_lowercase()
}

fn normalize_loose(s: &str) -> String {
    s.chars()
        .filter(|c| c.is_ascii_alphanumeric())
        .collect::<String>()
        .to_ascii_lowercase()
}

fn strings_match(found: &str, gt: &str) -> bool {
    let fnorm = normalize(found);
    let gnorm = normalize(gt);
    if fnorm.is_empty() || gnorm.is_empty() {
        return false;
    }
    if gnorm == fnorm || fnorm.contains(&gnorm) || gnorm.contains(&fnorm) {
        return true;
    }
    let fl = normalize_loose(found);
    let gl = normalize_loose(gt);
    if !fl.is_empty() && !gl.is_empty() && (fl == gl || fl.contains(&gl) || gl.contains(&fl)) {
        return true;
    }
    // "Age: 46" ↔ "aged 46" ↔ "46-year-old" ↔ "46"
    // Mirrors scripts/eval_jsl_corpus.py so both harnesses score identically.
    if let (Some(af), Some(ag)) = (age_years(found), age_years(gt))
        && af == ag
    {
        return true;
    }
    false
}

/// Extract a years integer from common age phrasings, or None. Faithful port
/// of `age_years` in scripts/eval_jsl_corpus.py (patterns: "age: N",
/// "aged N", "N-year-old", bare "N").
fn age_years(s: &str) -> Option<String> {
    let n = normalize(s);
    let patterns = [
        r"^age\s*:\s*(\d{1,3})$",
        r"^aged\s+(\d{1,3})$",
        r"^(\d{1,3})-year-old$",
        r"^(\d{1,3})$",
    ];
    for pat in patterns {
        let re = regex::Regex::new(pat).unwrap();
        if let Some(caps) = re.captures(&n)
            && let Some(m) = caps.get(1)
        {
            return Some(m.as_str().to_string());
        }
    }
    None
}

fn gt_key_for_pdf(pdf: &Path) -> String {
    let name = pdf.file_name().and_then(|s| s.to_str()).unwrap_or("");
    // subset names: "00_PDF_Deid_Deidentification_0.pdf" → "PDF_Deid_Deidentification_0.pdf"
    if let Some((_, rest)) = name.split_once('_')
        && rest.starts_with("PDF_Deid_")
    {
        return rest.to_string();
    }
    name.to_string()
}

/// Score detector findings against JSL Easy ground-truth PHI string lists.
///
/// Locks the Easy-subset floor so regex catalog changes cannot silently regress
/// below ~90% recall / ~95% precision (aggressive-mode baseline ≈ 99% / 98%).
///
/// Scored with `--aggressive` on purpose: the Easy GT lists bare dates and
/// bare phone numbers as PHI, while default mode keyword-gates those shapes
/// to protect precision on non-medical documents (invoice numbers, versions).
/// `--aggressive` is the documented recall mode for this corpus (see the
/// README eval snapshot); default-mode recall on this GT is ~57%.
#[test]
#[ignore = "optional JSL pdf-deid corpus; run with mise run test:corpus"]
fn corpus_deid_gt_score() {
    let Some(pdfs) = require_subset() else {
        return;
    };
    let gt_file = gt_path();
    if !gt_file.is_file() {
        eprintln!(
            "skip: ground truth not found at {} — run ./scripts/fetch_public_corpus.sh",
            gt_file.display()
        );
        return;
    }

    let gt_raw = std::fs::read_to_string(&gt_file).expect("read gt");
    let gt_map: HashMap<String, Vec<String>> =
        serde_json::from_str(&gt_raw).expect("parse gt json");

    let tmp = tempdir().unwrap();
    let mut total_gt = 0usize;
    let mut total_tp = 0usize;
    let mut total_findings = 0usize;
    let mut total_fp = 0usize;
    let mut docs = 0usize;

    for pdf in &pdfs {
        let key = gt_key_for_pdf(pdf);
        let Some(gt_list) = gt_map.get(&key) else {
            eprintln!("warn: no GT for {key}");
            continue;
        };
        let mut seen = HashSet::new();
        let gt_unique: Vec<&str> = gt_list
            .iter()
            .map(|s| s.as_str())
            .filter(|s| seen.insert(*s))
            .collect();

        let findings_path = tmp.path().join(format!(
            "{}.findings.json",
            pdf.file_stem().unwrap().to_string_lossy()
        ));
        let assert = redact_bin()
            .args([
                "detect",
                pdf.to_str().unwrap(),
                "-o",
                findings_path.to_str().unwrap(),
                // Recall mode: see the doc comment above (bare dates/phones).
                "--aggressive",
            ])
            .timeout(Duration::from_secs(120))
            .assert();
        assert
            .try_success()
            .unwrap_or_else(|_| panic!("detect failed for {}", pdf.display()));

        let raw = std::fs::read_to_string(&findings_path).expect("findings");
        let v: serde_json::Value = serde_json::from_str(&raw).expect("findings json");
        let found: Vec<String> = v
            .get("items")
            .and_then(|i| i.as_array())
            .map(|arr| {
                arr.iter()
                    .filter_map(|it| it.get("text").and_then(|t| t.as_str()).map(str::to_string))
                    .collect()
            })
            .unwrap_or_default();

        let tp: usize = gt_unique
            .iter()
            .filter(|g| found.iter().any(|f| strings_match(f, g)))
            .count();
        let fp: usize = found
            .iter()
            .filter(|f| !gt_unique.iter().any(|g| strings_match(f, g)))
            .count();

        let recall = if gt_unique.is_empty() {
            1.0
        } else {
            tp as f64 / gt_unique.len() as f64
        };
        eprintln!(
            "  {key}: recall={:.1}% found={} gt={} tp={tp} fp={fp}",
            recall * 100.0,
            found.len(),
            gt_unique.len()
        );

        total_gt += gt_unique.len();
        total_tp += tp;
        total_findings += found.len();
        total_fp += fp;
        docs += 1;
    }

    assert!(docs > 0, "no docs scored");
    // Guard total_gt == 0 (all GT lists empty) like eval_jsl_corpus.py so the
    // floor assert reports a sane value instead of NaN.
    let micro_recall = if total_gt == 0 {
        1.0
    } else {
        total_tp as f64 / total_gt as f64
    };
    let micro_precision = if total_findings == 0 {
        1.0
    } else {
        (total_findings - total_fp) as f64 / total_findings as f64
    };

    eprintln!(
        "corpus GT score: docs={docs} micro_recall={micro_recall:.4} micro_precision={micro_precision:.4} \
         tp={total_tp}/{total_gt} findings={total_findings} fp={total_fp}"
    );

    // Floors leave headroom under the current ~96%/100% Easy baseline.
    const MIN_RECALL: f64 = 0.90;
    const MIN_PRECISION: f64 = 0.95;
    assert!(
        micro_recall + f64::EPSILON >= MIN_RECALL,
        "micro-recall {micro_recall:.4} below floor {MIN_RECALL} (tp={total_tp}/{total_gt})"
    );
    assert!(
        micro_precision + f64::EPSILON >= MIN_PRECISION,
        "micro-precision {micro_precision:.4} below floor {MIN_PRECISION} (fp={total_fp}/{total_findings})"
    );
}
