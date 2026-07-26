//! Executable architecture rules for `redact` (the ArchUnit-style gate).
//!
//! Rust has no ArchUnit equivalent that enforces module layering at runtime;
//! the compiler enforces *crate* boundaries via `Cargo.toml`, and these
//! integration tests enforce the *intra-crate* layering documented in
//! `ARCHITECTURE.md` by scanning source text. They run under `cargo test`
//! and in CI, so a layering violation fails the build, not just a review.
//!
//! Heuristic limits (kept tiny on purpose): the scan matches `crate::` /
//! `super::` paths and `use` statements, so a violation hidden behind a
//! `pub use` re-export alias would slip through. Keep the rule set small and
//! the module paths canonical (import via `crate::types`, not aliases) so the
//! heuristic stays sound. `//` line comments are ignored; block comments are
//! not (no block comments contain these paths today).

use std::path::{Path, PathBuf};

fn crate_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
}

fn read_src(rel: &str) -> String {
    let path = crate_root().join(rel);
    std::fs::read_to_string(&path).unwrap_or_else(|e| panic!("read {}: {e}", path.display()))
}

/// Source lines minus `//`-style comments, so doc prose mentioning a module
/// (e.g. "no clap") can't trip a rule — only real code paths are matched.
fn code_lines(src: &str) -> Vec<&str> {
    src.lines()
        .filter(|l| {
            let t = l.trim_start();
            !(t.starts_with("//") || t.starts_with('*'))
        })
        .collect()
}

fn rs_files(dir: &Path) -> Vec<PathBuf> {
    let mut out = Vec::new();
    let mut stack = vec![dir.to_path_buf()];
    while let Some(d) = stack.pop() {
        let entries =
            std::fs::read_dir(&d).unwrap_or_else(|e| panic!("read_dir {}: {e}", d.display()));
        for entry in entries {
            let entry = entry.expect("dir entry");
            let p = entry.path();
            if p.is_dir() {
                stack.push(p);
            } else if p.extension().is_some_and(|e| e == "rs") {
                out.push(p);
            }
        }
    }
    out.sort();
    out
}

/// (file, line) hits for `needle` in real code lines of `files`.
fn hits(files: &[PathBuf], needle: &str) -> Vec<String> {
    let mut found = Vec::new();
    for f in files {
        let src = std::fs::read_to_string(f).expect("read rs file");
        for (i, line) in code_lines(&src).iter().enumerate() {
            if line.contains(needle) {
                found.push(format!("{}:{}: {needle}", f.display(), i + 1));
            }
        }
    }
    found
}

fn core_src_files() -> Vec<PathBuf> {
    rs_files(&crate_root().join("src"))
}

fn files_under(rel: &str) -> Vec<PathBuf> {
    let dir = crate_root().join(rel);
    rs_files(&dir)
        .into_iter()
        .filter(|p| p.starts_with(&dir))
        .collect()
}

#[test]
fn core_has_no_ux_dependencies() {
    // `redact-core` must stay a pure library: no clap/anyhow dependency, so
    // the "logic never lives in the CLI" rule holds in both directions.
    // (dev-dependencies are exempt — test helpers may use anything.)
    let manifest = read_src("Cargo.toml");
    let deps_section = manifest
        .split("[dev-dependencies]")
        .next()
        .expect("core Cargo.toml must parse");
    for banned in ["clap", "anyhow"] {
        assert!(
            !deps_section.contains(banned),
            "redact-core must not depend on {banned} (see ARCHITECTURE.md crate map)"
        );
    }

    let files = core_src_files();
    for banned in ["use clap", "clap::", "use anyhow", "anyhow::"] {
        let found = hits(&files, banned);
        assert!(
            found.is_empty(),
            "redact-core/src must not reference {banned}:\n{}",
            found.join("\n")
        );
    }
}

#[test]
fn detectors_stay_leaf() {
    // `detect/` maps strings to matches; it must not reach up into apply /
    // verify / cert / engine / pipeline — new detectors plug in behind the
    // `Detector` trait without touching the pipeline stages.
    let files = files_under("src/detect");
    assert!(!files.is_empty(), "expected sources under src/detect");
    for banned in [
        "crate::apply",
        "crate::verify",
        "crate::cert",
        "crate::engine",
        "crate::pipeline",
    ] {
        let found = hits(&files, banned);
        assert!(
            found.is_empty(),
            "src/detect must not reference {banned}:\n{}",
            found.join("\n")
        );
    }
}

#[test]
fn engine_stays_low_level() {
    // `engine/` opens / extracts / renders PDFs; it must not know about
    // detectors, geometry, or pipeline stages above it.
    let files = files_under("src/engine");
    assert!(!files.is_empty(), "expected sources under src/engine");
    for banned in [
        "crate::detect",
        "crate::geometry",
        "crate::apply",
        "crate::verify",
        "crate::cert",
        "crate::pipeline",
        "crate::findings",
    ] {
        let found = hits(&files, banned);
        assert!(
            found.is_empty(),
            "src/engine must not reference {banned}:\n{}",
            found.join("\n")
        );
    }
}

#[test]
fn geometry_stays_pure_mapping() {
    // `geometry.rs` maps text offsets to rects; painting, verification, and
    // orchestration live downstream and must not be referenced here.
    let root = crate_root();
    let files = vec![root.join("src/geometry.rs")];
    for banned in [
        "crate::apply",
        "crate::verify",
        "crate::engine",
        "crate::cert",
        "crate::pipeline",
    ] {
        let found = hits(&files, banned);
        assert!(
            found.is_empty(),
            "src/geometry.rs must not reference {banned}:\n{}",
            found.join("\n")
        );
    }
}

#[test]
fn cli_uses_core_not_backends() {
    // The CLI is UX only: it may orchestrate via `redact_core`, but must not
    // reach past it into the PDF backends (hayro/krilla) or the OCR runtime
    // (ocrs/rten) directly — those stay behind core's traits and features.
    let workspace_root = crate_root()
        .parent()
        .and_then(|p| p.parent())
        .expect("crates/redact-core/<..><..>")
        .to_path_buf();
    let cli_src = workspace_root.join("crates/redact-cli/src");
    let files = rs_files(&cli_src);
    assert!(
        !files.is_empty(),
        "expected sources under crates/redact-cli/src"
    );
    for banned in ["hayro::", "krilla::", "ocrs::", "rten::"] {
        let found = hits(&files, banned);
        assert!(
            found.is_empty(),
            "redact-cli must use redact_core instead of {banned} directly:\n{}",
            found.join("\n")
        );
    }
    let cli_manifest = std::fs::read_to_string(workspace_root.join("crates/redact-cli/Cargo.toml"))
        .expect("read redact-cli Cargo.toml");
    assert!(
        cli_manifest.contains("redact-core"),
        "redact-cli must depend on redact-core"
    );
}

#[test]
fn spike_is_never_a_dependency() {
    // `redact-ocr-spike` is a throwaway experiment (publish = false); no
    // shipped crate may depend on it or import it.
    let workspace_root = crate_root()
        .parent()
        .and_then(|p| p.parent())
        .expect("crates/redact-core/<..><..>")
        .to_path_buf();
    for member in ["redact-core", "redact-cli", "redact-fixturegen"] {
        let manifest =
            std::fs::read_to_string(workspace_root.join(format!("crates/{member}/Cargo.toml")))
                .unwrap_or_else(|e| panic!("read {member} Cargo.toml: {e}"));
        assert!(
            !manifest.contains("redact-ocr-spike") && !manifest.contains("redact_ocr_spike"),
            "{member} must not depend on redact-ocr-spike"
        );
    }
    let mut checked = 0;
    for member in ["redact-core", "redact-cli", "redact-fixturegen"] {
        let files = rs_files(&workspace_root.join(format!("crates/{member}/src")));
        checked += files.len();
        for banned in ["ocr_spike", "ocr-spike"] {
            let found = hits(&files, banned);
            assert!(
                found.is_empty(),
                "{member} must not reference {banned}:\n{}",
                found.join("\n")
            );
        }
    }
    assert!(checked > 0, "expected to scan shipped crate sources");
}
