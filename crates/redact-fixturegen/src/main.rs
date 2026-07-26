//! Generate synthetic PDFs with known PII for offline e2e tests.
//!
//! Krilla page surfaces use a **top-left origin with y growing downward**
//! (via an internal flip of PDF's y-up space). Layout helpers live in the
//! library target so tests can exercise generation and the ground truth.

use std::path::{Path, PathBuf};

use anyhow::{Context, Result};
use clap::Parser;
use redact_fixturegen::{
    Font, byte_drift_problems, generate_all, generate_ocr_scanned, load_font,
    meta_contract_problems,
};

#[derive(Parser, Debug)]
#[command(name = "redact-fixturegen", about = "Generate synthetic PII PDFs")]
struct Args {
    /// Output directory.
    #[arg(short, long, default_value = "testdata/fixtures/synthetic")]
    out_dir: PathBuf,

    /// TTF to use for every fixture (defaults to a built-in candidate list;
    /// the REDACT_FONT env var is honored when the flag is absent).
    #[arg(long)]
    font: Option<PathBuf>,

    /// Also generate the image-only ("scanned") fixture for OCR testing.
    #[arg(long)]
    scanned: bool,

    /// Regenerate into a temp dir and verify the committed files match
    /// byte-for-byte and every meta contract holds; writes nothing. This also
    /// byte-checks the optional scanned (`ocr_scanned`) fixture, so the
    /// committed file must exist even though `--scanned` is needed to create
    /// it (C14-n1).
    #[arg(long)]
    check: bool,
}

fn main() -> Result<()> {
    let Args {
        out_dir,
        font,
        scanned,
        check,
    } = Args::parse();

    let explicit_font = font.or_else(|| std::env::var_os("REDACT_FONT").map(PathBuf::from));
    let font = load_font(explicit_font.as_deref())?;

    if check {
        return run_check(&out_dir, &font);
    }

    std::fs::create_dir_all(&out_dir)?;
    // Same face for title and body (emphasis is size-only); load it once (C14-n2).
    let title_font = font.clone();
    generate_all(&out_dir, &font, &title_font)?;
    if scanned {
        generate_ocr_scanned(&out_dir, &font)?;
    }
    eprintln!("fixtures written to {}", out_dir.display());
    Ok(())
}

fn run_check(out_dir: &Path, font: &Font) -> Result<()> {
    let tmp = tempfile::tempdir().context("create temp dir for regeneration")?;
    let title_font = font.clone();
    let generated = generate_all(tmp.path(), font, &title_font)?;
    let mut problems = meta_contract_problems(&generated);

    // Byte-check the optional scanned (OCR) fixture too: it has no text layer
    // so meta-contract detection would be vacuous, but byte-drift is still a
    // valid check (C14-f2). Generate it up front and fold it into the single
    // drift scan so the orphan check's "produced" set covers the committed
    // ocr_scanned files (otherwise the default-fixture scan would report a
    // committed ocr_scanned.pdf as an orphan, and this scan would report
    // every default fixture as one, C14-n1).
    let scanned = generate_ocr_scanned(tmp.path(), font)?;
    let mut all = generated;
    all.push(scanned);
    problems.extend(byte_drift_problems(&all, out_dir));

    if problems.is_empty() {
        println!(
            "ok: {} fixtures in {} are byte-identical and their meta contracts hold",
            all.len(),
            out_dir.display()
        );
        return Ok(());
    }
    for problem in &problems {
        eprintln!("  - {problem}");
    }
    anyhow::bail!(
        "{} problem(s): committed fixtures drifted from generator output or a meta contract failed; re-run the generator to refresh",
        problems.len()
    )
}
