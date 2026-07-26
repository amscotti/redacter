//! `redact` — offline PDF redaction CLI.

use std::path::{Path, PathBuf};

use anyhow::{Context, Result, bail};
use clap::{Parser, Subcommand, ValueEnum};
use redact_core::{
    ApplyOptions, Category, DetectOptions, FindingsFile, Rect, RunOptions, certificate_from_json,
    certificate_matches_output, certificate_to_json, detect_document, redact_with_regions,
    redact_with_regions_and_options, run_pipeline, sha256_hex, verify_output,
};
use tracing_subscriber::EnvFilter;

#[derive(Parser, Debug)]
#[command(
    name = "redact",
    version,
    about = "Offline PDF redaction with verification and hash certificates"
)]
struct Cli {
    #[command(subcommand)]
    command: Commands,

    /// Increase logging verbosity (-v, -vv).
    #[arg(short, long, action = clap::ArgAction::Count, global = true)]
    verbose: u8,
}

#[derive(Subcommand, Debug)]
enum Commands {
    /// Detect PII and write a reviewable findings JSON.
    Detect {
        input: PathBuf,
        #[arg(short, long)]
        output: Option<PathBuf>,
        #[arg(long, default_value_t = 0.35, value_parser = parse_min_confidence)]
        min_confidence: f32,
        #[arg(long, value_delimiter = ',')]
        categories: Option<Vec<CategoryArg>>,
        /// Lower confidence floor; flag weaker unlabeled ID-shaped hits (more FPs).
        #[arg(long, default_value_t = false)]
        aggressive: bool,
        #[command(flatten)]
        ocr_args: OcrArgs,
    },
    /// Apply redactions from a findings file (or manual flags).
    Redact {
        input: PathBuf,
        #[arg(short, long)]
        output: PathBuf,
        #[arg(long)]
        findings: Option<PathBuf>,
        #[arg(long)]
        cert: Option<PathBuf>,
        #[arg(long, default_value_t = 2.0, value_parser = parse_scale)]
        scale: f32,
        #[arg(long, default_value_t = 1.5, value_parser = parse_pad)]
        pad: f32,
        #[arg(long = "text", value_name = "STRING")]
        texts: Vec<String>,
        #[arg(long = "rect", value_name = "PAGE(0-based):X,Y,W,H", value_parser = parse_rect_arg)]
        rects: Vec<RectArg>,
    },
    /// Detect + redact + verify + certify in one step.
    Run {
        input: PathBuf,
        #[arg(short, long)]
        output: PathBuf,
        #[arg(long)]
        cert: Option<PathBuf>,
        #[arg(long, default_value_t = 2.0, value_parser = parse_scale)]
        scale: f32,
        #[arg(long, default_value_t = 1.5, value_parser = parse_pad)]
        pad: f32,
        #[arg(long, default_value_t = 0.35, value_parser = parse_min_confidence)]
        min_confidence: f32,
        #[arg(long, value_delimiter = ',')]
        categories: Option<Vec<CategoryArg>>,
        /// Lower confidence floor; flag weaker unlabeled ID-shaped hits (more FPs).
        #[arg(long, default_value_t = false)]
        aggressive: bool,
        #[arg(long = "text", value_name = "STRING")]
        texts: Vec<String>,
        #[arg(long = "rect", value_name = "PAGE(0-based):X,Y,W,H", value_parser = parse_rect_arg)]
        rects: Vec<RectArg>,
        /// Required for non-interactive use; refuse to run without it.
        #[arg(long)]
        yes: bool,
        /// Do not run the regex detector (manual/search only).
        #[arg(long)]
        no_detect: bool,
        #[command(flatten)]
        ocr_args: OcrArgs,
    },
    /// Re-verify an output PDF against findings, explicit strings, and/or the
    /// certificate that was emitted alongside it.
    Verify {
        output: PathBuf,
        #[arg(long)]
        findings: Option<PathBuf>,
        #[arg(long = "string")]
        strings: Vec<String>,
        /// Check the output against the embedded SHA-256 in this certificate.
        #[arg(long)]
        cert: Option<PathBuf>,
    },
    /// Download OCR models into models/ocr (or REDACT_OCR_MODELS).
    ///
    /// Shells out to scripts/download_ocrs_models.sh: requires `bash` and a
    /// network connection (downloads only the ocrs text-detection and
    /// text-recognition models; no PDF processing happens here).
    ///
    /// Windows note: stock Windows has no `bash`; use Git Bash or WSL.
    OcrSetup {
        /// Destination directory for model files.
        #[arg(long)]
        dir: Option<PathBuf>,
    },
    /// Print OCR feature status, model paths, and whether models are present.
    OcrInfo,
}

/// CLI OCR mode (always parseable; honored only when built with `ocr` feature).
#[derive(Clone, Copy, Debug, PartialEq, Eq, ValueEnum)]
enum OcrModeArg {
    Off,
    Auto,
    On,
    Force,
}

/// CLI OCR preprocess (always parseable).
#[derive(Clone, Copy, Debug, PartialEq, Eq, ValueEnum, Default)]
enum OcrPreprocessArg {
    #[default]
    Off,
    Light,
    Strong,
}

impl OcrModeArg {
    fn default_for_build() -> Self {
        #[cfg(feature = "ocr")]
        {
            OcrModeArg::Auto
        }
        #[cfg(not(feature = "ocr"))]
        {
            OcrModeArg::Off
        }
    }

    fn is_off(self) -> bool {
        matches!(self, OcrModeArg::Off)
    }
}

impl std::fmt::Display for OcrModeArg {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            OcrModeArg::Off => write!(f, "off"),
            OcrModeArg::Auto => write!(f, "auto"),
            OcrModeArg::On => write!(f, "on"),
            OcrModeArg::Force => write!(f, "force"),
        }
    }
}

/// Shared OCR-related arguments for `detect` and `run` (C12-5).
#[derive(clap::Args, Debug)]
struct OcrArgs {
    /// OCR mode: off | auto | on | force (requires --features ocr).
    /// auto: OCR short or poor text layers, unioned with native text;
    /// on: OCR every page, unioned with native text;
    /// force: OCR only, ignores the native text layer entirely.
    #[arg(long, value_enum, default_value_t = OcrModeArg::default_for_build())]
    ocr: OcrModeArg,
    /// Render scale for OCR input (default 2.5 ≈ 180 dpi).
    #[arg(long, default_value_t = 2.5, value_parser = parse_ocr_scale)]
    ocr_scale: f32,
    /// Auto mode: OCR when native text is shorter than this (default 32).
    #[arg(long, default_value_t = 32)]
    ocr_min_chars: usize,
    /// Auto mode: OCR when the native text-layer quality score is below
    /// this (0–1; default 0.45).
    #[arg(long, default_value_t = 0.45, value_parser = parse_ocr_min_quality)]
    ocr_min_quality: f32,
    /// Retry OCR (higher scale + Strong preprocess) when a page yields
    /// at most this many chars (default 0: only when OCR finds nothing).
    #[arg(long, default_value_t = 0)]
    ocr_retry_chars: usize,
    /// Override OCR models directory (else REDACT_OCR_MODELS / models/ocr).
    #[arg(long)]
    ocr_models: Option<PathBuf>,
    /// Preprocess page raster before OCR: off | light | strong (default off).
    #[arg(long, value_enum, default_value_t = OcrPreprocessArg::Off)]
    ocr_preprocess: OcrPreprocessArg,
    /// Disable sparse-OCR retry (higher scale + strong preprocess).
    #[arg(long, default_value_t = false)]
    ocr_no_retry: bool,
}

#[derive(Clone, Debug)]
struct RectArg {
    page: usize,
    rect: Rect,
}

fn parse_rect_arg(s: &str) -> std::result::Result<RectArg, String> {
    // page:x,y,w,h
    let (page_s, rest) = s
        .split_once(':')
        .ok_or_else(|| "expected PAGE:X,Y,W,H".to_string())?;
    let page: usize = page_s.parse().map_err(|_| "invalid page".to_string())?;
    let parts: Vec<&str> = rest.split(',').collect();
    if parts.len() != 4 {
        return Err("expected PAGE:X,Y,W,H".into());
    }
    let nums: Vec<f32> = parts
        .iter()
        .map(|p| p.parse::<f32>().map_err(|_| format!("invalid number {p}")))
        .collect::<std::result::Result<_, _>>()?;
    let rect = Rect::new(nums[0], nums[1], nums[2], nums[3]);
    if !rect.is_valid() {
        return Err(format!(
            "invalid rect: x/y/w/h must be finite, width/height greater than 0, \
             and magnitudes ≤ {}, got {nums:?}",
            redact_core::types::MAX_RECT_MAGNITUDE
        ));
    }
    Ok(RectArg { page, rect })
}

/// Clap value parser for `--min-confidence`: finite and within 0.0..=1.0.
///
/// Out-of-range values would otherwise have surprising semantics — `-5`
/// silently detects everything (`conf >= -5` is always true) and `2.0`
/// detects nothing, failing later with a confusing "no included regions"
/// error. Reject them as clap usage errors (exit 2) instead (n2).
fn parse_min_confidence(s: &str) -> std::result::Result<f32, String> {
    let v: f32 = s
        .parse()
        .map_err(|_| format!("invalid number for --min-confidence: {s:?}"))?;
    if !v.is_finite() || !(0.0..=1.0).contains(&v) {
        return Err(format!(
            "--min-confidence must be finite and within 0.0..=1.0, got {s:?}"
        ));
    }
    Ok(v)
}

/// `--ocr-scale` value parser: a non-positive or non-finite render scale
/// would otherwise surface only as an operational `RedactError::Render`
/// (exit 1) at the first OCR page; reject it as a clap usage error
/// (exit 2) like every other malformed flag value (m1).
fn parse_ocr_scale(s: &str) -> std::result::Result<f32, String> {
    let v: f32 = s
        .parse()
        .map_err(|_| format!("invalid number for --ocr-scale: {s:?}"))?;
    if !v.is_finite() || v <= 0.0 {
        return Err(format!("--ocr-scale must be finite and > 0, got {s:?}"));
    }
    Ok(v)
}

/// `--scale` value parser (finite and > 0), mirroring `parse_ocr_scale`.
fn parse_scale(s: &str) -> std::result::Result<f32, String> {
    let v: f32 = s
        .parse()
        .map_err(|_| format!("invalid number for --scale: {s:?}"))?;
    if !v.is_finite() || v <= 0.0 {
        return Err(format!("--scale must be finite and > 0, got {s:?}"));
    }
    Ok(v)
}

/// `--pad` value parser (finite and >= 0).
fn parse_pad(s: &str) -> std::result::Result<f32, String> {
    let v: f32 = s
        .parse()
        .map_err(|_| format!("invalid number for --pad: {s:?}"))?;
    if !v.is_finite() || v < 0.0 {
        return Err(format!("--pad must be finite and >= 0, got {s:?}"));
    }
    Ok(v)
}

/// `--ocr-min-quality` value parser (0–1, finite), mirroring
/// `parse_min_confidence`.
fn parse_ocr_min_quality(s: &str) -> std::result::Result<f32, String> {
    let v: f32 = s
        .parse()
        .map_err(|_| format!("invalid number for --ocr-min-quality: {s:?}"))?;
    if !v.is_finite() || !(0.0..=1.0).contains(&v) {
        return Err(format!(
            "--ocr-min-quality must be finite and within 0.0..=1.0, got {s:?}"
        ));
    }
    Ok(v)
}

#[derive(Clone, Copy, Debug, ValueEnum)]
enum CategoryArg {
    Identity,
    Contact,
    Financial,
    Dates,
    Other,
    Email,
    Ssn,
    Phone,
    CreditCard,
    Iban,
}

impl From<CategoryArg> for Category {
    fn from(c: CategoryArg) -> Self {
        match c {
            CategoryArg::Identity => Category::Identity,
            CategoryArg::Contact => Category::Contact,
            CategoryArg::Financial => Category::Financial,
            CategoryArg::Dates => Category::Dates,
            CategoryArg::Other => Category::Other,
            CategoryArg::Email => Category::Email,
            CategoryArg::Ssn => Category::Ssn,
            CategoryArg::Phone => Category::Phone,
            CategoryArg::CreditCard => Category::CreditCard,
            CategoryArg::Iban => Category::Iban,
        }
    }
}

/// Marker error for CLI usage mistakes (wrong invocation or invalid option
/// values, including malformed input *data* such as a findings/certificate
/// file that fails to parse). `main()` maps it to exit code 2 ("usage"),
/// alongside clap parse errors (which exit before `real_main`) and I/O
/// failures. Operational failures — stale findings, verification/cert
/// mismatch, nothing to redact — stay exit 1.
#[derive(Debug)]
struct UsageError(String);

impl std::fmt::Display for UsageError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}

impl std::error::Error for UsageError {}

/// Bail with a [`UsageError`] (exit code 2 in `main()`).
macro_rules! bail_usage {
    ($($arg:tt)*) => {
        return Err(anyhow::Error::new(UsageError(format!($($arg)*))))
    };
}

fn main() {
    // Exit codes: 0 ok, 1 operational failure, 2 usage/IO.
    let code = match real_main() {
        Ok(()) => 0,
        Err(e) => {
            eprintln!("error: {e:#}");
            exit_code_for_error(&e)
        }
    };
    std::process::exit(code);
}

/// Classify an error into the appropriate exit code.
///
/// Exit codes: 0 ok, 1 operational failure, 2 usage/IO. clap usage errors
/// already exit 2 before `real_main`; this handles explicit usage errors
/// (`UsageError`) and I/O errors (exit 2), while semantic failures (stale
/// findings, cert mismatch, nothing to redact) stay operational (exit 1).
/// Malformed findings/certificate input is wrapped in `UsageError` at the
/// call sites (C12-6).
fn exit_code_for_error(e: &anyhow::Error) -> i32 {
    if e.downcast_ref::<UsageError>().is_some() || e.downcast_ref::<std::io::Error>().is_some() {
        2
    } else {
        1
    }
}

fn real_main() -> Result<()> {
    let cli = Cli::parse();
    init_tracing(cli.verbose);

    match cli.command {
        Commands::Detect {
            input,
            output,
            min_confidence,
            categories,
            aggressive,
            ocr_args,
        } => cmd_detect(
            input,
            output,
            min_confidence,
            categories,
            aggressive,
            ocr_args,
        ),
        Commands::Redact {
            input,
            output,
            findings,
            cert,
            scale,
            pad,
            texts,
            rects,
        } => cmd_redact(input, output, findings, cert, scale, pad, texts, rects),
        Commands::Run {
            input,
            output,
            cert,
            scale,
            pad,
            min_confidence,
            categories,
            aggressive,
            texts,
            rects,
            yes,
            no_detect,
            ocr_args,
        } => cmd_run(
            input,
            output,
            cert,
            scale,
            pad,
            min_confidence,
            categories,
            aggressive,
            texts,
            rects,
            yes,
            no_detect,
            ocr_args,
        ),
        Commands::Verify {
            output,
            findings,
            strings,
            cert,
        } => cmd_verify(output, findings, strings, cert),
        Commands::OcrSetup { dir } => cmd_ocr_setup(dir),
        Commands::OcrInfo => cmd_ocr_info(),
    }
}

fn init_tracing(verbose: u8) {
    let level = match verbose {
        0 => "warn",
        1 => "info",
        _ => "debug",
    };
    let filter = EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new(level));
    let _ = tracing_subscriber::fmt()
        .with_env_filter(filter)
        .with_writer(std::io::stderr)
        .try_init();
}

/// Ensure `--ocr` other than off is only used when the binary was built with OCR.
fn require_ocr_feature(mode: OcrModeArg) -> Result<()> {
    if mode.is_off() {
        return Ok(());
    }
    #[cfg(not(feature = "ocr"))]
    {
        // m1: a flag the build does not support is a usage mistake → exit 2.
        bail_usage!(
            "--ocr {mode} requires a build with OCR support. Rebuild with:\n  \
             cargo build -p redact-cli --release --features ocr\n  \
             Then install models: redact ocr-setup  (or ./scripts/download_ocrs_models.sh)"
        );
    }
    #[cfg(feature = "ocr")]
    {
        let _ = mode;
        Ok(())
    }
}

#[allow(clippy::too_many_arguments)] // CLI plumbing: mirrors clap arg surface 1:1.
#[cfg(feature = "ocr")]
fn build_ocr_options(
    mode: OcrModeArg,
    scale: f32,
    min_chars: usize,
    min_quality: f32,
    retry_chars: usize,
    models_dir: Option<PathBuf>,
    preprocess: OcrPreprocessArg,
    no_retry: bool,
) -> redact_core::OcrOptions {
    use redact_core::{OcrMode, OcrOptions, OcrPreprocess};
    let mode = match mode {
        OcrModeArg::Off => OcrMode::Off,
        OcrModeArg::Auto => OcrMode::Auto,
        OcrModeArg::On => OcrMode::On,
        OcrModeArg::Force => OcrMode::Force,
    };
    let preprocess = match preprocess {
        OcrPreprocessArg::Off => OcrPreprocess::Off,
        OcrPreprocessArg::Light => OcrPreprocess::Light,
        OcrPreprocessArg::Strong => OcrPreprocess::Strong,
    };
    OcrOptions {
        mode,
        scale,
        auto_min_chars: min_chars,
        min_text_layer_quality: min_quality,
        sparse_retry_chars: retry_chars,
        models_dir,
        preprocess,
        retry_if_sparse: !no_retry,
        ..Default::default()
    }
}

/// Build [`DetectOptions`] from shared OCR args + detector knobs.
fn detect_options(
    min_confidence: f32,
    categories: Option<Vec<CategoryArg>>,
    aggressive: bool,
    ocr_args: &OcrArgs,
) -> DetectOptions {
    #[cfg(feature = "ocr")]
    {
        DetectOptions {
            min_confidence,
            categories: categories.map(|c| c.into_iter().map(Category::from).collect()),
            aggressive,
            ocr: build_ocr_options(
                ocr_args.ocr,
                ocr_args.ocr_scale,
                ocr_args.ocr_min_chars,
                ocr_args.ocr_min_quality,
                ocr_args.ocr_retry_chars,
                ocr_args.ocr_models.clone(),
                ocr_args.ocr_preprocess,
                ocr_args.ocr_no_retry,
            ),
        }
    }
    #[cfg(not(feature = "ocr"))]
    {
        let _ = ocr_args;
        DetectOptions {
            min_confidence,
            categories: categories.map(|c| c.into_iter().map(Category::from).collect()),
            aggressive,
        }
    }
}

/// Resolve a path to its canonical form for identity comparison, tolerating
/// a not-yet-written output file: canonicalize the parent (or CWD for bare
/// relative names) and re-join the file name.
fn canonicalize_for_compare(p: &Path) -> std::io::Result<PathBuf> {
    match std::fs::canonicalize(p) {
        Ok(c) => Ok(c),
        Err(_) => {
            let abs = if p.is_absolute() {
                p.to_path_buf()
            } else {
                std::env::current_dir()?.join(p)
            };
            match abs.parent() {
                Some(parent) => {
                    let cparent = std::fs::canonicalize(parent)?;
                    // `file_name` is `None` for paths terminating in `..`
                    // (and `/`); joining an empty default would resolve to the
                    // parent itself and could confuse the clobber guard, so
                    // fall back to a direct canonicalization instead.
                    match abs.file_name() {
                        Some(name) => Ok(cparent.join(name)),
                        None => std::fs::canonicalize(&abs),
                    }
                }
                None => std::fs::canonicalize(&abs),
            }
        }
    }
}

/// True when `a` and `b` refer to the same file, resolving `.`/`..`, symlinks,
/// and case variants so equivalent spellings (`./doc.pdf` vs `doc.pdf`) can't
/// bypass the input==output clobber guard (C12-2). Falls back to lexical
/// equality when canonicalization is impossible.
fn same_file(a: &Path, b: &Path) -> bool {
    match (canonicalize_for_compare(a), canonicalize_for_compare(b)) {
        (Ok(ca), Ok(cb)) => ca == cb,
        _ => a == b,
    }
}

fn cmd_detect(
    input: PathBuf,
    output: Option<PathBuf>,
    min_confidence: f32,
    categories: Option<Vec<CategoryArg>>,
    aggressive: bool,
    ocr_args: OcrArgs,
) -> Result<()> {
    require_ocr_feature(ocr_args.ocr)?;
    // C12-2: refuse to overwrite the input file — detect's findings JSON write
    // would otherwise clobber the source PDF with JSON and lose the document.
    if let Some(path) = &output
        && same_file(&input, path)
    {
        bail_usage!("output must differ from input");
    }
    let bytes = std::fs::read(&input).with_context(|| format!("read {}", input.display()))?;
    let opts = detect_options(min_confidence, categories, aggressive, &ocr_args);
    let detect = detect_document(&bytes, &opts)?;
    // Warn on image-only / scanned inputs only after a successful parse: the
    // count comes from the detect pass itself (single document open, n3), so
    // a corrupt input surfaces its real open error instead of a spurious
    // "no extractable text layer" warning ahead of it.
    if detect.text_char_count == 0 {
        #[cfg(feature = "ocr")]
        {
            if matches!(ocr_args.ocr, OcrModeArg::Off) {
                let dir = redact_core::resolve_models_dir(ocr_args.ocr_models.as_deref());
                if redact_core::has_models(&dir) {
                    eprintln!(
                        "warning: no extractable text layer (image-only or scanned PDF). \
                         Try --ocr auto (models found at {}).",
                        dir.display()
                    );
                } else {
                    eprintln!(
                        "warning: no extractable text layer (image-only or scanned PDF). \
                         Run `redact ocr-setup` then re-run with --ocr auto."
                    );
                }
            }
        }
        #[cfg(not(feature = "ocr"))]
        {
            let _ = &ocr_args;
            eprintln!(
                "warning: no extractable text layer (image-only or scanned PDF). \
                 Auto-detect will return zero findings. Rebuild with --features ocr \
                 and use --ocr auto (see `redact ocr-info`)."
            );
        }
    }
    let findings = FindingsFile::from_detect(
        Some(input.display().to_string()),
        sha256_hex(&bytes),
        &detect.regions,
        &detect.unmapped,
        // Region does not yet carry detector_id; provenance is threaded for
        // unmapped items only until the geometry layer is extended (C09-m1).
        None,
    )?;
    if !detect.unmapped.is_empty() {
        // C10-M1: an unmappable hit must never vanish silently — it is listed
        // in the findings file as an excluded (included: false) item so the
        // human reviewer sees the detector fired but no geometry was produced.
        eprintln!(
            "warning: {} detector hit(s) could not be mapped to glyph geometry \
             (no usable text spans); listed as excluded (included: false) items \
             that will NOT be redacted",
            detect.unmapped.len()
        );
    }
    let json = findings.to_json()?;
    if let Some(path) = output {
        std::fs::write(&path, json).with_context(|| format!("write {}", path.display()))?;
        eprintln!(
            "wrote {} finding(s) to {}",
            findings.items.len(),
            path.display()
        );
    } else {
        println!("{json}");
    }
    Ok(())
}

#[allow(clippy::too_many_arguments)]
fn cmd_redact(
    input: PathBuf,
    output: PathBuf,
    findings: Option<PathBuf>,
    cert: Option<PathBuf>,
    scale: f32,
    pad: f32,
    texts: Vec<String>,
    rects: Vec<RectArg>,
) -> Result<()> {
    // C12-2: refuse to overwrite the input file (in-place clobber would lose
    // the original document on the full-save path). Compare canonical paths so
    // `./doc.pdf` vs `doc.pdf`, symlinks, and case variants can't bypass it.
    if same_file(&input, &output) {
        bail_usage!("output must differ from input");
    }
    let bytes = std::fs::read(&input).with_context(|| format!("read {}", input.display()))?;
    let mut regions = Vec::new();

    if let Some(path) = &findings {
        let raw =
            std::fs::read_to_string(path).with_context(|| format!("read {}", path.display()))?;
        // m1: malformed findings *data* (unparseable JSON, invalid items) is a
        // usage/input-data error → exit 2; semantic staleness below stays 1.
        let f = FindingsFile::from_json(&raw)
            .map_err(|e| UsageError(format!("invalid findings file {}: {e}", path.display())))?;
        // The findings file records the exact input it was detected against;
        // applying stale geometry to a modified/different PDF would silently
        // redact shifted content, so refuse on mismatch.
        f.check_source_sha256(&sha256_hex(&bytes))?;
        regions.extend(
            f.to_regions().map_err(|e| {
                UsageError(format!("invalid findings file {}: {e}", path.display()))
            })?,
        );
    }

    let has_extra = !texts.is_empty() || !rects.is_empty();
    let excluded = regions.iter().filter(|r| !r.included).count();
    if !has_extra {
        // n4: distinguish "nothing given" (usage → 2) from "given but nothing
        // applicable" (operational → 1).
        if regions.is_empty() {
            if findings.is_some() {
                bail!(
                    "findings file contains no applicable items (all items are unmapped \
                     or the file has none); nothing to redact"
                );
            }
            bail_usage!("provide --findings and/or --text / --rect");
        }
        // m3: excluded findings must not silently produce an unredacted output —
        // guard on the *included* count and warn when the human unchecked some.
        if excluded == regions.len() {
            bail!(
                "no included findings to redact (every item is excluded in the \
                 findings file)"
            );
        }
    }
    if excluded > 0 {
        eprintln!(
            "warning: {} of {} finding(s) are excluded (included: false) and will not be redacted",
            excluded,
            regions.len()
        );
    }

    let apply = ApplyOptions { scale, pad };
    let result = if has_extra {
        // Map search texts / manual rects into regions via the core, then
        // redact findings + search + manual in a single document open (m2) —
        // no second/third parse of the input.
        let run = RunOptions {
            detect: DetectOptions::default(),
            apply: apply.clone(),
            search_texts: texts,
            manual_rects: rects
                .into_iter()
                .map(|r| (r.page, r.rect, "manual".into()))
                .collect(),
            run_detector: false,
        };
        redact_with_regions_and_options(&bytes, &regions, &run, &apply)?
    } else {
        redact_with_regions(&bytes, &regions, &apply)?
    };
    write_outputs(&output, cert.as_deref(), &result)?;
    Ok(())
}

#[allow(clippy::too_many_arguments)]
fn cmd_run(
    input: PathBuf,
    output: PathBuf,
    cert: Option<PathBuf>,
    scale: f32,
    pad: f32,
    min_confidence: f32,
    categories: Option<Vec<CategoryArg>>,
    aggressive: bool,
    texts: Vec<String>,
    rects: Vec<RectArg>,
    yes: bool,
    no_detect: bool,
    ocr_args: OcrArgs,
) -> Result<()> {
    if !yes {
        bail_usage!("refusing to run without --yes (non-interactive safety)");
    }
    // C12-2: refuse to overwrite the input file (in-place clobber would lose
    // the original document on the full-save path). Compare canonical paths so
    // `./doc.pdf` vs `doc.pdf`, symlinks, and case variants can't bypass it.
    if same_file(&input, &output) {
        bail_usage!("output must differ from input");
    }
    // n4: with the detector disabled and nothing given, `run` has nothing to
    // redact — "nothing given" is a usage error (exit 2), unlike "given but
    // nothing applicable" which stays operational (exit 1).
    if no_detect && texts.is_empty() && rects.is_empty() {
        bail_usage!("--no-detect requires --text and/or --rect (nothing to redact otherwise)");
    }
    require_ocr_feature(ocr_args.ocr)?;
    let bytes = std::fs::read(&input).with_context(|| format!("read {}", input.display()))?;
    let opts = RunOptions {
        detect: detect_options(min_confidence, categories, aggressive, &ocr_args),
        apply: ApplyOptions { scale, pad },
        search_texts: texts,
        manual_rects: rects
            .into_iter()
            .map(|r| (r.page, r.rect, "manual".into()))
            .collect(),
        run_detector: !no_detect,
    };
    let result = run_pipeline(&bytes, &opts)?;
    write_outputs(&output, cert.as_deref(), &result)?;
    Ok(())
}

fn cmd_verify(
    output: PathBuf,
    findings: Option<PathBuf>,
    strings: Vec<String>,
    cert: Option<PathBuf>,
) -> Result<()> {
    let bytes = std::fs::read(&output).with_context(|| format!("read {}", output.display()))?;

    if let Some(path) = cert.as_deref() {
        // Intentionally verify the certificate first: a cert mismatch is a
        // strong signal of tampering and should abort before findings/text
        // checks, so the user learns the most severe issue first (C12-3).
        let raw =
            std::fs::read_to_string(path).with_context(|| format!("read {}", path.display()))?;
        // m1: an unparseable certificate file is usage/input-data → exit 2; a
        // readable certificate that doesn't match stays operational → 1.
        let c = certificate_from_json(&raw)
            .map_err(|e| UsageError(format!("invalid certificate file {}: {e}", path.display())))?;
        let actual = sha256_hex(&bytes);
        if certificate_matches_output(&c, &bytes) {
            println!("PASS  cert-output-sha256  output matches certificate (sha256 {actual})");
        } else {
            println!(
                "FAIL  cert-output-sha256  output sha256 {actual} != certificate {}",
                c.output.sha256
            );
            bail!("certificate does not match output file");
        }
    }

    if findings.is_none() && strings.is_empty() {
        if cert.is_some() {
            // C12-4: cert-only verify proves file identity, not content
            // secrecy — warn so the user doesn't mistake it for full
            // verification.
            eprintln!(
                "warning: cert-only verify checks file identity, not content \
                 secrecy; use --findings/--string to verify redactions"
            );
            return Ok(());
        }
        bail_usage!("provide --findings and/or --string (or --cert)");
    }

    let mut regions = Vec::new();
    if let Some(path) = findings {
        let raw =
            std::fs::read_to_string(&path).with_context(|| format!("read {}", path.display()))?;
        let f = FindingsFile::from_json(&raw)
            .map_err(|e| UsageError(format!("invalid findings file {}: {e}", path.display())))?;
        regions.extend(
            f.to_regions()
                .map_err(|e| UsageError(format!("invalid findings file {}: {e}", path.display())))?
                .into_iter()
                .filter(|r| r.included),
        );
    }
    for s in strings {
        regions.push(redact_core::Region {
            // No single page owns a search-string region; using usize::MAX
            // avoids under-reporting the page span in the verify detail
            // message (C12-1). The actual secret-search/pixel-removal checks
            // scan all pages regardless of this value.
            page_index: usize::MAX,
            rects: vec![],
            source_text: s,
            category: Category::Custom,
            confidence: 1.0,
            included: true,
            source: redact_core::MatchSource::Manual,
        });
    }
    if regions.is_empty() {
        // n4: "nothing given" was already a usage error above; reaching here
        // means inputs were given but nothing is applicable (all findings
        // items excluded/unmapped) — operational, not usage.
        bail!(
            "no included findings/strings to verify (every findings item is \
             excluded or unmapped)"
        );
    }
    let v = verify_output(&bytes, &regions)?;
    for c in &v.checks {
        let mark = if c.passed { "PASS" } else { "FAIL" };
        println!("{mark}  {} — {}", c.id, c.detail);
    }
    if !v.passed {
        bail!("verification failed");
    }
    Ok(())
}

fn cmd_ocr_setup(dir: Option<PathBuf>) -> Result<()> {
    // Prefer reusing scripts/download_ocrs_models.sh to avoid new network deps.
    let script = find_download_script()?;
    let mut cmd = std::process::Command::new("bash");
    cmd.arg(&script);
    if let Some(d) = dir {
        // Script respects REDACT_OCR_MODELS.
        cmd.env("REDACT_OCR_MODELS", &d);
        eprintln!("installing OCR models → {}", d.display());
    } else if let Ok(env_dir) = std::env::var("REDACT_OCR_MODELS") {
        eprintln!("installing OCR models → {env_dir} (REDACT_OCR_MODELS)");
    } else {
        eprintln!("installing OCR models → models/ocr (default)");
    }
    let status = cmd
        .status()
        .with_context(|| format!("run {}", script.display()))?;
    if !status.success() {
        bail!(
            "model download failed (exit {:?}). You can also run:\n  {}",
            status.code(),
            script.display()
        );
    }
    Ok(())
}

fn cmd_ocr_info() -> Result<()> {
    #[cfg(feature = "ocr")]
    {
        println!("ocr feature: enabled");
        let dir = redact_core::resolve_models_dir(None);
        let present = redact_core::has_models(&dir);
        println!("models dir:  {}", dir.display());
        println!(
            "models:      {}",
            if present {
                "found (text-detection.rten + text-recognition.rten)"
            } else {
                "missing — run: redact ocr-setup"
            }
        );
        if let Ok(env) = std::env::var("REDACT_OCR_MODELS") {
            println!("REDACT_OCR_MODELS: {env}");
        }
        println!("default CLI --ocr: auto");
        println!("backend: pure Rust ocrs + rten (no System Tesseract)");
    }
    #[cfg(not(feature = "ocr"))]
    {
        println!("ocr feature: disabled");
        println!("rebuild with: cargo build -p redact-cli --release --features ocr");
        println!("then:         redact ocr-setup");
        println!("default CLI --ocr: off");
        // Still report if models exist on disk for user convenience.
        let candidates = [
            std::env::var_os("REDACT_OCR_MODELS").map(PathBuf::from),
            Some(PathBuf::from("models/ocr")),
            Some(PathBuf::from("models")),
        ];
        for c in candidates.into_iter().flatten() {
            let det = c.join("text-detection.rten");
            let rec = c.join("text-recognition.rten");
            if det.is_file() && rec.is_file() {
                println!(
                    "models on disk: {} (present; binary still needs --features ocr)",
                    c.display()
                );
                break;
            }
        }
    }
    Ok(())
}

fn find_download_script() -> Result<PathBuf> {
    // Walk up from CWD and from the executable to find scripts/download_ocrs_models.sh.
    let name = Path::new("scripts/download_ocrs_models.sh");
    let mut candidates = Vec::new();
    if let Ok(cwd) = std::env::current_dir() {
        let mut d = cwd;
        for _ in 0..6 {
            candidates.push(d.join(name));
            if !d.pop() {
                break;
            }
        }
    }
    if let Ok(exe) = std::env::current_exe()
        && let Some(mut d) = exe.parent().map(|p| p.to_path_buf())
    {
        for _ in 0..8 {
            candidates.push(d.join(name));
            if !d.pop() {
                break;
            }
        }
    }
    // Common relative path when run from repo root / target/*/
    candidates.push(PathBuf::from(name));
    for c in &candidates {
        if c.is_file() {
            return Ok(c.clone());
        }
    }
    bail!(
        "could not find scripts/download_ocrs_models.sh (searched from CWD and executable). \
         Run from the repo root, or: bash scripts/download_ocrs_models.sh"
    );
}

fn write_outputs(
    output: &Path,
    cert: Option<&Path>,
    result: &redact_core::PipelineResult,
) -> Result<()> {
    std::fs::write(output, &result.output)
        .with_context(|| format!("write {}", output.display()))?;
    eprintln!(
        "wrote {} ({} redaction(s), verified)",
        output.display(),
        result.regions.iter().filter(|r| r.included).count()
    );
    if let Some(path) = cert {
        // Defense-in-depth: re-read the just-written output file from disk so
        // the certified output hash binds to the durable artifact, not just
        // the in-memory buffer (TOCTOU — a partial flush or truncation would
        // otherwise leave the cert attesting bytes that differ from the file).
        let mut cert = result.certificate.clone();
        let durable =
            std::fs::read(output).with_context(|| format!("read back {}", output.display()))?;
        cert.output.sha256 = redact_core::sha256_hex(&durable);
        let json = certificate_to_json(&cert)?;
        std::fs::write(path, json).with_context(|| format!("write {}", path.display()))?;
        eprintln!("wrote certificate {}", path.display());
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_rect_arg_valid() {
        let r = parse_rect_arg("0:72,640,120,14").unwrap();
        assert_eq!(r.page, 0);
        assert_eq!(r.rect, Rect::new(72.0, 640.0, 120.0, 14.0));
    }

    #[test]
    fn parse_rect_arg_missing_colon() {
        let err = parse_rect_arg("072,640,120,14").unwrap_err();
        assert!(err.contains("PAGE:X,Y,W,H"), "got: {err}");
    }

    #[test]
    fn parse_rect_arg_five_parts() {
        let err = parse_rect_arg("0:1,2,3,4,5").unwrap_err();
        assert!(err.contains("PAGE:X,Y,W,H"), "got: {err}");
    }

    #[test]
    fn parse_rect_arg_non_numeric_page() {
        let err = parse_rect_arg("x:1,2,3,4").unwrap_err();
        assert!(err.contains("invalid page"), "got: {err}");
    }

    #[test]
    fn parse_rect_arg_non_numeric_coord() {
        let err = parse_rect_arg("0:a,2,3,4").unwrap_err();
        assert!(err.contains("invalid number"), "got: {err}");
    }

    #[test]
    fn parse_rect_arg_nan_coords() {
        // "nan" parses as f32::NAN, so rejection must come from Rect::is_valid.
        let err = parse_rect_arg("0:nan,1,2,3").unwrap_err();
        assert!(err.contains("invalid rect"), "got: {err}");
    }

    #[test]
    fn parse_rect_arg_negative_width_or_height() {
        for s in ["0:1,2,-3,4", "0:1,2,3,-4"] {
            let err = parse_rect_arg(s).unwrap_err();
            assert!(err.contains("invalid rect"), "{s} → {err}");
        }
    }

    #[test]
    fn parse_min_confidence_range() {
        assert_eq!(parse_min_confidence("0.5").unwrap(), 0.5);
        assert_eq!(parse_min_confidence("0").unwrap(), 0.0);
        assert_eq!(parse_min_confidence("1").unwrap(), 1.0);
        for bad in ["-0.1", "1.5", "nan", "inf", "-inf", "abc"] {
            assert!(parse_min_confidence(bad).is_err(), "{bad} must be rejected");
        }
    }

    // C12-6: unit-test the exit-code classification logic in isolation.

    #[test]
    fn exit_code_usage_error_is_2() {
        let e = anyhow::Error::new(UsageError("bad invocation".into()));
        assert_eq!(exit_code_for_error(&e), 2);
    }

    #[test]
    fn exit_code_io_error_is_2() {
        let e = anyhow::Error::new(std::io::Error::new(
            std::io::ErrorKind::PermissionDenied,
            "permission denied",
        ));
        assert_eq!(exit_code_for_error(&e), 2);
    }

    #[test]
    fn exit_code_operational_error_is_1() {
        // A plain anyhow bail! is a semantic/operational failure → exit 1.
        let e = anyhow::Error::msg("verification failed");
        assert_eq!(exit_code_for_error(&e), 1);
    }

    #[test]
    fn exit_code_wrapped_usage_error_is_2() {
        // UsageError wrapped with additional context must still classify as 2.
        let e = anyhow::Error::new(UsageError("invalid findings".into()))
            .context("failed during redact");
        assert_eq!(exit_code_for_error(&e), 2);
    }
}
