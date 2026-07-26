//! OCR backends: produce `PageText` from page rasters (feature = `"ocr"`).
//!
//! Pure Rust only (`ocrs` + `rten`). No System Tesseract.

mod coords;
mod models;
mod ocrs_backend;
mod page_text;
mod preprocess;

pub use coords::{pixel_rect_to_page, pixel_to_page};
pub use models::{DETECTION_MODEL, RECOGNITION_MODEL, has_models, model_paths, resolve_models_dir};
pub use ocrs_backend::OcrsBackend;
pub use page_text::{OcrWord, page_text_from_lines};
pub use preprocess::{OcrPreprocess, preprocess_rgba};

use std::path::PathBuf;

use image::RgbaImage;

use crate::Result;
use crate::engine::HayroDocument;
use crate::error::RedactError;
use crate::types::PageText;

/// Produces page text + geometry in hayro top-left page space (unscaled points).
pub trait OcrBackend: Send + Sync {
    fn ocr_page(
        &self,
        rgba: &RgbaImage,
        page_index: usize,
        page_width: f32,
        page_height: f32,
        scale: f32,
    ) -> Result<PageText>;
}

/// When / whether to run OCR on a page (pipeline wiring is O2).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum OcrMode {
    /// Never OCR.
    #[default]
    Off,
    /// OCR when native text is sparse (`auto_min_chars`) or its text-layer
    /// quality is poor. OCR output is *unioned* with native detections (like
    /// [`OcrMode::On`]): the native layer is never discarded, because OCR is
    /// lossy and can misrecognize the very tokens that triggered it (C13-M1).
    Auto,
    /// OCR every page, unioned with native text.
    On,
    /// OCR only; ignore native text (debug / ablation).
    Force,
}

/// Options for OCR text acquisition.
#[derive(Debug, Clone)]
pub struct OcrOptions {
    pub mode: OcrMode,
    /// Render scale for OCR input (default 2.5 ≈ 180 dpi from 72 dpi).
    pub scale: f32,
    /// In `Auto` mode, OCR when native page char count is below this (default 32).
    pub auto_min_chars: usize,
    /// In `Auto` mode, OCR when native text-layer quality score is below this
    /// (0–1; default 0.45). Mirrors VeriRedact “poor text layer → OCR”.
    pub min_text_layer_quality: f32,
    /// Override model directory search.
    pub models_dir: Option<PathBuf>,
    /// Pixel preprocess before recognition (helps noisy scans).
    pub preprocess: OcrPreprocess,
    /// If OCR text is sparse, retry at higher scale with Strong preprocess.
    pub retry_if_sparse: bool,
    /// Char threshold that triggers sparse retry (default 0: only retry when
    /// OCR found *nothing*; raise to also retry short-but-nonempty output).
    pub sparse_retry_chars: usize,
    /// Scale used on sparse retry (default 3.5).
    pub retry_scale: f32,
}

impl Default for OcrOptions {
    fn default() -> Self {
        Self {
            mode: OcrMode::Off,
            scale: 2.5,
            auto_min_chars: 32,
            min_text_layer_quality: 0.45,
            models_dir: None,
            // Off by default: Light can hurt already-clean renders (Medium).
            // Sparse retry still applies Strong when OCR text is thin.
            preprocess: OcrPreprocess::Off,
            retry_if_sparse: true,
            sparse_retry_chars: 0,
            retry_scale: 3.5,
        }
    }
}

/// Decision for one page under [`OcrOptions`]. Auto mode carries the
/// computed quality assessment so callers do not re-run the scorer.
#[derive(Debug, Clone)]
pub struct PageOcrDecision {
    /// Whether OCR should run for this page.
    pub needs_ocr: bool,
    /// Text-layer quality assessment in Auto mode once the char-count gate
    /// passed; `None` for non-Auto modes and for text below `auto_min_chars`.
    pub quality: Option<crate::text_quality::TextLayerQuality>,
}

impl OcrOptions {
    /// Single authoritative per-page policy: OCR when native text is short
    /// (`auto_min_chars`) **or** text-layer quality is poor.
    pub fn page_ocr_decision(&self, native_text: &str) -> PageOcrDecision {
        match self.mode {
            OcrMode::Off => PageOcrDecision {
                needs_ocr: false,
                quality: None,
            },
            OcrMode::On | OcrMode::Force => PageOcrDecision {
                needs_ocr: true,
                quality: None,
            },
            OcrMode::Auto => {
                let n = native_text.chars().count();
                if n < self.auto_min_chars {
                    return PageOcrDecision {
                        needs_ocr: true,
                        quality: None,
                    };
                }
                let q = crate::text_quality::assess_text_layer(native_text);
                PageOcrDecision {
                    needs_ocr: q.is_poor(self.min_text_layer_quality),
                    quality: Some(q),
                }
            }
        }
    }

    /// Whether a page should be OCR'd under these options (delegates to
    /// [`OcrOptions::page_ocr_decision`] so one policy is authoritative).
    pub fn page_needs_ocr_text(&self, native_text: &str) -> bool {
        self.page_ocr_decision(native_text).needs_ocr
    }
}

/// Render a page then run OCR with default options (Force mode + `scale`;
/// everything else comes from [`OcrOptions::default`] — preprocess Off,
/// sparse retry on with the default near-empty gate). Prefer
/// [`ocr_page_from_doc_with_opts`] when any policy needs to differ.
pub fn ocr_page_from_doc(
    doc: &HayroDocument,
    page: usize,
    backend: &dyn OcrBackend,
    scale: f32,
) -> Result<PageText> {
    ocr_page_from_doc_with_opts(
        doc,
        page,
        backend,
        &OcrOptions {
            mode: OcrMode::Force,
            scale,
            ..Default::default()
        },
    )
}

/// Render + optional preprocess + optional sparse retry.
pub fn ocr_page_from_doc_with_opts(
    doc: &HayroDocument,
    page: usize,
    backend: &dyn OcrBackend,
    opts: &OcrOptions,
) -> Result<PageText> {
    let native = doc.page_text(page)?;
    // n4: validate primary scale up-front for symmetry with the retry-scale
    // guard — render_page already validates, but returns Render instead of Ocr.
    if !opts.scale.is_finite() || opts.scale <= 0.0 {
        return Err(RedactError::Ocr(format!(
            "scale must be finite and > 0, got {:?}",
            opts.scale
        )));
    }
    let mut rgba = doc.render_page(page, opts.scale)?;
    preprocess_rgba(&mut rgba, opts.preprocess);
    let mut page_text = backend.ocr_page(&rgba, page, native.width, native.height, opts.scale)?;

    // Sparse retry is gated on *near-empty* output (`sparse_retry_chars`,
    // default 0 → only when OCR found nothing): a second full render at
    // 3.5× plus another detection+recognition inference on every short-but-
    // legitimate page (footer, one-line memo, form label) is pure cost
    // (C13-M2). Retry pass selection requires both higher text quality
    // (alphanumeric density) and a minimum character floor, so a
    // hallucinating high-scale pass cannot displace accurate short text
    // (C13-M2, C13-5).
    if opts.retry_if_sparse && page_text.text.chars().count() <= opts.sparse_retry_chars {
        let retry_scale = opts.retry_scale;
        // n4: explicit validation like `render_page` gives `scale` — a
        // 0/negative/NaN retry scale is an error, not a silent no-op clamp.
        if !retry_scale.is_finite() || retry_scale <= 0.0 {
            return Err(RedactError::Ocr(format!(
                "retry_scale must be finite and > 0, got {retry_scale:?} (sparse retry is enabled)"
            )));
        }
        tracing::debug!(
            page,
            chars = page_text.text.chars().count(),
            retry_scale,
            "OCR sparse; retrying with Strong preprocess"
        );
        let mut rgba2 = doc.render_page(page, retry_scale)?;
        preprocess_rgba(&mut rgba2, OcrPreprocess::Strong);
        let retry = backend.ocr_page(&rgba2, page, native.width, native.height, retry_scale)?;
        let first_score = ocr_pass_quality(&page_text.text);
        let retry_score = ocr_pass_quality(&retry.text);
        // C13-5: require the retry to beat both the quality score *and* a
        // minimum length floor so a hallucinating retry pass that produces a
        // few word-like tokens cannot displace an accurate near-empty first
        // pass. The floor is 50% more characters than the first pass (but at
        // least 1), so a single-token retry can never win on quality alone.
        let first_chars = page_text.text.chars().count();
        let retry_chars = retry.text.chars().count();
        // Zero-quality output (pure punctuation/symbols, no alphanumerics)
        // carries no PII signal, so a score-0 retry must never displace a
        // score-0 (empty or equally useless) first pass. When `first_score`
        // is already > 0 any winning retry has `retry_score > 0` anyway, so
        // this is exactly "strict `>` when first_score == 0".
        let retry_beats_quality = retry_score > 0.0
            && (retry_score > first_score
                || (retry_score == first_score && retry_chars > first_chars));
        // C13-5: the floor is 50% more characters than the first pass (but at
        // least 1) — `first_chars + 1` let a single extra garbage char win on
        // length alone.
        let retry_meets_floor =
            retry_chars >= first_chars.saturating_add(first_chars.div_ceil(2)).max(1);
        if retry_beats_quality && retry_meets_floor {
            page_text = retry;
        }
    }
    Ok(page_text)
}

/// Quality signal for choosing between two OCR passes: share of
/// alphanumeric characters (0–1). Clean prose and digit-heavy identifiers
/// score high; pure punctuation/symbol noise scores 0.
fn ocr_pass_quality(text: &str) -> f32 {
    let n = text.chars().count();
    if n == 0 {
        return 0.0;
    }
    let alnum = text.chars().filter(|c| c.is_alphanumeric()).count();
    alnum as f32 / n as f32
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn options_auto_min_chars() {
        let opts = OcrOptions {
            mode: OcrMode::Auto,
            auto_min_chars: 10,
            ..Default::default()
        };
        // Below the char gate → OCR regardless of content.
        assert!(opts.page_needs_ocr_text("012345678"));
        // At/above the gate, clean text is not OCR'd.
        assert!(!opts.page_needs_ocr_text("abcdefghij"));
        // Mode coverage: Off never OCRs; On/Force always do.
        let off = OcrOptions {
            mode: OcrMode::Off,
            ..Default::default()
        };
        assert!(!off.page_needs_ocr_text("012345678"));
        let on = OcrOptions {
            mode: OcrMode::On,
            ..Default::default()
        };
        assert!(on.page_needs_ocr_text(""));
        let force = OcrOptions {
            mode: OcrMode::Force,
            ..Default::default()
        };
        assert!(force.page_needs_ocr_text("0123456789"));
    }

    #[test]
    fn auto_decision_carries_quality_assessment() {
        let opts = OcrOptions {
            mode: OcrMode::Auto,
            auto_min_chars: 8,
            min_text_layer_quality: 0.45,
            ..Default::default()
        };
        // Below the char gate: OCR, but no quality assessment is produced.
        let short = opts.page_ocr_decision("short");
        assert!(short.needs_ocr);
        assert!(short.quality.is_none());
        // Garbage above the gate: OCR, and the assessment says poor.
        let garbage = "%%%%$$$$####@@@@!!!!%%%%$$$$####@@@@!!!!%%%%$$$$####";
        let d = opts.page_ocr_decision(garbage);
        assert!(d.needs_ocr);
        let q = d.quality.expect("quality assessed above char gate");
        assert!(q.is_poor(opts.min_text_layer_quality));
        // Clean prose above the gate: native text, quality is fine.
        let prose =
            "Patient Name: Jane Doe born on 01/02/1990 SSN 123-45-6789 hospital visit notes.";
        let d = opts.page_ocr_decision(prose);
        assert!(!d.needs_ocr);
        let q = d.quality.expect("quality assessed above char gate");
        assert!(!q.is_poor(opts.min_text_layer_quality));
        // Off mode: never OCR, no assessment.
        let off = OcrOptions {
            mode: OcrMode::Off,
            ..Default::default()
        };
        let d = off.page_ocr_decision(prose);
        assert!(!d.needs_ocr);
        assert!(d.quality.is_none());
    }

    #[test]
    fn default_preprocess_is_off_with_sparse_retry() {
        assert_eq!(OcrOptions::default().preprocess, OcrPreprocess::Off);
        assert!(OcrOptions::default().retry_if_sparse);
    }

    #[test]
    fn auto_uses_text_quality_not_only_length() {
        let opts = OcrOptions {
            mode: OcrMode::Auto,
            auto_min_chars: 8,
            min_text_layer_quality: 0.45,
            ..Default::default()
        };
        // Long enough to pass char threshold, but garbage → still needs OCR.
        let garbage = "%%%%$$$$####@@@@!!!!%%%%$$$$####@@@@!!!!%%%%$$$$####";
        assert!(garbage.chars().count() >= opts.auto_min_chars);
        assert!(opts.page_needs_ocr_text(garbage));
        // Clean prose should not need OCR.
        let prose =
            "Patient Name: Jane Doe born on 01/02/1990 SSN 123-45-6789 hospital visit notes.";
        assert!(!opts.page_needs_ocr_text(prose));
    }
}
