//! High-level detect → apply → verify → certify pipeline.

use crate::apply::apply_regions_in;
use crate::cert::{Certificate, build_certificate};
use crate::detect::detect;
use crate::engine::HayroDocument;
use crate::error::{RedactError, Result};
use crate::geometry::{map_matches, regions_for_search_text_in, require_mapped};
use crate::types::{ApplyOptions, DetectOptions, PageText, Rect, Region, TextMatch};
use crate::verify::{VerificationResult, verify_output_with_page_count};

/// Lazily materialize the OCR backend slot and return a reference to it.
///
/// Non-panicking by construction: the `None` arm runs the loader and `?`
/// propagates load failure; the follow-up match re-checks the slot instead
/// of unwrapping, so a future refactor can never panic here (C13-n1).
#[cfg(feature = "ocr")]
fn ensure_ocr_backend<'a>(
    slot: &'a mut Option<Box<dyn crate::ocr::OcrBackend>>,
    load: &mut dyn FnMut() -> Result<Box<dyn crate::ocr::OcrBackend>>,
) -> Result<&'a dyn crate::ocr::OcrBackend> {
    if slot.is_none() {
        *slot = Some(load()?);
    }
    match slot.as_ref() {
        Some(b) => Ok(b.as_ref()),
        None => Err(RedactError::Ocr(
            "OCR backend slot empty after successful load".into(),
        )),
    }
}

/// Production OCR backend loader for pipeline runs (models from `opts`).
/// Public entry points use this; tests inject their own loader (C13-m3).
#[cfg(feature = "ocr")]
fn ocr_backend_loader(
    opts: &RunOptions,
) -> impl FnMut() -> Result<Box<dyn crate::ocr::OcrBackend>> + '_ {
    move || {
        let b = crate::ocr::OcrsBackend::load(opts.detect.ocr.models_dir.as_deref())?;
        Ok(Box::new(b) as Box<dyn crate::ocr::OcrBackend>)
    }
}

/// Production OCR backend loader for detect-only runs (models from `opts`).
#[cfg(feature = "ocr")]
fn ocr_backend_loader_detect(
    opts: &DetectOptions,
) -> impl FnMut() -> Result<Box<dyn crate::ocr::OcrBackend>> + '_ {
    move || {
        let b = crate::ocr::OcrsBackend::load(opts.ocr.models_dir.as_deref())?;
        Ok(Box::new(b) as Box<dyn crate::ocr::OcrBackend>)
    }
}

#[derive(Debug)]
pub struct PipelineResult {
    pub output: Vec<u8>,
    pub regions: Vec<Region>,
    pub verification: VerificationResult,
    pub certificate: Certificate,
    /// Per-page text acquisition source (`"native"`, `"ocr"`, `"hybrid"`).
    /// Populated on every pipeline run (`"native"` for non-OCR builds);
    /// `"hybrid"` only once an OCR pass actually ran for the page.
    pub text_sources: TextSources,
}

/// Per-page text acquisition source labels (`"native"`, `"ocr"`, `"hybrid"`).
pub type TextSources = Vec<(usize, &'static str)>;

/// Result of a detect-only pass ([`detect_document`]).
///
/// The `unmapped` list carries every detector hit that fired but could not be
/// mapped to glyph geometry (text layer without usable spans, sticky-glue
/// failure). These are surfaced to the findings file as excluded items so the
/// human-review workflow learns a secret was found but could not be painted —
/// never silently dropped (C10-M1).
#[derive(Debug)]
pub struct DetectDocumentResult {
    pub regions: Vec<Region>,
    /// Unmapped hits as `(page_index, match)` pairs.
    pub unmapped: Vec<(usize, TextMatch)>,
    /// Extractable text chars across all pages (native, or OCR where it ran).
    /// Zero means image-only / scanned pages; surfaced so the CLI can warn
    /// without re-parsing the input for a char count (C12-n3).
    pub text_char_count: usize,
}

#[derive(Debug, Clone, Default)]
pub struct RunOptions {
    pub detect: DetectOptions,
    pub apply: ApplyOptions,
    /// Extra exact strings to redact on every page.
    pub search_texts: Vec<String>,
    /// Manual rectangles (page_index, rect, label).
    pub manual_rects: Vec<(usize, Rect, String)>,
    /// If true, run detector; if false, only manual/search.
    pub run_detector: bool,
}

/// Confidence key for ordering: non-finite values (NaN/±inf) map to -inf so
/// they sort below every finite value. `partial_cmp` returns `None` for NaN
/// and treating that as `Equal` is intransitive (`0.5 == NaN`, `NaN == 0.7`,
/// but `0.5 < 0.7`) — a total order is required by `sort_by` (C10-m3).
fn conf_ord_key(c: f32) -> f32 {
    if c.is_finite() { c } else { f32::NEG_INFINITY }
}

/// Descending total-order comparison of two confidences.
fn conf_cmp_desc(a: f32, b: f32) -> std::cmp::Ordering {
    conf_ord_key(b).total_cmp(&conf_ord_key(a))
}

fn dedupe_matches(mut matches: Vec<TextMatch>) -> Vec<TextMatch> {
    // Group by text; within each group the highest-confidence match comes first,
    // and dedup_by keeps the first of consecutive duplicates.
    matches.sort_by(|a, b| {
        a.text
            .cmp(&b.text)
            .then(conf_cmp_desc(a.confidence, b.confidence))
            .then((b.end - b.start).cmp(&(a.end - a.start)))
    });
    matches.dedup_by(|a, b| a.text == b.text);
    matches
}

/// Detect regions on one page from a [`PageText`] (spaced + raw detect, then map).
pub fn detect_page_regions(page: &PageText, opts: &DetectOptions) -> (Vec<Region>, Vec<TextMatch>) {
    let (spaced, _) = crate::geometry::spaced_text(page);
    // Prefer spaced text (line breaks) so sticky concatenation does not corrupt emails.
    // Also run on raw for codes that lose internal spaces incorrectly.
    let mut matches = detect(&spaced, opts);
    matches.extend(detect(&page.text, opts));
    matches = dedupe_matches(matches);
    map_matches(page, &matches)
}

/// Map every search text on one page against a precomputed spaced structure,
/// accumulating per-text region counts so the caller can fail closed when an
/// explicitly requested string maps to nothing anywhere in the document.
fn search_page_regions(
    page: &PageText,
    spaced: &str,
    map: &[Option<usize>],
    texts: &[String],
    counts: &mut std::collections::HashMap<String, usize>,
    regions: &mut Vec<Region>,
) {
    for text in texts {
        let found = regions_for_search_text_in(page, spaced, map, text);
        *counts.entry(text.clone()).or_insert(0) += found.len();
        regions.extend(found);
    }
}

/// Refuse to export when an explicitly requested search string maps to zero
/// regions anywhere in the document: unlike detector hits, search strings are
/// explicit commands, and silently dropping one would certify an unredacted
/// secret (mirrors `require_mapped` for detector hits).
fn require_search_texts_mapped(
    search_texts: &[String],
    counts: &std::collections::HashMap<String, usize>,
) -> Result<()> {
    for text in search_texts {
        if counts.get(text).copied().unwrap_or(0) == 0 {
            return Err(RedactError::SearchTextNotFound { text: text.clone() });
        }
    }
    Ok(())
}

/// Intersection-over-union of two axis-aligned rects. 0 if no overlap.
pub fn rect_iou(a: &Rect, b: &Rect) -> f32 {
    let ix1 = a.x.max(b.x);
    let iy1 = a.y.max(b.y);
    let ix2 = (a.x + a.w).min(b.x + b.w);
    let iy2 = (a.y + a.h).min(b.y + b.h);
    let iw = (ix2 - ix1).max(0.0);
    let ih = (iy2 - iy1).max(0.0);
    let inter = iw * ih;
    if inter <= 0.0 {
        return 0.0;
    }
    let area_a = (a.w * a.h).max(0.0);
    let area_b = (b.w * b.h).max(0.0);
    let union = area_a + area_b - inter;
    if union <= 0.0 {
        return 0.0;
    }
    inter / union
}

/// Loose normalize for comparing region source texts (alphanumeric lowercased).
fn normalize_loose(s: &str) -> String {
    s.chars()
        .filter(|c| c.is_alphanumeric())
        .flat_map(|c| c.to_lowercase())
        .collect()
}

fn texts_similar(a: &str, b: &str) -> bool {
    let na = normalize_loose(a);
    let nb = normalize_loose(b);
    if na.is_empty() || nb.is_empty() {
        return false;
    }
    na == nb || na.contains(&nb) || nb.contains(&na)
}

fn region_area(r: &Region) -> f32 {
    r.rects
        .iter()
        .map(|rect| rect.w.max(0.0) * rect.h.max(0.0))
        .sum()
}

/// Area key for ordering: non-finite (NaN dimensions) maps to 0 so the
/// comparator stays a total order (C10-m3).
fn area_ord_key(r: &Region) -> f32 {
    let a = region_area(r);
    if a.is_finite() { a } else { 0.0 }
}

/// Descending total-order comparison of two region areas.
fn area_cmp_desc(a: &Region, b: &Region) -> std::cmp::Ordering {
    area_ord_key(b).total_cmp(&area_ord_key(a))
}

/// Whether every rect in `inner` lies inside some rect of `outer`.
///
/// A small tolerance absorbs OCR rounding and `pixel_rect_to_page` scaling
/// slivers; apply pads every rect by ≥1.5 pt before painting, so a sub-tolerance
/// protrusion is still covered by the pad (C10-M2).
fn rect_sets_contain(outer: &[Rect], inner: &[Rect]) -> bool {
    if outer.is_empty() || inner.is_empty() {
        return false;
    }
    const TOL: f32 = 0.5;
    inner.iter().all(|ri| {
        outer.iter().any(|ro| {
            ri.x >= ro.x - TOL
                && ri.y >= ro.y - TOL
                && ri.x + ri.w <= ro.x + ro.w + TOL
                && ri.y + ri.h <= ro.y + ro.h + TOL
        })
    })
}

/// Whether two rects overlap with positive area in both axes.
fn rects_overlap(a: &Rect, b: &Rect) -> bool {
    let ix = (a.x + a.w).min(b.x + b.w) - a.x.max(b.x);
    let iy = (a.y + a.h).min(b.y + b.h) - a.y.max(b.y);
    ix > 0.0 && iy > 0.0
}

/// Whether any rect pair overlaps (positive-area intersection in both axes).
fn rect_sets_overlap(a: &[Rect], b: &[Rect]) -> bool {
    a.iter().any(|ra| b.iter().any(|rb| rects_overlap(ra, rb)))
}

/// Prefer native geometry when overlapping; else higher confidence / larger area.
#[derive(Clone, Copy, PartialEq, Eq)]
enum RegionOrigin {
    Native,
    Ocr,
}

/// Union two region lists (typically native + OCR detect), deduping overlaps.
///
/// Policy (v2, C10-M2):
/// - Prefer higher confidence, then larger area, then native over OCR.
/// - A candidate is dropped **only** when a kept region's rect set fully
///   contains its rects (and the texts are similar) — an IoU threshold alone
///   could discard a fully-covering native region in favor of a partially-
///   covering higher-confidence OCR region, leaving a sliver of secret ink
///   unpainted.
/// - Partial overlaps are merged by unioning the rect sets, so coverage can
///   never shrink; native rects always survive an OCR merge regardless of
///   confidence (native boxes are glyph-accurate).
pub fn union_regions(native: Vec<Region>, ocr: Vec<Region>) -> Vec<Region> {
    let mut tagged: Vec<(Region, RegionOrigin)> = native
        .into_iter()
        .map(|r| (r, RegionOrigin::Native))
        .chain(ocr.into_iter().map(|r| (r, RegionOrigin::Ocr)))
        .collect();

    // Total order (C10-m3): confidence desc, area desc, native over OCR.
    tagged.sort_by(|a, b| {
        conf_cmp_desc(a.0.confidence, b.0.confidence)
            .then(area_cmp_desc(&a.0, &b.0))
            .then_with(|| match (a.1, b.1) {
                (RegionOrigin::Native, RegionOrigin::Ocr) => std::cmp::Ordering::Less,
                (RegionOrigin::Ocr, RegionOrigin::Native) => std::cmp::Ordering::Greater,
                _ => std::cmp::Ordering::Equal,
            })
    });

    #[derive(Clone, Copy)]
    enum MergeAction {
        /// Kept region fully contains the candidate: drop it.
        Drop,
        /// The candidate fully contains the kept region: replace the kept
        /// region's rects with the candidate's (covers strictly more ink).
        ReplaceWith(usize),
        /// Partial overlap: union the rect sets so no ink is lost.
        MergeInto(usize),
        /// No overlap: keep as a new region.
        Keep,
    }

    let mut kept: Vec<(Region, RegionOrigin)> = Vec::new();
    for (cand, origin) in tagged {
        let mut action = MergeAction::Keep;
        for (idx, (k, _)) in kept.iter().enumerate() {
            if k.page_index != cand.page_index || !texts_similar(&k.source_text, &cand.source_text)
            {
                continue;
            }
            if rect_sets_contain(&k.rects, &cand.rects) {
                // Fully covered — dropping cannot shrink coverage.
                action = MergeAction::Drop;
                break;
            }
            if rect_sets_overlap(&k.rects, &cand.rects) {
                if rect_sets_contain(&cand.rects, &k.rects) {
                    // The candidate covers the kept region entirely: prefer the
                    // candidate's rects — a native region covering its OCR twin
                    // wins regardless of confidence (C10-M2).
                    action = MergeAction::ReplaceWith(idx);
                } else {
                    // Partial overlap — union the rect sets so no ink is lost.
                    action = MergeAction::MergeInto(idx);
                }
                break;
            }
        }
        match action {
            MergeAction::Drop => {}
            MergeAction::ReplaceWith(idx) => {
                let (k, k_origin) = &mut kept[idx];
                k.rects = cand.rects;
                *k_origin = origin;
            }
            MergeAction::MergeInto(idx) => {
                let (k, k_origin) = &mut kept[idx];
                k.rects.extend(cand.rects);
                // Prefer native geometry whenever it overlaps OCR, regardless
                // of confidence.
                if origin == RegionOrigin::Native && *k_origin == RegionOrigin::Ocr {
                    *k_origin = RegionOrigin::Native;
                }
            }
            MergeAction::Keep => kept.push((cand, origin)),
        }

        // The merge loop stops at the first overlapping kept region, but the
        // candidate can also fully contain *other* kept regions (e.g. one long
        // OCR box spanning two native boxes). Once `idx` absorbed the
        // candidate's rects those regions are fully contained by the modified
        // rect set — leaving them in would paint the same ink twice and list
        // the same occurrence twice in the certificate, so drop them (same
        // text-similar + geometric criterion as the Drop action).
        if let MergeAction::ReplaceWith(idx) | MergeAction::MergeInto(idx) = action {
            let merged_rects = kept[idx].0.rects.clone();
            let merged_text = kept[idx].0.source_text.clone();
            let redundant: Vec<usize> = kept
                .iter()
                .enumerate()
                .filter(|(j, (k, _))| {
                    *j != idx
                        && k.page_index == kept[idx].0.page_index
                        && texts_similar(&merged_text, &k.source_text)
                        && rect_sets_contain(&merged_rects, &k.rects)
                })
                .map(|(j, _)| j)
                .collect();
            for j in redundant.into_iter().rev() {
                kept.remove(j);
            }
        }
    }
    kept.into_iter().map(|(r, _)| r).collect()
}

/// Detect PII regions across all pages (mapped to geometry).
///
/// Detector hits that fire but cannot be mapped to glyph geometry are
/// *surfaced*, not dropped: they come back in [`DetectDocumentResult::unmapped`]
/// (as `(page_index, match)` pairs) so the findings file can list them as
/// excluded items and the human reviewer learns a secret was found but could
/// not be painted (C10-M1).
pub fn detect_document(input: &[u8], opts: &DetectOptions) -> Result<DetectDocumentResult> {
    #[cfg(feature = "ocr")]
    {
        let mut load = ocr_backend_loader_detect(opts);
        detect_document_with(input, opts, &mut load)
    }
    #[cfg(not(feature = "ocr"))]
    {
        detect_document_no_ocr(input, opts)
    }
}

/// [`detect_document`] with an injected OCR backend loader — test seam
/// (C13-m3): lets integration tests drive the On/Auto/Force/retry paths with
/// a stub backend, no models required.
#[cfg(feature = "ocr")]
pub fn detect_document_with(
    input: &[u8],
    opts: &DetectOptions,
    load: &mut dyn FnMut() -> Result<Box<dyn crate::ocr::OcrBackend>>,
) -> Result<DetectDocumentResult> {
    let doc = HayroDocument::open(input.to_vec())?;
    let mut all_regions = Vec::new();
    let mut unmapped_total: Vec<(usize, TextMatch)> = Vec::new();
    let mut total_text_chars = 0usize;
    let mut any_ocr_attempted = false;
    let page_count = doc.page_count();

    let mut backend: Option<Box<dyn crate::ocr::OcrBackend>> = None;

    use crate::ocr::{OcrMode, ocr_page_from_doc_with_opts};

    for i in 0..page_count {
        let native = doc.page_text(i)?;
        let native_chars = native.text.chars().count();

        match opts.ocr.mode {
            OcrMode::Off => {
                total_text_chars += native_chars;
                let (regions, unmapped) = detect_page_regions(&native, opts);
                all_regions.extend(regions);
                unmapped_total.extend(unmapped.into_iter().map(|m| (i, m)));
                tracing::info!(page = i, source = "native", chars = native_chars);
            }
            OcrMode::Force => {
                any_ocr_attempted = true;
                let b = ensure_ocr_backend(&mut backend, load)?;
                let ocr_page = ocr_page_from_doc_with_opts(&doc, i, b, &opts.ocr)?;
                let chars = ocr_page.text.chars().count();
                total_text_chars += chars;
                let (regions, unmapped) = detect_page_regions(&ocr_page, opts);
                all_regions.extend(regions);
                unmapped_total.extend(unmapped.into_iter().map(|m| (i, m)));
                tracing::info!(page = i, source = "ocr", chars);
            }
            OcrMode::Auto => {
                // Short text OR poor text-layer quality → OCR (VeriRedact-style).
                // The decision carries the assessment, so the scorer runs
                // exactly once per page (C11-n2).
                let decision = opts.ocr.page_ocr_decision(&native.text);
                if decision.needs_ocr {
                    any_ocr_attempted = true;
                    // C13-M1: Auto never discards the native layer — OCR
                    // detections are unioned with native detections exactly
                    // like On mode, so a secret the OCR pass misrecognizes
                    // cannot silently vanish from the output.
                    let (native_regions, native_unmapped) = detect_page_regions(&native, opts);
                    let b = ensure_ocr_backend(&mut backend, load)?;
                    let ocr_page = ocr_page_from_doc_with_opts(&doc, i, b, &opts.ocr)?;
                    let ocr_chars = ocr_page.text.chars().count();
                    total_text_chars += native_chars.max(ocr_chars);
                    let (ocr_regions, ocr_unmapped) = detect_page_regions(&ocr_page, opts);
                    all_regions.extend(union_regions(native_regions, ocr_regions));
                    unmapped_total.extend(native_unmapped.into_iter().map(|m| (i, m)));
                    unmapped_total.extend(ocr_unmapped.into_iter().map(|m| (i, m)));
                    let quality = decision.quality.as_ref();
                    tracing::info!(
                        page = i,
                        source = "hybrid",
                        chars = ocr_chars,
                        native_chars,
                        quality = ?quality.map(|q| q.score),
                        reasons = ?quality.map(|q| &q.reasons),
                        "auto OCR (short or poor text layer), native text kept"
                    );
                } else {
                    total_text_chars += native_chars;
                    let (regions, unmapped) = detect_page_regions(&native, opts);
                    all_regions.extend(regions);
                    unmapped_total.extend(unmapped.into_iter().map(|m| (i, m)));
                    tracing::info!(page = i, source = "native", chars = native_chars);
                }
            }
            OcrMode::On => {
                any_ocr_attempted = true;
                let (native_regions, native_unmapped) = detect_page_regions(&native, opts);
                let b = ensure_ocr_backend(&mut backend, load)?;
                let ocr_page = ocr_page_from_doc_with_opts(&doc, i, b, &opts.ocr)?;
                let ocr_chars = ocr_page.text.chars().count();
                total_text_chars += native_chars.max(ocr_chars);
                let (ocr_regions, ocr_unmapped) = detect_page_regions(&ocr_page, opts);
                all_regions.extend(union_regions(native_regions, ocr_regions));
                unmapped_total.extend(native_unmapped.into_iter().map(|m| (i, m)));
                unmapped_total.extend(ocr_unmapped.into_iter().map(|m| (i, m)));
                tracing::info!(page = i, source = "hybrid", native_chars, ocr_chars);
            }
        }
    }

    // Warn only when there is still no text and we either never tried OCR or mode is Off.
    if page_count > 0 && total_text_chars == 0 {
        use crate::ocr::OcrMode;
        if matches!(opts.ocr.mode, OcrMode::Off) {
            tracing::warn!(
                pages = page_count,
                "no extractable text layer on any page; auto-detect needs a text layer or OCR. \
                 Pass --ocr auto (requires a build with --features ocr and models via ocr-setup)."
            );
        } else if any_ocr_attempted {
            tracing::warn!(
                pages = page_count,
                "no text found after OCR; detect will return zero findings"
            );
        }
    }

    // C10-M1: unmapped hits are never silently dropped — surface them to the
    // caller (the findings file lists them as excluded items) and warn loudly.
    if !unmapped_total.is_empty() {
        tracing::warn!(
            count = unmapped_total.len(),
            "{} detector hit(s) could not be mapped to page geometry (text layer \
             without usable glyph spans); they are surfaced in the findings as \
             excluded (included: false) items and will NOT be redacted",
            unmapped_total.len()
        );
    }
    Ok(DetectDocumentResult {
        regions: all_regions,
        unmapped: unmapped_total,
        text_char_count: total_text_chars,
    })
}

/// Non-OCR detect-only pass (build without `--features ocr`).
#[cfg(not(feature = "ocr"))]
fn detect_document_no_ocr(input: &[u8], opts: &DetectOptions) -> Result<DetectDocumentResult> {
    let doc = HayroDocument::open(input.to_vec())?;
    let mut all_regions = Vec::new();
    let mut unmapped_total: Vec<(usize, TextMatch)> = Vec::new();
    let mut total_text_chars = 0usize;
    let page_count = doc.page_count();

    for i in 0..page_count {
        let native = doc.page_text(i)?;
        let native_chars = native.text.chars().count();
        total_text_chars += native_chars;
        let (regions, unmapped) = detect_page_regions(&native, opts);
        all_regions.extend(regions);
        unmapped_total.extend(unmapped.into_iter().map(|m| (i, m)));
    }

    if page_count > 0 && total_text_chars == 0 {
        tracing::warn!(
            pages = page_count,
            "no extractable text layer on any page; auto-detect needs a text layer (or OCR). \
             Image-only / scanned PDFs will produce zero findings until OCR is enabled \
             (rebuild with --features ocr)."
        );
    }

    // C10-M1: unmapped hits are never silently dropped — surface them to the
    // caller (the findings file lists them as excluded items) and warn loudly.
    if !unmapped_total.is_empty() {
        tracing::warn!(
            count = unmapped_total.len(),
            "{} detector hit(s) could not be mapped to page geometry (text layer \
             without usable glyph spans); they are surfaced in the findings as \
             excluded (included: false) items and will NOT be redacted",
            unmapped_total.len()
        );
    }
    Ok(DetectDocumentResult {
        regions: all_regions,
        unmapped: unmapped_total,
        text_char_count: total_text_chars,
    })
}

/// How much extractable text the PDF has (chars across all pages).
///
/// Zero usually means image-only / scanned pages (Medium/Hard JSL corpus, camera scans).
pub fn text_layer_char_count(input: &[u8]) -> Result<usize> {
    let doc = HayroDocument::open(input.to_vec())?;
    let mut n = 0usize;
    for i in 0..doc.page_count() {
        n += doc.page_text(i)?.text.chars().count();
    }
    Ok(n)
}

/// Build the region list a [`RunOptions`] implies — per-page detect (if
/// enabled) plus search texts and manual rects — without applying anything.
///
/// Returns `(regions, text_sources)`. Unmapped detector hits are an error
/// (`require_mapped`), matching the "refuse unsafe export" invariant.
pub fn regions_for_options(input: &[u8], opts: &RunOptions) -> Result<(Vec<Region>, TextSources)> {
    let doc = HayroDocument::open(input.to_vec())?;
    #[cfg(feature = "ocr")]
    {
        let mut load = ocr_backend_loader(opts);
        regions_for_options_in(&doc, opts, &mut load)
    }
    #[cfg(not(feature = "ocr"))]
    {
        regions_for_options_in(&doc, opts)
    }
}

/// [`regions_for_options`] with an injected OCR backend loader — test seam
/// (C13-m3): lets integration tests drive the On/Auto/Force/retry paths with
/// a stub backend, no models required.
#[cfg(feature = "ocr")]
pub fn regions_for_options_with(
    input: &[u8],
    opts: &RunOptions,
    load: &mut dyn FnMut() -> Result<Box<dyn crate::ocr::OcrBackend>>,
) -> Result<(Vec<Region>, TextSources)> {
    let doc = HayroDocument::open(input.to_vec())?;
    regions_for_options_in(&doc, opts, load)
}

/// Keep only unmapped detector hits whose normalized text is NOT among the
/// texts the other layer already mapped to geometry.
///
/// Hybrid (On/Auto) mode runs the detector against both the native and OCR
/// text layers; a hit one layer cannot map to glyph spans is not a run
/// failure when the other layer mapped and painted the same secret — one
/// broken text layer must not abort the whole run for a secret that IS
/// redacted (C10-M1 relaxation in `regions_for_options_in`).
#[cfg(feature = "ocr")]
fn unmapped_not_already_mapped(
    unmapped: Vec<TextMatch>,
    mapped_texts: &std::collections::HashSet<String>,
) -> Vec<TextMatch> {
    unmapped
        .into_iter()
        .filter(|m| !mapped_texts.contains(&normalize_loose(&m.text)))
        .collect()
}

/// [`regions_for_options`] against an already-open document, so a pipeline run
/// parses the input once instead of once per stage (C10-m1).
///
/// With `feature = "ocr"`, `load` lazily materializes the OCR backend; the
/// production loader wraps [`crate::ocr::OcrsBackend`], tests inject a stub.
fn regions_for_options_in(
    doc: &HayroDocument,
    opts: &RunOptions,
    #[cfg(feature = "ocr")] load: &mut dyn FnMut() -> Result<Box<dyn crate::ocr::OcrBackend>>,
) -> Result<(Vec<Region>, TextSources)> {
    let input_pages = doc.page_count();
    let mut regions = Vec::new();
    let mut unmapped_all = Vec::new();
    let mut text_sources: Vec<(usize, &'static str)> = Vec::new();
    // Per-search-text region counts across all pages, for the fail-closed
    // missing-text check (mirrors `require_mapped` for detector hits).
    let mut search_counts: std::collections::HashMap<String, usize> =
        std::collections::HashMap::new();

    #[cfg(feature = "ocr")]
    let mut backend: Option<Box<dyn crate::ocr::OcrBackend>> = None;
    // Pages on which OCR must run for detect/search (On: every page; Auto:
    // the per-page decision, computed exactly once here — C11-n2).
    #[cfg(feature = "ocr")]
    let mut ocr_for_page: Vec<bool> = Vec::with_capacity(input_pages);

    // Pre-acquire per-page PageTexts used for detect and search (shared).
    // Without OCR feature this is always native; with OCR it follows mode.
    let mut page_texts: Vec<(PageText, &'static str)> = Vec::with_capacity(input_pages);

    for i in 0..input_pages {
        let native = doc.page_text(i)?;

        #[cfg(not(feature = "ocr"))]
        {
            page_texts.push((native, "native"));
        }

        #[cfg(feature = "ocr")]
        {
            use crate::ocr::{OcrMode, ocr_page_from_doc_with_opts};

            match opts.detect.ocr.mode {
                OcrMode::Off => {
                    ocr_for_page.push(false);
                    page_texts.push((native, "native"));
                }
                OcrMode::Force => {
                    // OCR-only text; runs eagerly because Force is the whole
                    // "ignore native" contract, independent of run_detector.
                    let b = ensure_ocr_backend(&mut backend, load)?;
                    let ocr_page = ocr_page_from_doc_with_opts(doc, i, b, &opts.detect.ocr)?;
                    ocr_for_page.push(false);
                    page_texts.push((ocr_page, "ocr"));
                }
                OcrMode::Auto => {
                    // Decide once per page (C11-n2). OCR itself runs lazily in
                    // the detect/search stages so the native layer stays
                    // available for the union (C13-M1).
                    let needs_ocr = opts.detect.ocr.page_ocr_decision(&native.text).needs_ocr;
                    ocr_for_page.push(needs_ocr);
                    page_texts.push((native, "native"));
                }
                OcrMode::On => {
                    // Keep native for dual detect; OCR page stored only for
                    // hybrid detect. Label "native" until an OCR pass actually
                    // runs (C10-m4): with run_detector=false and empty
                    // search_texts, OCR never executes and every page stays
                    // "native" — not "hybrid".
                    ocr_for_page.push(true);
                    page_texts.push((native, "native"));
                }
            }
            tracing::info!(page = i, source = page_texts[i].1);
        }
    }

    text_sources.extend(page_texts.iter().enumerate().map(|(i, (_, src))| (i, *src)));

    if opts.run_detector {
        #[cfg(feature = "ocr")]
        {
            use crate::ocr::{OcrMode, ocr_page_from_doc_with_opts};

            if matches!(opts.detect.ocr.mode, OcrMode::On | OcrMode::Auto) {
                // Hybrid-capable modes: native detections are never dropped
                // (C13-M1). On OCRs every page; Auto only pages that passed
                // the per-page decision.
                let always_ocr = matches!(opts.detect.ocr.mode, OcrMode::On);
                for (i, (native, _)) in page_texts.iter().enumerate() {
                    let (native_regions, native_unmapped) =
                        detect_page_regions(native, &opts.detect);
                    if always_ocr || ocr_for_page[i] {
                        let b = ensure_ocr_backend(&mut backend, load)?;
                        let ocr_page = ocr_page_from_doc_with_opts(doc, i, b, &opts.detect.ocr)?;
                        let (ocr_regions, ocr_unmapped) =
                            detect_page_regions(&ocr_page, &opts.detect);
                        // C10-M1 hybrid relaxation: a hit one layer cannot map
                        // to glyph spans is not a run failure when the other
                        // layer mapped and painted the same secret — filter
                        // each layer's unmapped hits against the other layer's
                        // mapped source texts.
                        let native_mapped: std::collections::HashSet<String> = native_regions
                            .iter()
                            .map(|r| normalize_loose(&r.source_text))
                            .collect();
                        let ocr_mapped: std::collections::HashSet<String> = ocr_regions
                            .iter()
                            .map(|r| normalize_loose(&r.source_text))
                            .collect();
                        unmapped_all
                            .extend(unmapped_not_already_mapped(native_unmapped, &ocr_mapped));
                        unmapped_all
                            .extend(unmapped_not_already_mapped(ocr_unmapped, &native_mapped));
                        regions.extend(union_regions(native_regions, ocr_regions));
                        // OCR actually ran on this page → acquisition is hybrid.
                        text_sources[i] = (i, "hybrid");
                        // Search also on OCR text. Spaced text is computed
                        // once per page and shared across search strings. The
                        // two layers' search results are unioned like detect
                        // regions so one physical occurrence found by both
                        // layers becomes a single region (painted once, listed
                        // once) instead of two duplicates.
                        let (native_spaced, native_map) = crate::geometry::spaced_text(native);
                        let mut native_search = Vec::new();
                        search_page_regions(
                            native,
                            &native_spaced,
                            &native_map,
                            &opts.search_texts,
                            &mut search_counts,
                            &mut native_search,
                        );
                        let (ocr_spaced, ocr_map) = crate::geometry::spaced_text(&ocr_page);
                        let mut ocr_search = Vec::new();
                        search_page_regions(
                            &ocr_page,
                            &ocr_spaced,
                            &ocr_map,
                            &opts.search_texts,
                            &mut search_counts,
                            &mut ocr_search,
                        );
                        regions.extend(union_regions(native_search, ocr_search));
                    } else {
                        regions.extend(native_regions);
                        unmapped_all.extend(native_unmapped);
                        let (spaced, map) = crate::geometry::spaced_text(native);
                        search_page_regions(
                            native,
                            &spaced,
                            &map,
                            &opts.search_texts,
                            &mut search_counts,
                            &mut regions,
                        );
                    }
                }
            } else {
                for (page, _) in &page_texts {
                    let (mapped, unmapped) = detect_page_regions(page, &opts.detect);
                    regions.extend(mapped);
                    unmapped_all.extend(unmapped);
                }
                for (page, _) in &page_texts {
                    let (spaced, map) = crate::geometry::spaced_text(page);
                    search_page_regions(
                        page,
                        &spaced,
                        &map,
                        &opts.search_texts,
                        &mut search_counts,
                        &mut regions,
                    );
                }
            }
        }

        #[cfg(not(feature = "ocr"))]
        {
            for (page, _) in &page_texts {
                let (mapped, unmapped) = detect_page_regions(page, &opts.detect);
                regions.extend(mapped);
                unmapped_all.extend(unmapped);
            }
            for (page, _) in &page_texts {
                let (spaced, map) = crate::geometry::spaced_text(page);
                search_page_regions(
                    page,
                    &spaced,
                    &map,
                    &opts.search_texts,
                    &mut search_counts,
                    &mut regions,
                );
            }
        }
    } else {
        // Search only (no detector).
        #[cfg(feature = "ocr")]
        {
            use crate::ocr::{OcrMode, ocr_page_from_doc_with_opts};

            if matches!(opts.detect.ocr.mode, OcrMode::On | OcrMode::Auto) {
                // Hybrid-capable modes: search native and, on pages where OCR
                // runs, OCR text too (C13-M1 keeps the native layer live).
                let always_ocr = matches!(opts.detect.ocr.mode, OcrMode::On);
                for (i, (native, _)) in page_texts.iter().enumerate() {
                    let (native_spaced, native_map) = crate::geometry::spaced_text(native);
                    let mut native_search = Vec::new();
                    search_page_regions(
                        native,
                        &native_spaced,
                        &native_map,
                        &opts.search_texts,
                        &mut search_counts,
                        &mut native_search,
                    );
                    // OCR runs only when something will actually use it
                    // (empty search list → nothing to do; label stays native,
                    // C10-m4).
                    if (always_ocr || ocr_for_page[i]) && !opts.search_texts.is_empty() {
                        let b = ensure_ocr_backend(&mut backend, load)?;
                        let ocr_page = ocr_page_from_doc_with_opts(doc, i, b, &opts.detect.ocr)?;
                        let (ocr_spaced, ocr_map) = crate::geometry::spaced_text(&ocr_page);
                        let mut ocr_search = Vec::new();
                        search_page_regions(
                            &ocr_page,
                            &ocr_spaced,
                            &ocr_map,
                            &opts.search_texts,
                            &mut search_counts,
                            &mut ocr_search,
                        );
                        // OCR actually ran on this page → acquisition is hybrid.
                        text_sources[i] = (i, "hybrid");
                        // Union the two layers' search regions (same dedupe as
                        // detect) so one occurrence found by both layers is not
                        // painted twice / listed twice in the certificate.
                        regions.extend(union_regions(native_search, ocr_search));
                    } else {
                        regions.extend(native_search);
                    }
                }
            } else {
                for (page, _) in &page_texts {
                    let (spaced, map) = crate::geometry::spaced_text(page);
                    search_page_regions(
                        page,
                        &spaced,
                        &map,
                        &opts.search_texts,
                        &mut search_counts,
                        &mut regions,
                    );
                }
            }
        }
        #[cfg(not(feature = "ocr"))]
        {
            for (page, _) in &page_texts {
                let (spaced, map) = crate::geometry::spaced_text(page);
                search_page_regions(
                    page,
                    &spaced,
                    &map,
                    &opts.search_texts,
                    &mut search_counts,
                    &mut regions,
                );
            }
        }
    }

    for (page_index, rect, label) in &opts.manual_rects {
        if !rect.is_valid() {
            // n2: manual rects are CLI input, not a findings file — use
            // `InvalidInput` (exit 2) so the CLI error doesn't claim the
            // findings JSON was invalid (C10-F7).
            return Err(RedactError::InvalidInput(format!(
                "manual rect for page {page_index}: invalid rect {rect:?} \
                 (x/y/w/h must be finite, width and height > 0, \
                 magnitudes ≤ {})",
                crate::types::MAX_RECT_MAGNITUDE
            )));
        }
        regions.push(crate::geometry::manual_region(
            *page_index,
            *rect,
            label.clone(),
        ));
    }

    require_search_texts_mapped(&opts.search_texts, &search_counts)?;
    require_mapped(&unmapped_all)?;
    Ok((regions, text_sources))
}

/// Full pipeline.
pub fn run_pipeline(input: &[u8], opts: &RunOptions) -> Result<PipelineResult> {
    let doc = HayroDocument::open(input.to_vec())?;
    let input_pages = doc.page_count();
    let (regions, text_sources) = {
        #[cfg(feature = "ocr")]
        {
            let mut load = ocr_backend_loader(opts);
            regions_for_options_in(&doc, opts, &mut load)?
        }
        #[cfg(not(feature = "ocr"))]
        {
            regions_for_options_in(&doc, opts)?
        }
    };

    // C10-m2: redacting nothing must fail loudly (like `redact` on an empty
    // findings file) instead of silently rebuilding the document as image-only
    // pages — that destroys the text layer of an untouched document and still
    // issues a certificate.
    if regions.iter().filter(|r| r.included).count() == 0 {
        return Err(RedactError::NoIncludedRegions);
    }

    let output = apply_regions_in(&doc, &regions, &opts.apply)?;
    finalize(input, input_pages, output, regions, text_sources)
}

/// Apply precomputed regions (from findings file) with verify + cert.
pub fn redact_with_regions(
    input: &[u8],
    regions: &[Region],
    apply: &ApplyOptions,
) -> Result<PipelineResult> {
    let doc = HayroDocument::open(input.to_vec())?;
    let input_pages = doc.page_count();
    // Same zero-included guard as [`run_pipeline`] (C10-m2): an all-excluded
    // region set must not trigger a text-layer-destroying image rebuild.
    if regions.iter().filter(|r| r.included).count() == 0 {
        return Err(RedactError::NoIncludedRegions);
    }
    // Reuse the already-open document (C10-2 fix) — avoids a second parse.
    let output = apply_regions_in(&doc, regions, apply)?;
    finalize(input, input_pages, output, regions.to_vec(), Vec::new())
}

/// Apply precomputed regions (e.g. from a findings file) plus the extra
/// search/manual regions implied by `extra`, in a single document open, then
/// verify and certify (C12-m2).
///
/// The CLI's findings+`--text`/`--rect` merge path used to map the extras via
/// [`regions_for_options`] (one open) and then re-open the input inside
/// [`redact_with_regions`] (a second open, plus a third in `apply_regions`).
/// This entry point shares the open document between mapping and apply, so the
/// merge path parses the input exactly once — the same "parse once" promise
/// as [`run_pipeline`] (C10-m1).
///
/// `extra` supplies search texts and manual rects; detection is not re-run
/// (the caller already has precomputed regions — findings or a prior detect).
pub fn redact_with_regions_and_options(
    input: &[u8],
    regions: &[Region],
    extra: &RunOptions,
    apply: &ApplyOptions,
) -> Result<PipelineResult> {
    let doc = HayroDocument::open(input.to_vec())?;
    let input_pages = doc.page_count();
    // Detection is NOT re-run here: the caller already supplies precomputed
    // regions (findings file or a prior detect), so force `run_detector` off
    // even when a library caller passes run-style `extra` options. Re-running
    // the detector would duplicate the caller's detection regions and can
    // spuriously fail the run on unmapped hits (C12-m2).
    let mut extra = extra.clone();
    extra.run_detector = false;
    let (extra_regions, _) = {
        #[cfg(feature = "ocr")]
        {
            let mut load = ocr_backend_loader(&extra);
            regions_for_options_in(&doc, &extra, &mut load)?
        }
        #[cfg(not(feature = "ocr"))]
        {
            regions_for_options_in(&doc, &extra)?
        }
    };
    let mut merged = regions.to_vec();
    merged.extend(extra_regions);
    // Same zero-included guard as [`run_pipeline`] / [`redact_with_regions`]
    // (C10-m2): an all-excluded region set must not trigger a
    // text-layer-destroying image rebuild.
    if merged.iter().filter(|r| r.included).count() == 0 {
        return Err(RedactError::NoIncludedRegions);
    }
    let output = apply_regions_in(&doc, &merged, apply)?;
    finalize(input, input_pages, output, merged, Vec::new())
}

/// Shared verify → certify → [`PipelineResult`] construction for both pipeline
/// entry points (C10-m1). A failed verification is an error: no certificate is
/// ever emitted for an unverified export.
fn finalize(
    input: &[u8],
    input_pages: usize,
    output: Vec<u8>,
    regions: Vec<Region>,
    text_sources: TextSources,
) -> Result<PipelineResult> {
    let (verification, output_pages) = verify_output_with_page_count(&output, &regions)?;
    finalize_verified(
        input,
        input_pages,
        output,
        regions,
        text_sources,
        verification,
        output_pages,
    )
}

/// Certify an already-verified export — the single choke point that turns a
/// failed verification into an error before a certificate can be constructed
/// (the verified-OK invariant; `build_certificate` double-checks `passed`).
fn finalize_verified(
    input: &[u8],
    input_pages: usize,
    output: Vec<u8>,
    regions: Vec<Region>,
    text_sources: TextSources,
    verification: VerificationResult,
    output_pages: usize,
) -> Result<PipelineResult> {
    if !verification.passed {
        let detail = verification
            .checks
            .iter()
            .filter(|c| !c.passed)
            .map(|c| format!("{}: {}", c.id, c.detail))
            .collect::<Vec<_>>()
            .join("; ");
        return Err(RedactError::VerificationFailed(detail));
    }

    // C10-1: page count came from verify's single parse; no re-open needed.
    let certificate = build_certificate(
        input,
        &output,
        input_pages,
        output_pages,
        &regions,
        verification.clone(),
    )?;

    Ok(PipelineResult {
        output,
        regions,
        verification,
        certificate,
        text_sources,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::Category;

    fn region(page: usize, x: f32, y: f32, w: f32, h: f32, text: &str, conf: f32) -> Region {
        Region {
            page_index: page,
            rects: vec![Rect::new(x, y, w, h)],
            source_text: text.to_string(),
            category: Category::Ssn,
            confidence: conf,
            included: true,
            source: crate::types::MatchSource::Regex,
        }
    }

    #[test]
    fn rect_iou_identical_is_one() {
        let a = Rect::new(0.0, 0.0, 10.0, 10.0);
        assert!((rect_iou(&a, &a) - 1.0).abs() < 1e-5);
    }

    #[test]
    fn rect_iou_no_overlap_is_zero() {
        let a = Rect::new(0.0, 0.0, 10.0, 10.0);
        let b = Rect::new(20.0, 20.0, 5.0, 5.0);
        assert_eq!(rect_iou(&a, &b), 0.0);
    }

    #[test]
    fn rect_iou_partial() {
        let a = Rect::new(0.0, 0.0, 10.0, 10.0);
        let b = Rect::new(5.0, 0.0, 10.0, 10.0);
        // inter=50, union=150 → 1/3
        let iou = rect_iou(&a, &b);
        assert!((iou - 50.0 / 150.0).abs() < 1e-5);
    }

    #[test]
    fn union_regions_dedupes_high_iou_similar_text() {
        let native = vec![region(0, 10.0, 10.0, 40.0, 12.0, "123-45-6789", 0.9)];
        let ocr = vec![region(0, 11.0, 10.0, 40.0, 12.0, "123-45-6789", 0.7)];
        let merged = union_regions(native, ocr);
        assert_eq!(merged.len(), 1);
        assert!((merged[0].confidence - 0.9).abs() < 1e-5);
    }

    #[test]
    fn union_regions_keeps_distant() {
        let native = vec![region(0, 10.0, 10.0, 40.0, 12.0, "123-45-6789", 0.9)];
        let ocr = vec![region(0, 200.0, 200.0, 40.0, 12.0, "987-65-4321", 0.8)];
        let merged = union_regions(native, ocr);
        assert_eq!(merged.len(), 2);
    }

    #[test]
    fn union_regions_prefers_native_on_tie_conf() {
        let native = vec![region(0, 10.0, 10.0, 40.0, 12.0, "alice@ex.com", 0.8)];
        let ocr = vec![region(0, 10.5, 10.0, 40.0, 12.0, "alice@ex.com", 0.8)];
        let merged = union_regions(native.clone(), ocr);
        assert_eq!(merged.len(), 1);
        // Native x=10 preferred
        assert!((merged[0].rects[0].x - 10.0).abs() < 1e-5);
    }

    #[test]
    fn texts_similar_ignores_punctuation() {
        assert!(texts_similar("123-45-6789", "123456789"));
        assert!(!texts_similar("aaa", "bbb"));
    }

    #[test]
    fn union_regions_does_not_shrink_coverage_for_partial_ocr_overlap() {
        // C10-M2: a higher-confidence OCR rect covering only part of the native
        // rect must not displace it — the merged region must still cover the
        // full native span (the old IoU>0.5 dedupe dropped the native rects).
        let native = vec![region(0, 10.0, 10.0, 100.0, 20.0, "123-45-6789", 0.7)];
        let ocr = vec![region(0, 10.0, 10.0, 60.0, 20.0, "123-45-6789", 0.95)];
        let merged = union_regions(native, ocr);
        assert_eq!(merged.len(), 1, "regions: {merged:?}");
        // The full native rect must still be covered by the merged rect set.
        assert!(
            rect_sets_contain(&merged[0].rects, &[Rect::new(10.0, 10.0, 100.0, 20.0)]),
            "merged rects {:#?} must cover the native rect",
            merged[0].rects
        );
        // The kept region keeps the higher confidence.
        assert!((merged[0].confidence - 0.95).abs() < 1e-5);
    }

    #[test]
    fn union_regions_drops_only_when_kept_contains_candidate() {
        // A candidate fully inside a kept region is dropped; the kept rects win.
        let native = vec![region(0, 10.0, 10.0, 100.0, 20.0, "123-45-6789", 0.7)];
        let ocr = vec![region(0, 12.0, 11.0, 40.0, 12.0, "123-45-6789", 0.9)];
        let merged = union_regions(native, ocr);
        assert_eq!(merged.len(), 1, "regions: {merged:?}");
        assert!((merged[0].rects[0].x - 10.0).abs() < 1e-5);
    }

    #[test]
    fn union_regions_keeps_disjoint_same_text_occurrences() {
        // Two separate occurrences of the same text must NOT be merged into one
        // region just because their texts are similar — merging requires overlap.
        let a = vec![region(
            0,
            10.0,
            10.0,
            40.0,
            12.0,
            "jane.doe@example.com",
            0.8,
        )];
        let b = vec![region(
            0,
            200.0,
            200.0,
            40.0,
            12.0,
            "jane.doe@example.com",
            0.9,
        )];
        let merged = union_regions(a, b);
        assert_eq!(merged.len(), 2, "regions: {merged:?}");
    }

    #[test]
    fn union_regions_drops_regions_contained_by_merged_rect_set() {
        // A candidate that overlaps one kept region and fully contains another
        // must not leave the contained region behind as a duplicate: once the
        // first kept region absorbed the candidate's rects, the contained
        // region would be painted twice and listed twice in the certificate.
        let a = region(0, 0.0, 0.0, 50.0, 20.0, "jane.doe@example.com", 0.9);
        let b = region(0, 80.0, 0.0, 20.0, 20.0, "jane.doe@example.com", 0.8);
        let c = region(0, 40.0, 0.0, 60.0, 20.0, "jane.doe@example.com", 0.7);
        let merged = union_regions(vec![a, b], vec![c]);
        assert_eq!(merged.len(), 1, "regions: {merged:?}");
        // The surviving region still covers B's span (no coverage lost).
        assert!(
            rect_sets_contain(&merged[0].rects, &[Rect::new(80.0, 0.0, 20.0, 20.0)]),
            "merged rects {:#?} must still cover B's span",
            merged[0].rects
        );
    }

    #[test]
    fn union_regions_dedupes_search_regions_across_layers() {
        // Search regions produced from the native and OCR layers for the same
        // needle at the same place collapse to a single region — the pipeline
        // unions the two layers' search results like detect regions so one
        // physical occurrence is painted and listed exactly once.
        let native = vec![region(0, 10.0, 10.0, 40.0, 12.0, "alice@ex.com", 1.0)];
        let ocr = vec![region(0, 10.0, 10.0, 40.0, 12.0, "alice@ex.com", 1.0)];
        let merged = union_regions(native, ocr);
        assert_eq!(merged.len(), 1, "regions: {merged:?}");
    }

    #[cfg(feature = "ocr")]
    #[test]
    fn unmapped_hits_already_mapped_by_other_layer_are_not_failures() {
        // C10-M1 hybrid relaxation: a hit one layer cannot map to glyph spans
        // is not a run failure when the other layer mapped and painted the
        // same secret (On mode + one broken text layer must not abort the run).
        // Production callers build this set via `normalize_loose` (see the
        // hybrid detect path above), so the fixture must do the same — a raw
        // "123-45-6789" would never match the normalized hit by design.
        let mapped: std::collections::HashSet<String> =
            [normalize_loose("123-45-6789")].into_iter().collect();
        let hits = vec![
            TextMatch {
                start: 0,
                end: 11,
                text: "123-45-6789".into(),
                category: Category::Ssn,
                confidence: 0.9,
                detector_id: "test".into(),
                source: crate::types::MatchSource::Regex,
            },
            TextMatch {
                start: 20,
                end: 32,
                text: "other-secret".into(),
                category: Category::Ssn,
                confidence: 0.9,
                detector_id: "test".into(),
                source: crate::types::MatchSource::Regex,
            },
        ];
        let filtered = unmapped_not_already_mapped(hits, &mapped);
        assert_eq!(
            filtered.len(),
            1,
            "only the unmapped-in-both-layers hit remains"
        );
        assert_eq!(filtered[0].text, "other-secret");
    }

    #[test]
    fn unmapped_detector_hit_is_surfaced_not_silently_dropped() {
        // C10-M1: a text layer with content but no glyph spans makes the
        // detector fire while the mapper cannot produce geometry; the hit must
        // come back as unmapped (and the run path refuses via `require_mapped`),
        // never silently dropped.
        let page = PageText {
            page_index: 0,
            text: "Contact jane.doe@example.com for SSN 123-45-6789".into(),
            spans: vec![],
            width: 600.0,
            height: 800.0,
        };
        let (regions, unmapped) = detect_page_regions(&page, &DetectOptions::default());
        assert!(regions.is_empty(), "no geometry can be mapped: {regions:?}");
        assert!(
            !unmapped.is_empty(),
            "detector hits on span-less text must be surfaced as unmapped"
        );
    }

    #[test]
    fn failed_verification_never_reaches_certificate() {
        // m5: the pipeline's single choke point must refuse before
        // build_certificate (which double-checks `passed`) can emit anything
        // for a failed verification.
        let failed = VerificationResult {
            passed: false,
            checks: vec![],
        };
        let err = finalize_verified(
            b"input",
            1,
            b"output".to_vec(),
            vec![],
            Vec::new(),
            failed,
            1,
        )
        .expect_err("failed verification must not certify");
        assert!(matches!(err, RedactError::VerificationFailed(_)), "{err:?}");
    }

    fn pii_basic() -> Vec<u8> {
        std::fs::read(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../../testdata/fixtures/synthetic/pii_basic.pdf"
        ))
        .unwrap()
    }

    #[test]
    fn zero_included_regions_is_refused_not_rebuilt() {
        // m2: redacting nothing must fail loudly instead of rebuilding the
        // document as image-only pages (destroying the text layer) and
        // certifying the result.
        let err = run_pipeline(
            &pii_basic(),
            &RunOptions {
                run_detector: false,
                ..Default::default()
            },
        )
        .expect_err("zero-region run must be refused, not image-rebuilt");
        assert!(matches!(err, RedactError::NoIncludedRegions), "{err:?}");
    }

    #[test]
    fn missing_search_text_fails_closed_through_pipeline() {
        // m5: the fail-closed search-text path at the core level — an explicit
        // search string found nowhere must refuse the whole run (the CLI e2e
        // already exercises the same path end-to-end).
        let err = run_pipeline(
            &pii_basic(),
            &RunOptions {
                run_detector: false,
                search_texts: vec!["needle-that-does-not-exist-anywhere".into()],
                ..Default::default()
            },
        )
        .expect_err("missing search text must fail closed");
        assert!(
            matches!(err, RedactError::SearchTextNotFound { .. }),
            "{err:?}"
        );
    }
}
