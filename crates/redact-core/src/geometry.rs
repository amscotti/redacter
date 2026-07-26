//! Map text matches to page rectangles.

use crate::error::{RedactError, Result};
use crate::types::{MatchSource, PageText, Rect, Region, TextMatch};

/// Canonical home is [`crate::types`]; re-exported here so existing
/// `geometry::same_line_rects` paths keep working. This single `pub use`
/// also brings the name into scope for internal use below.
pub use crate::types::same_line_rects;

/// Byte length of `s`'s first character (1 for ASCII / empty). Occurrence
/// loops advance `from = pos + first_char_len(needle)` so a multi-byte UTF-8
/// needle (e.g. "éclair", "日本語") skips a whole character instead of landing
/// on a continuation byte, which would panic on the next `text[from..]` slice.
fn first_char_len(s: &str) -> usize {
    s.chars().next().map_or(1, char::len_utf8)
}

/// Build a search-friendly string with approximate inter-glyph spaces for regex.
/// Returns (spaced_text, map from spaced byte index → original span index).
///
/// Spaces are inserted only when the horizontal gap between glyph *ink edges*
/// is clearly larger than a running median character advance (not using the
/// unreliable glyph width estimate from unit-square transforms). The gap uses
/// the span's pre-refine ink width (`ink_w`): the text device replaces
/// `rect.w` with the origin-to-origin advance to the next glyph, which would
/// make every same-line gap ~0 and swallow all word spaces.
pub fn spaced_text(page: &PageText) -> (String, Vec<Option<usize>>) {
    let mut out = String::new();
    let mut map = Vec::new();
    let mut prev: Option<&crate::types::TextSpan> = None;
    let mut advances = AdvanceWindow::new();

    for (i, span) in page.spans.iter().enumerate() {
        if let Some(p) = prev {
            let same_line = same_line_rects(p.rect, span.rect);
            if !same_line {
                out.push('\n');
                map.push(None);
            } else {
                // Right-edge-to-left-edge gap between consecutive glyphs:
                // the left-edge delta (`span.rect.x - p.rect.x`) overestimates
                // the advance for variable-width glyphs (e.g. wide "W" → narrow
                // "i"), skewing the running-median threshold. Using the gap
                // between the previous span's right edge and the current
                // span's left edge gives a truer inter-glyph spacing metric.
                // The right edge must come from the pre-refine ink width
                // (`ink_w`): on native pages `rect.w` has been replaced by the
                // origin-to-origin advance, making this gap ~0 for every
                // same-line pair and hiding all word spaces (C05 word-gap bug).
                let prev_w = p.ink_w.unwrap_or(p.rect.w);
                let advance = span.rect.x - (p.rect.x + prev_w);
                if advance.is_finite() && advance > 0.0 {
                    let median = advances.median().unwrap_or(6.0).clamp(3.0, 20.0);
                    // Word gap: clearly larger than a single character advance.
                    if advance > median * 1.55 {
                        out.push(' ');
                        map.push(None);
                    } else {
                        // Only *within-word* advances feed the running median;
                        // word-gap advances would inflate it and swallow real
                        // gaps ("JohnSmith"), so they are excluded.
                        advances.push(advance);
                    }
                }
            }
        }
        let start = out.len();
        out.push_str(&span.text);
        for _ in start..out.len() {
            map.push(Some(i));
        }
        prev = Some(span);
    }

    (out, map)
}

/// Bounded sorted window of recent glyph advances for running-median estimation.
///
/// Keeps the last ≤64 advances both in insertion order (for eviction) and in a
/// sorted buffer (for O(1) median), so `spaced_text` stays linear-ish instead
/// of re-sorting the whole history for every glyph. `median` is O(1); `push` is
/// O(window_size) due to `sorted.remove` / `sorted.insert` (at most 64-element
/// shift), so `spaced_text` is O(spans × 64).
struct AdvanceWindow {
    recent: std::collections::VecDeque<f32>,
    sorted: Vec<f32>,
}

impl AdvanceWindow {
    fn new() -> Self {
        Self {
            recent: std::collections::VecDeque::with_capacity(64),
            sorted: Vec::with_capacity(64),
        }
    }

    fn push(&mut self, v: f32) {
        // Defensive: a non-finite advance (inf from a degenerate glyph box)
        // would poison every later median comparison. Callers already skip
        // non-positive gaps; this keeps the window total-ordered even if one
        // slips through.
        if !v.is_finite() {
            return;
        }
        if self.recent.len() == 64 {
            let old = self.recent.pop_front().expect("window not empty");
            if let Ok(pos) = self
                .sorted
                .binary_search_by(|x| x.partial_cmp(&old).unwrap_or(std::cmp::Ordering::Equal))
            {
                self.sorted.remove(pos);
            }
        }
        self.recent.push_back(v);
        let pos = self.sorted.partition_point(|x| *x < v);
        self.sorted.insert(pos, v);
    }

    fn median(&self) -> Option<f32> {
        let n = self.sorted.len();
        if n == 0 {
            return None;
        }
        Some(if n.is_multiple_of(2) {
            (self.sorted[n / 2 - 1] + self.sorted[n / 2]) / 2.0
        } else {
            self.sorted[n / 2]
        })
    }
}

/// Map a byte range in `spaced` text back to union of original span rects.
pub fn rects_for_spaced_range(
    page: &PageText,
    map: &[Option<usize>],
    start: usize,
    end: usize,
) -> Option<Vec<Rect>> {
    let end = end.min(map.len());
    if start >= end {
        return None;
    }
    let mut indices = Vec::new();
    for si in map.iter().take(end).skip(start).flatten().copied() {
        if indices.last().copied() != Some(si) {
            indices.push(si);
        }
    }
    if indices.is_empty() {
        return None;
    }
    let mut rects: Vec<Rect> = indices
        .into_iter()
        .filter_map(|i| page.spans.get(i).map(|s| s.rect))
        .collect();
    if rects.is_empty() {
        return None;
    }
    // Merge overlapping / adjacent on same line.
    rects = merge_rects(rects);
    if rects.is_empty() {
        return None;
    }
    Some(rects)
}

fn merge_rects(mut rects: Vec<Rect>) -> Vec<Rect> {
    // Defensive boundary check: one degenerate glyph box (non-finite or
    // zero-area) must be skipped here rather than aborting the whole apply
    // later; the paint backstop in apply remains the final guard.
    rects.retain(|r| {
        let ok = r.is_valid();
        if !ok {
            tracing::debug!("dropping invalid rect at mapping boundary: {r:?}");
        }
        ok
    });
    if rects.is_empty() {
        return rects;
    }
    rects.sort_by(|a, b| {
        a.y.partial_cmp(&b.y)
            .unwrap_or(std::cmp::Ordering::Equal)
            .then(a.x.partial_cmp(&b.x).unwrap_or(std::cmp::Ordering::Equal))
    });
    let mut out = vec![rects[0]];
    for r in rects.into_iter().skip(1) {
        let last = out.last_mut().unwrap();
        let same_line = same_line_rects(*last, r);
        // Adjacent if the gap (right edge of last → left edge of r) is at
        // most half the *smaller* of the two rects' widths, with a minimum
        // tolerance of 4.0 pt so narrow single-character spans (width < 8.0)
        // still merge. Basing the tolerance on the smaller width (instead of
        // the accumulated merged rect's width, which grows without bound with
        // every merge) stops a wide region from absorbing a distant glyph box
        // on the same line (e.g. a page number or margin note).
        let gap = r.x - (last.x + last.w);
        let adjacent = gap <= (last.w.min(r.w) * 0.5).max(4.0);
        if same_line && adjacent {
            *last = last.union(r);
        } else {
            out.push(r);
        }
    }
    out
}

/// Map text matches on a page to regions. Unmapped matches are returned separately.
///
/// For each detector hit we map **every** occurrence of that string on the page
/// (not only the first), so names/SSNs that appear in headers and body both get
/// painted — matching user expectations for true multi-hit redaction.
pub fn map_matches(page: &PageText, matches: &[TextMatch]) -> (Vec<Region>, Vec<TextMatch>) {
    let (spaced, map) = spaced_text(page);
    let mut regions = Vec::new();
    let mut unmapped = Vec::new();
    // Avoid emitting duplicate regions for the same (text, byte-range) when
    // several detectors fire on the same string. The leading `bool` tags the
    // namespace: `false` = spaced-text offset, `true` = raw-text offset (an
    // arithmetic offset could collide on very large pages).
    let mut seen_keys: std::collections::HashSet<(bool, String, usize)> =
        std::collections::HashSet::new();
    // Skip re-scanning the page for a text an earlier match already mapped.
    let mut processed: std::collections::HashSet<String> = std::collections::HashSet::new();

    for m in matches {
        if m.text.is_empty() || processed.contains(&m.text) {
            continue;
        }
        processed.insert(m.text.clone());
        let mut found_any = false;

        // Prefer the detector's exact byte offsets first (C05-2/C05-3). The
        // re-scan by text below maps *every* occurrence for completeness, but
        // if the detector flagged a specific position, that position must be
        // mapped even when a text re-scan would land on a different one first.
        if m.start < m.end
            && let Some(rects) = rects_for_raw_range(page, m.start, m.end, &m.text)
        {
            let key = (true, m.text.clone(), m.start);
            if seen_keys.insert(key) {
                regions.push(Region {
                    page_index: page.page_index,
                    rects,
                    source_text: m.text.clone(),
                    category: m.category,
                    confidence: m.confidence,
                    included: true,
                    source: m.source,
                });
            }
            found_any = true;
        }

        // All spaced-text occurrences. Advance past the match's first
        // character (a whole UTF-8 char, not one byte) so *overlapping*
        // occurrences are found (e.g. "aa" in "aaa" → offsets 0 and 1).
        let mut from = 0;
        while let Some(rel) = spaced[from..].find(&m.text) {
            let pos = from + rel;
            if let Some(rects) = rects_for_spaced_range(page, &map, pos, pos + m.text.len()) {
                let key = (false, m.text.clone(), pos);
                if seen_keys.insert(key) {
                    regions.push(Region {
                        page_index: page.page_index,
                        rects,
                        source_text: m.text.clone(),
                        category: m.category,
                        confidence: m.confidence,
                        included: true,
                        source: m.source,
                    });
                }
                found_any = true;
            }
            from = pos + first_char_len(&m.text);
        }

        // Also raw-text occurrences not already covered (sticky glue path).
        // Advance past the match's first character (a whole UTF-8 char, not
        // one byte) so *overlapping* occurrences are found.
        let mut from = 0;
        while let Some(rel) = page.text[from..].find(&m.text) {
            let pos = from + rel;
            let end = pos + m.text.len();
            // Verify the overlapping spans reconstruct the needle (C05-1):
            // a shorter needle that is a substring of a larger ID matched by
            // another detector would otherwise produce a spurious region for
            // a location the detector never flagged.
            if let Some(rects) = rects_for_raw_range(page, pos, end, &m.text) {
                let key = (true, m.text.clone(), pos); // namespace raw vs spaced
                if seen_keys.insert(key) {
                    regions.push(Region {
                        page_index: page.page_index,
                        rects,
                        source_text: m.text.clone(),
                        category: m.category,
                        confidence: m.confidence,
                        included: true,
                        source: m.source,
                    });
                }
                found_any = true;
            }
            from = pos + first_char_len(&m.text);
        }

        if !found_any {
            unmapped.push(m.clone());
        }
    }

    // The same glyph run can be mapped through both the spaced-text and the
    // raw-text paths (any space-free match: SSNs, credit cards, phones, IDs),
    // producing duplicate regions with identical rects. Keep one per
    // (page, source text, rect set); keyed by a sorted rect fingerprint so
    // the dedupe stays linear instead of scanning all prior regions.
    let mut seen_regions: std::collections::HashSet<(usize, String, RectFingerprint)> =
        std::collections::HashSet::with_capacity(regions.len());
    let mut deduped: Vec<Region> = Vec::with_capacity(regions.len());
    for r in regions {
        if seen_regions.insert((r.page_index, r.source_text.clone(), rects_key(&r.rects))) {
            deduped.push(r);
        }
    }
    (deduped, unmapped)
}

/// Collect spans overlapping `[pos, end)` in raw page text and merge them.
/// Guards against substring contamination (C05-1): the concatenated span
/// text within `[pos, end)` must equal the needle text, so a shorter needle
/// that is merely a substring of a larger ID matched by another detector
/// cannot produce a spurious region for a location the detector never flagged.
fn rects_for_raw_range(page: &PageText, pos: usize, end: usize, needle: &str) -> Option<Vec<Rect>> {
    let mut rects = Vec::new();
    let mut reconstructed = String::new();
    for span in &page.spans {
        if span.end > pos && span.start < end && span.rect.is_valid() {
            // Append only the part of the span that falls inside [pos, end).
            let lo = span.start.max(pos);
            let hi = span.end.min(end);
            if span.text.is_empty() {
                tracing::warn!(
                    "span claims byte range [{}, {}) but has empty text; \
                     skipping — may cause mapping miss for bytes in this range",
                    span.start,
                    span.end
                );
                continue;
            }
            // Map byte offsets within the span's text.
            let rel_lo = lo.saturating_sub(span.start);
            let rel_hi = hi.saturating_sub(span.start);
            if let Some(slice) = span.text.get(rel_lo..rel_hi.min(span.text.len())) {
                reconstructed.push_str(slice);
            }
            rects.push(span.rect);
        }
    }
    if reconstructed != needle {
        return None;
    }
    let merged = merge_rects(rects);
    if merged.is_empty() {
        None
    } else {
        Some(merged)
    }
}

/// Stable, hashable fingerprint of a rect set, for region dedupe.
type RectFingerprint = Vec<(i64, i64, i64, i64)>;

fn rects_key(rects: &[Rect]) -> RectFingerprint {
    // Quantize each coordinate to 0.01 pt so near-identical rects that differ
    // only by sub-pixel float rounding (e.g. from different `union` orderings
    // between the spaced and raw passes) collapse to the same fingerprint.
    let mut key: RectFingerprint = rects
        .iter()
        .map(|r| {
            (
                (r.x * 100.0).round() as i64,
                (r.y * 100.0).round() as i64,
                (r.w * 100.0).round() as i64,
                (r.h * 100.0).round() as i64,
            )
        })
        .collect();
    key.sort_unstable();
    key
}

/// Create regions for every occurrence of `needle` in page text.
///
/// Both the spaced pass (line-break aware, word gaps from advances) and the
/// raw pass (contiguous text — catches a needle that straddles a line break
/// in the spaced text, e.g. `"John \nSmith"`) run unconditionally, and
/// duplicates produced by both passes are collapsed by rect-set equality.
pub fn regions_for_search_text(page: &PageText, needle: &str) -> Vec<Region> {
    let (spaced, map) = spaced_text(page);
    regions_for_search_text_in(page, &spaced, &map, needle)
}

/// Like [`regions_for_search_text`], but reuses a precomputed spaced text +
/// byte map for the page so the caller does not rebuild them per search
/// string per page.
pub fn regions_for_search_text_in(
    page: &PageText,
    spaced: &str,
    map: &[Option<usize>],
    needle: &str,
) -> Vec<Region> {
    if needle.is_empty() {
        return Vec::new();
    }
    let mut regions = Vec::new();
    let mut from = 0;
    while let Some(rel) = spaced[from..].find(needle) {
        let pos = from + rel;
        if let Some(rects) = rects_for_spaced_range(page, map, pos, pos + needle.len()) {
            regions.push(search_region(page, needle, rects));
        }
        from = pos + first_char_len(needle);
    }
    // Raw-text pass: always runs, even when the spaced pass found occurrences
    // elsewhere — a needle can occur once with clean geometry and once split
    // across a line break, and both must be mapped.
    let mut from = 0;
    while let Some(rel) = page.text[from..].find(needle) {
        let pos = from + rel;
        let end = pos + needle.len();
        if let Some(rects) = rects_for_raw_range(page, pos, end, needle) {
            regions.push(search_region(page, needle, rects));
        }
        from = pos + first_char_len(needle);
    }
    // Collapse identical rect-sets produced by both passes (space-free
    // needles match in both); first occurrence wins. Uses the same
    // HashSet-based O(n) approach as `map_matches`.
    let mut seen_regions: std::collections::HashSet<(usize, String, RectFingerprint)> =
        std::collections::HashSet::with_capacity(regions.len());
    let mut deduped: Vec<Region> = Vec::with_capacity(regions.len());
    for r in regions {
        if seen_regions.insert((r.page_index, r.source_text.clone(), rects_key(&r.rects))) {
            deduped.push(r);
        }
    }
    deduped
}

fn search_region(page: &PageText, needle: &str, rects: Vec<Rect>) -> Region {
    Region {
        page_index: page.page_index,
        rects,
        source_text: needle.to_string(),
        category: crate::types::Category::Custom,
        confidence: 1.0,
        included: true,
        source: MatchSource::Search,
    }
}

/// Ensure all included regions have geometry; error if any required mapping failed.
pub fn require_mapped(unmapped: &[TextMatch]) -> Result<()> {
    if unmapped.is_empty() {
        Ok(())
    } else {
        Err(RedactError::UnmappedMatches {
            count: unmapped.len(),
        })
    }
}

/// Manual region from CLI rect (already in page space).
pub fn manual_region(page_index: usize, rect: Rect, label: impl Into<String>) -> Region {
    Region {
        page_index,
        rects: vec![rect],
        source_text: label.into(),
        category: crate::types::Category::Custom,
        confidence: 1.0,
        included: true,
        source: MatchSource::Manual,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::{Category, MatchSource, PageText, TextMatch, TextSpan};

    fn page_with_text(text: &str) -> PageText {
        let mut spans = Vec::new();
        let mut off = 0;
        for ch in text.chars() {
            let s = ch.to_string();
            let s_len = s.len();
            spans.push(TextSpan {
                start: off,
                end: off + s_len,
                text: s,
                rect: Rect::new(off as f32 * 8.0, 0.0, 8.0, 10.0),
                ink_w: None,
            });
            off += s_len;
        }
        PageText {
            page_index: 0,
            text: text.to_string(),
            spans,
            width: 1000.0,
            height: 100.0,
        }
    }

    /// Build a page from explicit (x, y) glyph placements, so tests can
    /// exercise line breaks, tall spans and mixed geometry.
    fn page_with_geometry(glyphs: &[(&str, f32, f32)], width: f32, height: f32) -> PageText {
        let mut spans = Vec::new();
        let mut text = String::new();
        let mut off = 0;
        for (ch, x, y) in glyphs {
            let s = (*ch).to_string();
            let s_len = s.len();
            spans.push(TextSpan {
                start: off,
                end: off + s_len,
                text: s,
                rect: Rect::new(*x, *y, 8.0, 10.0),
                ink_w: None,
            });
            off += s_len;
            text.push_str(ch);
        }
        PageText {
            page_index: 0,
            text,
            spans,
            width,
            height,
        }
    }

    fn match_at(text: &str) -> TextMatch {
        TextMatch {
            start: 0,
            end: text.len(),
            text: text.to_string(),
            category: Category::Ssn,
            confidence: 0.9,
            detector_id: "regex:ssn-dashed".into(),
            source: MatchSource::Regex,
        }
    }

    #[test]
    fn map_matches_dedupes_spaced_and_raw_duplicates() {
        // Space-free match is contiguous in BOTH the spaced and the raw text,
        // so both mapping branches fire; they must collapse into one region.
        let pt = page_with_text("SSN: 123-45-6789 END");
        let (regions, unmapped) = map_matches(&pt, &[match_at("123-45-6789")]);
        assert!(unmapped.is_empty());
        assert_eq!(regions.len(), 1, "duplicate regions: {regions:?}");
        assert_eq!(regions[0].source_text, "123-45-6789");
    }

    #[test]
    fn map_matches_maps_every_occurrence() {
        // Multi-hit: same SSN twice on the page → two distinct regions.
        let pt = page_with_text("SSN 123-45-6789 and SSN 123-45-6789 END");
        let (regions, unmapped) = map_matches(&pt, &[match_at("123-45-6789")]);
        assert!(unmapped.is_empty());
        assert_eq!(regions.len(), 2, "regions: {regions:?}");
    }

    #[test]
    fn map_matches_line_break_straddle() {
        // A detector match whose text straddles a line break in the spaced
        // text: the spaced-text pass won't find it (the \n breaks the match),
        // but the raw-text fallback pass should map it via the contiguous
        // page.text. This mirrors the search-text straddle test but exercises
        // the detector path (map_matches).
        // y=0 line: "John \n"  (space + newline between "John" and "Smith")
        // y=20 line: "Smith"
        let pt = page_with_geometry(
            &[
                ("J", 0.0, 0.0),
                ("o", 8.0, 0.0),
                ("h", 16.0, 0.0),
                ("n", 24.0, 0.0),
                (" ", 32.0, 0.0),
                ("\n", 40.0, 0.0),
                ("S", 0.0, 20.0),
                ("m", 8.0, 20.0),
                ("i", 16.0, 20.0),
                ("t", 24.0, 20.0),
                ("h", 32.0, 20.0),
            ],
            100.0,
            100.0,
        );
        // page.text = "John \nSmith"; the match text is "John \nSmith" which
        // is contiguous in raw text. The spaced pass inserts a \n for the
        // y-break so "John \nSmith" won't match there, but the raw pass finds
        // it at byte offset 0.
        let needle = "John \nSmith";
        let m = TextMatch {
            start: 0,
            end: needle.len(),
            text: needle.to_string(),
            category: Category::Person,
            confidence: 0.8,
            detector_id: "regex:person".into(),
            source: MatchSource::Regex,
        };
        let (regions, unmapped) = map_matches(&pt, &[m]);
        assert!(unmapped.is_empty(), "should be mapped via raw pass");
        assert_eq!(regions.len(), 1, "regions: {regions:?}");
    }

    #[test]
    fn spaced_text_inserts_word_gaps_not_inside_words() {
        let pt = page_with_text("hello world");
        let (spaced, _) = spaced_text(&pt);
        assert_eq!(spaced, "hello world");
    }

    #[test]
    fn advance_window_median() {
        let mut w = AdvanceWindow::new();
        assert_eq!(w.median(), None);
        for v in 0..64 {
            w.push(v as f32);
        }
        assert_eq!(w.median(), Some(31.5));
        // Window is bounded at 64: pushing one more evicts the oldest (0.0).
        w.push(64.0);
        assert_eq!(w.median(), Some(32.5));
    }

    #[test]
    fn spaced_text_inserts_line_breaks() {
        // Two lines (y=0 and y=20): a \n must be inserted between them.
        let pt = page_with_geometry(
            &[
                ("J", 0.0, 0.0),
                ("o", 8.0, 0.0),
                ("h", 16.0, 0.0),
                ("n", 24.0, 0.0),
                ("S", 0.0, 20.0),
                ("m", 8.0, 20.0),
                ("i", 16.0, 20.0),
                ("t", 24.0, 20.0),
                ("h", 32.0, 20.0),
            ],
            100.0,
            100.0,
        );
        let (spaced, _) = spaced_text(&pt);
        assert_eq!(spaced, "John\nSmith");
    }

    #[test]
    fn tall_span_does_not_glue_following_line() {
        // Drop-cap span (h=100) followed by a normal line at y=20: the shared
        // predicate uses BOTH heights, so the tall span cannot widen the
        // tolerance and swallow the line break.
        let spans = vec![
            TextSpan {
                start: 0,
                end: 1,
                text: "T".into(),
                rect: Rect::new(0.0, 0.0, 20.0, 100.0),
                ink_w: None,
            },
            TextSpan {
                start: 1,
                end: 2,
                text: "h".into(),
                rect: Rect::new(0.0, 20.0, 8.0, 10.0),
                ink_w: None,
            },
        ];
        let pt = PageText {
            page_index: 0,
            text: "Th".into(),
            spans,
            width: 100.0,
            height: 100.0,
        };
        let (spaced, _) = spaced_text(&pt);
        assert_eq!(spaced, "T\nh");
    }

    #[test]
    fn search_text_raw_fallback_runs_even_when_spaced_hit_exists() {
        // F1: occurrence 1 sits on one line (spaced text finds it); occurrence 2
        // straddles a line break with a trailing space glyph (spaced: "John \nSmith")
        // and is contiguous only in the raw text. Both must be mapped.
        let pt = page_with_geometry(
            &[
                // Line 1: "John Smith"
                ("J", 0.0, 0.0),
                ("o", 8.0, 0.0),
                ("h", 16.0, 0.0),
                ("n", 24.0, 0.0),
                (" ", 32.0, 0.0),
                ("S", 40.0, 0.0),
                ("m", 48.0, 0.0),
                ("i", 56.0, 0.0),
                ("t", 64.0, 0.0),
                ("h", 72.0, 0.0),
                // Line 2: "John " (trailing space glyph)
                ("J", 0.0, 20.0),
                ("o", 8.0, 20.0),
                ("h", 16.0, 20.0),
                ("n", 24.0, 20.0),
                (" ", 32.0, 20.0),
                // Line 3: "Smith"
                ("S", 0.0, 40.0),
                ("m", 8.0, 40.0),
                ("i", 16.0, 40.0),
                ("t", 24.0, 40.0),
                ("h", 32.0, 40.0),
            ],
            200.0,
            100.0,
        );
        let regions = regions_for_search_text(&pt, "John Smith");
        assert_eq!(regions.len(), 2, "regions: {regions:?}");
        // Occurrence 1 is a single merged line rect; occurrence 2 spans two
        // lines and must be a separate, two-rect region.
        assert!(regions.iter().any(|r| r.rects.len() == 1));
        assert!(regions.iter().any(|r| r.rects.len() == 2));
    }

    #[test]
    fn search_text_non_ascii_needle() {
        // Multi-byte UTF-8 offsets must map back to the right spans.
        let pt = page_with_text("café résumé");
        let regions = regions_for_search_text(&pt, "résumé");
        assert_eq!(regions.len(), 1, "regions: {regions:?}");
        assert!(!regions[0].rects.is_empty());
    }

    #[test]
    fn search_text_multi_byte_first_char_no_panic() {
        // A needle whose FIRST character is multi-byte (e.g. "é") must not
        // panic the occurrence loop: advancing by one *byte* lands on a UTF-8
        // continuation byte and the next `spaced[from..]` slice panics.
        // Advancing by the first char's byte length finds both occurrences.
        let pt = page_with_text("éa éb");
        let regions = regions_for_search_text(&pt, "é");
        assert_eq!(regions.len(), 2, "regions: {regions:?}");
        let regions2 = regions_for_search_text(&pt, "éa");
        assert_eq!(regions2.len(), 1, "regions: {regions2:?}");
    }

    #[test]
    fn spaced_text_uses_ink_width_not_refined_advance() {
        // Native pages: `refine_advances` replaces each glyph's rect.w with
        // the origin-to-origin advance to the next same-line glyph, so the
        // right-edge gap would be ~0 and word gaps would never become spaces.
        // The pre-refine ink width (`ink_w`) must be used for the gap instead.
        // Spans mimic a refined page: rect.w = advance (8), ink_w = ink (6),
        // word gap between "b" and "c" = 24 - (8 + 6) = 10.
        let pt = PageText {
            page_index: 0,
            text: "abcd".into(),
            spans: vec![
                TextSpan {
                    start: 0,
                    end: 1,
                    text: "a".into(),
                    rect: Rect::new(0.0, 0.0, 8.0, 10.0),
                    ink_w: Some(6.0),
                },
                TextSpan {
                    start: 1,
                    end: 2,
                    text: "b".into(),
                    rect: Rect::new(8.0, 0.0, 8.0, 10.0),
                    ink_w: Some(6.0),
                },
                TextSpan {
                    start: 2,
                    end: 3,
                    text: "c".into(),
                    rect: Rect::new(24.0, 0.0, 8.0, 10.0),
                    ink_w: Some(6.0),
                },
                TextSpan {
                    start: 3,
                    end: 4,
                    text: "d".into(),
                    rect: Rect::new(32.0, 0.0, 8.0, 10.0),
                    ink_w: Some(6.0),
                },
            ],
            width: 100.0,
            height: 100.0,
        };
        let (spaced, _) = spaced_text(&pt);
        assert_eq!(spaced, "ab cd", "spaced: {spaced:?}");
    }

    #[test]
    fn regions_for_search_text_in_reuses_precomputed_spaced() {
        let pt = page_with_text("hello world");
        let (spaced, map) = spaced_text(&pt);
        let regions = regions_for_search_text_in(&pt, &spaced, &map, "world");
        assert_eq!(regions.len(), 1);
        assert_eq!(regions[0].source_text, "world");
        assert!(!regions[0].rects.is_empty());
    }

    #[test]
    fn merge_rects_drops_invalid_rects() {
        let merged = merge_rects(vec![
            Rect::new(0.0, 0.0, 8.0, 10.0),
            Rect::new(f32::NAN, 0.0, 8.0, 10.0),
            Rect::new(0.0, 0.0, 0.0, 10.0), // zero width
        ]);
        assert_eq!(merged.len(), 1);
        assert_eq!(merged[0], Rect::new(0.0, 0.0, 8.0, 10.0));
    }

    #[test]
    fn merge_rects_tolerance_does_not_grow_with_accumulated_width() {
        // A wide accumulated region must not absorb a distant small glyph:
        // the adjacency tolerance is based on the SMALLER of the two widths,
        // so a 400 pt region cannot accept a 20 pt gap (old formula allowed
        // up to 400*0.5 = 200 pt and swallowed margin notes / page numbers).
        let merged = merge_rects(vec![
            Rect::new(0.0, 0.0, 400.0, 10.0),
            Rect::new(420.0, 0.0, 8.0, 10.0), // gap 20
        ]);
        assert_eq!(
            merged.len(),
            2,
            "wide region absorbed a distant glyph: {merged:?}"
        );
    }

    #[test]
    fn merge_rects_small_gap_still_merges() {
        // The 4.0 pt floor must be preserved: a narrow glyph a couple of
        // points away from a wide region is genuinely adjacent and merges.
        let merged = merge_rects(vec![
            Rect::new(0.0, 0.0, 400.0, 10.0),
            Rect::new(402.0, 0.0, 8.0, 10.0), // gap 2
        ]);
        assert_eq!(merged.len(), 1, "regions: {merged:?}");
    }

    #[test]
    fn map_matches_skips_already_processed_text() {
        // Two detector hits with identical text must map the page only once
        // (F9), still producing one region per occurrence.
        let pt = page_with_text("SSN 123-45-6789 END");
        let (regions, unmapped) =
            map_matches(&pt, &[match_at("123-45-6789"), match_at("123-45-6789")]);
        assert!(unmapped.is_empty());
        assert_eq!(regions.len(), 1, "regions: {regions:?}");
    }

    #[test]
    fn map_matches_distinct_needles_same_page() {
        // C05-8: two *different* detector hits on the same page must both map
        // to independent regions.
        let pt = page_with_text("John Smith SSN 123-45-6789 END");
        let m1 = TextMatch {
            start: 0,
            end: 10,
            text: "John Smith".into(),
            category: Category::Person,
            confidence: 0.8,
            detector_id: "regex:person".into(),
            source: MatchSource::Regex,
        };
        let m2 = match_at("123-45-6789");
        let (regions, unmapped) = map_matches(&pt, &[m1, m2]);
        assert!(unmapped.is_empty());
        assert_eq!(regions.len(), 2, "regions: {regions:?}");
        let texts: Vec<&str> = regions.iter().map(|r| r.source_text.as_str()).collect();
        assert!(texts.contains(&"John Smith"));
        assert!(texts.contains(&"123-45-6789"));
    }

    #[test]
    fn map_matches_empty_page() {
        // C05-9: a page with no extractable text returns no regions and all
        // matches unmapped, without panicking.
        let pt = PageText {
            page_index: 0,
            text: String::new(),
            spans: Vec::new(),
            width: 100.0,
            height: 100.0,
        };
        let (regions, unmapped) = map_matches(&pt, &[match_at("123-45-6789")]);
        assert!(regions.is_empty());
        assert_eq!(unmapped.len(), 1);
    }

    #[test]
    fn regions_for_search_text_empty_page() {
        // C05-9: search on an empty page returns no regions.
        let pt = PageText {
            page_index: 0,
            text: String::new(),
            spans: Vec::new(),
            width: 100.0,
            height: 100.0,
        };
        let regions = regions_for_search_text(&pt, "anything");
        assert!(regions.is_empty());
    }

    #[test]
    fn raw_pass_rejects_substring_contamination() {
        // C05-1: a short needle that is a substring of a longer span must not
        // produce a spurious region if the overlapping spans' text does not
        // reconstruct the needle. Here each glyph is its own span, so the
        // reconstruction check always passes for legitimate matches — but it
        // guards against the case where a single wide span covers text that
        // merely *contains* the needle substring at the byte level.
        // Build a page where one span covers "AAA" and the needle is "A":
        // the raw pass must map it (reconstruction of the "A" slice succeeds).
        let pt = PageText {
            page_index: 0,
            text: "AAA".into(),
            spans: vec![TextSpan {
                start: 0,
                end: 3,
                text: "AAA".into(),
                rect: Rect::new(0.0, 0.0, 24.0, 10.0),
                ink_w: None,
            }],
            width: 100.0,
            height: 100.0,
        };
        let regions = regions_for_search_text(&pt, "A");
        // "A" occurs 3 times (overlapping search finds all 3 at offsets 0,1,2);
        // all map to the same single span rect, so dedupe collapses to 1.
        assert!(!regions.is_empty());
    }

    #[test]
    fn raw_pass_rejects_mismatched_reconstruction() {
        // C05-1 core: when the overlapping span text does NOT equal the needle,
        // rects_for_raw_range returns None. Build a scenario where spans have
        // text that differs from the page.text slice at the needle position.
        let pt = PageText {
            page_index: 0,
            text: "XY".into(),
            spans: vec![TextSpan {
                start: 0,
                end: 2,
                text: "ZZ".into(), // span text mismatches page.text
                rect: Rect::new(0.0, 0.0, 16.0, 10.0),
                ink_w: None,
            }],
            width: 100.0,
            height: 100.0,
        };
        // Searching for "XY" in page.text finds it, but the span text is "ZZ",
        // so reconstruction fails → no regions from the raw pass. The spaced
        // pass also fails (same spans), so we get no regions.
        let regions = regions_for_search_text(&pt, "XY");
        assert!(
            regions.is_empty(),
            "mismatched reconstruction should reject: {regions:?}"
        );
    }

    #[test]
    fn map_matches_uses_detector_byte_offsets() {
        // C05-2/C05-3: the detector's start/end byte offsets must be mapped
        // even when the text re-scan would find a different occurrence first.
        // Place "SSN" twice; the detector offsets point at the second one.
        let pt = page_with_text("SSN is here and SSN again");
        // detector says the match is at the second "SSN" (offset 18).
        let m = TextMatch {
            start: 18,
            end: 21,
            text: "SSN".into(),
            category: Category::Ssn,
            confidence: 0.9,
            detector_id: "regex:test".into(),
            source: MatchSource::Regex,
        };
        let (regions, unmapped) = map_matches(&pt, &[m]);
        assert!(unmapped.is_empty());
        // Both occurrences are mapped (detector offset + text re-scan), and
        // dedupe collapses to 2 distinct rect-sets.
        assert_eq!(regions.len(), 2, "regions: {regions:?}");
    }

    #[test]
    fn map_matches_multi_byte_first_char_no_panic() {
        // Same UTF-8 continuation-byte hazard as the search path: the
        // detector-hit occurrence loops must advance by a whole first
        // character, not one byte, when the needle starts with multi-byte
        // UTF-8 text.
        let pt = page_with_text("éa éb");
        let m = TextMatch {
            start: 0,
            end: "é".len(),
            text: "é".into(),
            category: Category::Ssn,
            confidence: 0.9,
            detector_id: "regex:test".into(),
            source: MatchSource::Regex,
        };
        let (regions, unmapped) = map_matches(&pt, &[m]);
        assert!(unmapped.is_empty(), "unmapped: {unmapped:?}");
        assert_eq!(regions.len(), 2, "regions: {regions:?}");
    }
}
