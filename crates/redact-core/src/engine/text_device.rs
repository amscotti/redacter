//! Collect unicode glyphs + approximate boxes via hayro's Device trait.

use hayro::hayro_interpret::font::Glyph;
use hayro::hayro_interpret::hayro_cmap::BfString;
use hayro::hayro_interpret::{
    BlendMode, ClipPath, Device, GlyphDrawMode, Image, Paint, PathDrawMode, SoftMask,
};
use kurbo::{Affine, BezPath, Point, Shape};

use crate::types::{PageText, Rect, TextSpan};

/// Font units per em (hayro-interpret's `UNITS_PER_EM`): hayro's
/// `glyph_transform` is `full_transform * Affine::scale(1.0 / UNITS_PER_EM)`,
/// so the combined CTM maps **font units** (1 unit = 1/1000 em) directly into
/// viewport space.
const UNITS_PER_EM: f64 = 1000.0;

/// Approximate equality for two `Affine` transforms (component-wise epsilon).
///
/// Used by the FillStroke dedupe so that floating-point drift between the
/// two draws (possible across platforms/optimization levels) doesn't silently
/// break the dedupe and extract text doubled.
fn affines_approx_eq(a: Affine, b: Affine) -> bool {
    let ac = a.as_coeffs();
    let bc = b.as_coeffs();
    const EPS: f64 = 1e-9;
    ac.iter().zip(bc.iter()).all(|(&x, &y)| (x - y).abs() < EPS)
}

/// Whether a glyph draw mode is a fill or a stroke.
///
/// Hayro dispatches `Fill` then `Stroke` for `TextRenderingMode::FillStroke`
/// text (outlined / bold-effect). The dedupe in [`TextCollector::record`]
/// matches a consecutive draw with a *different* mode (fill↔stroke) but the
/// same glyph and transform, so it only drops the FillStroke double-dispatch —
/// never two legitimate copies of the same character at the same position.
fn mode_kind(mode: &GlyphDrawMode) -> &'static str {
    match mode {
        GlyphDrawMode::Fill => "fill",
        GlyphDrawMode::Stroke(_) => "stroke",
        GlyphDrawMode::Invisible => "invisible",
    }
}

#[derive(Default)]
pub(crate) struct TextCollector {
    pub page_index: usize,
    pub width: f32,
    pub height: f32,
    glyphs: Vec<GlyphHit>,
    /// Last (unicode, combined transform, raw CTM, draw-mode kind) drawn, to
    /// dedupe hayro's double-dispatch for `FillStroke` text modes. Carrying the
    /// draw-mode kind (not just `ch` + transform) ensures the dedupe only
    /// fires on the genuine Fill→Stroke double-dispatch — two distinct glyphs
    /// at the same position with the same mode are never silently dropped. The
    /// raw CTM (before composition with `glyph_transform`) adds a position
    /// identity signal so two distinct glyphs sharing the same `(ch, combined)`
    /// but at different text positions are also never collapsed (C01-m1).
    last_draw: Option<(String, Affine, Affine, &'static str)>,
}

struct GlyphHit {
    ch: String,
    /// Top-left page render coordinates (y grows downward).
    x: f32,
    y: f32,
    w: f32,
    h: f32,
}

impl TextCollector {
    pub fn new(page_index: usize, width: f32, height: f32) -> Self {
        Self {
            page_index,
            width,
            height,
            glyphs: Vec::new(),
            last_draw: None,
        }
    }

    pub fn into_page_text(mut self) -> PageText {
        // Keep each glyph's pre-refine ink width: `refine_advances` replaces
        // `g.w` with the origin-to-origin advance to the next same-line glyph,
        // which `spaced_text` needs to tell real word gaps apart from the
        // advance (see `geometry::spaced_text`).
        let ink_widths: Vec<f32> = self.glyphs.iter().map(|g| g.w).collect();
        // Refine widths from consecutive advances on the same baseline.
        refine_advances(&mut self.glyphs);

        let mut text = String::new();
        let mut spans = Vec::new();

        for (gi, g) in self.glyphs.iter().enumerate() {
            // Skip truly invisible glyphs (collapsed transform, e.g. `0 Tf`
            // produces no visible ink): the 0.5/1.0 floor would otherwise
            // inflate them into spurious detection regions.
            if g.w == 0.0 || g.h == 0.0 {
                continue;
            }
            let start = text.len();
            text.push_str(&g.ch);
            let end = text.len();
            spans.push(TextSpan {
                start,
                end,
                text: g.ch.clone(),
                rect: Rect::new(g.x, g.y, g.w.max(0.5), g.h.max(1.0)),
                ink_w: Some(ink_widths[gi]),
            });
        }

        PageText {
            page_index: self.page_index,
            text,
            spans,
            width: self.width,
            height: self.height,
        }
    }

    /// Record one glyph draw, skipping the exact consecutive duplicate that
    /// hayro emits for `TextRenderingMode::FillStroke` /
    /// `FillAndStrokeAndClip` (outlined/bold-effect text). Without the dedupe
    /// such text would be extracted doubled ("Jane" → "JJaann ee") and never
    /// match a detection regex.
    ///
    /// The dedupe key is `(ch, combined transform, raw CTM, draw-mode kind)`: it
    /// fires only when the *mode differs* (fill↔stroke) but the glyph,
    /// combined transform, and raw CTM all match — the genuine Fill→Stroke
    /// double-dispatch. Two distinct glyphs at the same position sharing the
    /// same mode are never dropped. The raw CTM (`ctm`, before composition
    /// with `glyph_transform`) ensures two distinct glyphs sharing the same
    /// `(ch, combined)` but at different text positions are also never
    /// collapsed (C01-m1).
    fn record(
        &mut self,
        ch: String,
        combined: Affine,
        ctm: Affine,
        mode: &GlyphDrawMode,
        (x, y, w, h): (f32, f32, f32, f32),
    ) {
        let kind = mode_kind(mode);
        if self.last_draw.as_ref().is_some_and(|(c, t, ct, k)| {
            *c == ch && affines_approx_eq(*t, combined) && affines_approx_eq(*ct, ctm) && *k != kind
        }) {
            return;
        }
        self.glyphs.push(GlyphHit {
            ch: ch.clone(),
            x,
            y,
            w,
            h,
        });
        self.last_draw = Some((ch, combined, ctm, kind));
    }
}

/// Axis-aligned ink box of a glyph in viewport space (top-left, y-down).
///
/// Outline glyphs (Type1 / TrueType / Type0 / CFF — essentially every real
/// font) expose their outline in font units via [`Glyph::Outline`], and the
/// combined CTM maps font units directly into viewport space (see
/// [`UNITS_PER_EM`]), so transforming the outline yields the exact ink box.
///
/// The previous approach measured the transform's unit vectors as if they were
/// 1 em — but hayro's `glyph_transform` scales by `1/1000`, so a 12 pt font
/// measured `0.012` and every box collapsed to sub-point size (the C1 bug:
/// ~1 pt tall boxes missing ~90% of the ink).
///
/// The final box keeps the outline's exact horizontal ink span but is extended
/// vertically to the em envelope (baseline − descent .. baseline + ascent).
/// Punctuation like `.`/`-`/`,` has only ~1 pt of ink, and a box that tight
/// would read as a line break to the word/line heuristics downstream (the
/// e2e regression: emails/SSNs split at every period/hyphen). A line-height
/// box for those glyphs keeps the text on one line while still covering the
/// ink. Type3 glyphs have no accessible outline and whitespace glyphs have an
/// empty one; for those we fall back to the em envelope built from the
/// 1000-unit em square.
fn glyph_ink_box(glyph: &Glyph<'_>, combined: Affine) -> (f32, f32, f32, f32) {
    let outline_box = if let Glyph::Outline(outline) = glyph {
        let path = combined * outline.outline();
        if path.segments().next().is_some() {
            let b = path.bounding_box();
            Some((
                b.x0 as f32,
                b.y0 as f32,
                (b.x1 - b.x0) as f32,
                (b.y1 - b.y0) as f32,
            ))
        } else {
            None
        }
    } else {
        None
    };
    let em_box = em_estimate_box(combined);
    match outline_box {
        // Extend the exact ink vertically to the em envelope; keep the exact
        // horizontal span (a full-em-wide envelope would over-cover by ~2×
        // and inflate the box area, weakening box↔ink test ratios).
        Some((x, y, w, h)) => {
            let y0 = y.min(em_box.1);
            let y1 = (y + h).max(em_box.1 + em_box.3);
            (x, y0, w, y1 - y0)
        }
        None => em_box,
    }
}

/// Estimate a glyph's ink box from the em square, for glyphs without an
/// accessible outline (Type3) or with an empty one (whitespace). The combined
/// transform maps **font units** (1 unit = 1/1000 em, y-up: ascent positive,
/// descent negative) into viewport space, so the em square is
/// `(UNITS_PER_EM, 0)` / `(0, UNITS_PER_EM)` in local space.
///
/// The estimated ink box is expressed in font units (advance ≈ one em wide,
/// ascent 0.85 em above the baseline, descent 0.25 em below) and transformed
/// through the combined CTM, taking the AABB — so rotated pages (/Rotate)
/// get correctly oriented coverage too. A box that only grew along +x / -y
/// would miss text running in any other direction.
///
/// The advance width is only an em-wide upper bound: `refine_advances`
/// replaces it with the real distance to the next glyph on the same line, so
/// the estimate only has to guarantee coverage, not tightness.
fn em_estimate_box(combined: Affine) -> (f32, f32, f32, f32) {
    // 1000 font units = 1 em; the ink extends 0.85 em above the baseline and
    // 0.25 em below (a generous cap-height + small descent envelope).
    let advance_units = UNITS_PER_EM;
    let ascent_units = UNITS_PER_EM * 0.85;
    let descent_units = UNITS_PER_EM * 0.25;
    let local_corners = [
        Point::new(0.0, 0.0),
        Point::new(advance_units, 0.0),
        Point::new(0.0, -descent_units),
        Point::new(advance_units, -descent_units),
        Point::new(0.0, ascent_units),
        Point::new(advance_units, ascent_units),
    ];
    let mut min_x = f64::INFINITY;
    let mut min_y = f64::INFINITY;
    let mut max_x = f64::NEG_INFINITY;
    let mut max_y = f64::NEG_INFINITY;
    for p in local_corners {
        let q = combined * p;
        min_x = min_x.min(q.x);
        min_y = min_y.min(q.y);
        max_x = max_x.max(q.x);
        max_y = max_y.max(q.y);
    }
    (
        min_x as f32,
        min_y as f32,
        ((max_x - min_x) as f32).max(0.5),
        ((max_y - min_y) as f32).max(1.0),
    )
}

/// Replace per-glyph width with next-glyph advance when on the same line.
fn refine_advances(glyphs: &mut [GlyphHit]) {
    if glyphs.is_empty() {
        return;
    }
    for i in 0..glyphs.len().saturating_sub(1) {
        let (left, right) = glyphs.split_at_mut(i + 1);
        let cur = &mut left[i];
        let next = &right[0];
        // Shared line-break predicate: derived from BOTH spans' heights so
        // this module agrees with spaced_text / merge_rects on line breaks.
        let same_line = crate::types::same_line_rects(
            Rect::new(cur.x, cur.y, cur.w, cur.h),
            Rect::new(next.x, next.y, next.w, next.h),
        );
        if same_line && next.x > cur.x {
            let adv = next.x - cur.x;
            if adv > 0.2 && adv < cur.h.max(4.0) * 3.0 {
                cur.w = adv;
            }
        }
    }
}

impl Device<'_> for TextCollector {
    fn set_soft_mask(&mut self, _: Option<SoftMask<'_>>) {}
    fn set_blend_mode(&mut self, _: BlendMode) {}
    fn draw_path(&mut self, _: &BezPath, _: Affine, _: &Paint<'_>, _: &PathDrawMode) {}
    fn push_clip_path(&mut self, _: &ClipPath) {}
    fn push_transparency_group(&mut self, _: f32, _: Option<SoftMask<'_>>, _: BlendMode) {}
    fn pop_clip_path(&mut self) {}
    fn pop_transparency_group(&mut self) {}
    fn draw_image(&mut self, _: Image<'_, '_>, _: Affine) {}

    fn draw_glyph(
        &mut self,
        glyph: &Glyph<'_>,
        transform: Affine,
        glyph_transform: Affine,
        _: &Paint<'_>,
        mode: &GlyphDrawMode,
    ) {
        let Some(unicode) = glyph.as_unicode() else {
            return;
        };
        let ch = match unicode {
            BfString::Char(c) => c.to_string(),
            BfString::String(s) => s,
        };
        if ch.is_empty() {
            return;
        }

        // The CTM already carries hayro's initial transform (y-flip, `/Rotate`
        // and crop-box translation) — the exact same viewport transform
        // `render()` uses — so no extra flip here: glyph boxes land in the
        // same top-left (y-down) space as the rendered pixmap.
        let combined = transform * glyph_transform;
        let box_geom = glyph_ink_box(glyph, combined);
        // Carry the raw CTM (`transform`, before composition with
        // `glyph_transform`) into the dedupe so that two physically distinct
        // glyphs sharing the same `(ch, combined)` but at different text
        // positions are never collapsed (C01-m1). The FillStroke
        // double-dispatch uses the identical `transform` for both the Fill and
        // Stroke calls, so the genuine dedupe case is unaffected.
        self.record(ch, combined, transform, mode, box_geom);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use hayro::hayro_interpret::StrokeProps;

    fn hit(ch: &str, x: f32, y: f32, w: f32, h: f32) -> GlyphHit {
        GlyphHit {
            ch: ch.to_string(),
            x,
            y,
            w,
            h,
        }
    }

    #[test]
    fn refine_advances_merges_same_line() {
        let mut glyphs = vec![
            hit("a", 0.0, 0.0, 100.0, 10.0),
            hit("b", 12.0, 0.0, 100.0, 10.0),
        ];
        refine_advances(&mut glyphs);
        // Width replaced by the advance to the next glyph.
        assert_eq!(glyphs[0].w, 12.0);
        // Last glyph on the line keeps its original width.
        assert_eq!(glyphs[1].w, 100.0);
    }

    #[test]
    fn refine_advances_skips_next_line() {
        let mut glyphs = vec![
            hit("a", 0.0, 0.0, 5.0, 10.0),
            hit("b", 0.0, 14.0, 5.0, 10.0),
        ];
        refine_advances(&mut glyphs);
        assert_eq!(glyphs[0].w, 5.0);
    }

    #[test]
    fn refine_advances_ignores_backwards_glyphs() {
        let mut glyphs = vec![
            hit("a", 10.0, 0.0, 5.0, 10.0),
            hit("b", 2.0, 0.0, 5.0, 10.0),
        ];
        refine_advances(&mut glyphs);
        assert_eq!(glyphs[0].w, 5.0);
    }

    #[test]
    fn fillstroke_double_draw_is_deduped() {
        // hayro dispatches draw_glyph twice for TextRenderingMode::FillStroke
        // (and FillAndStrokeAndClip): first with Fill mode, then with Stroke
        // mode, both carrying the same transform. The dedupe must drop the
        // second (different mode, same glyph + transform).
        let mut c = TextCollector::new(0, 100.0, 100.0);
        let t = Affine::translate((10.0, 50.0)) * Affine::scale(12.0);
        c.record(
            "J".into(),
            t,
            t,
            &GlyphDrawMode::Fill,
            (10.0, 50.0, 8.0, 10.0),
        );
        c.record(
            "J".into(),
            t,
            t,
            &GlyphDrawMode::Stroke(StrokeProps::default()),
            (10.0, 50.0, 8.0, 10.0),
        );
        assert_eq!(c.glyphs.len(), 1, "double draw must be deduped");
        assert_eq!(c.into_page_text().text, "J");
    }

    #[test]
    fn same_mode_same_glyph_same_transform_is_kept() {
        // Two draws with the SAME mode are distinct glyphs (e.g. two ligatures
        // that map to the same unicode at the same position). The dedupe must
        // NOT drop the second — only fill↔stroke double-dispatches are deduped.
        let mut c = TextCollector::new(0, 100.0, 100.0);
        let t = Affine::translate((10.0, 50.0)) * Affine::scale(12.0);
        c.record(
            "J".into(),
            t,
            t,
            &GlyphDrawMode::Fill,
            (10.0, 50.0, 8.0, 10.0),
        );
        c.record(
            "J".into(),
            t,
            t,
            &GlyphDrawMode::Fill,
            (10.0, 50.0, 8.0, 10.0),
        );
        assert_eq!(c.glyphs.len(), 2, "same-mode draw must not be deduped");
        assert_eq!(c.into_page_text().text, "JJ");
    }

    #[test]
    fn identical_glyph_at_distinct_transforms_is_kept() {
        // Real "aa" text: same char twice, but different positions.
        let mut c = TextCollector::new(0, 100.0, 100.0);
        let t1 = Affine::translate((0.0, 0.0)) * Affine::scale(12.0);
        let t2 = Affine::translate((14.0, 0.0)) * Affine::scale(12.0);
        c.record(
            "a".into(),
            t1,
            t1,
            &GlyphDrawMode::Fill,
            (0.0, 0.0, 6.0, 9.0),
        );
        c.record(
            "a".into(),
            t2,
            t2,
            &GlyphDrawMode::Fill,
            (14.0, 0.0, 6.0, 9.0),
        );
        assert_eq!(c.glyphs.len(), 2);
        assert_eq!(c.into_page_text().text, "aa");
    }

    #[test]
    fn rotated_glyph_box_covers_ink() {
        // A 90°-rotated glyph: text runs downward in viewport space. The box
        // must still cover the ink (the old +x/-y-only box missed it entirely).
        let mut c = TextCollector::new(0, 100.0, 100.0);
        // Rotate the local frame by 90° so the advance axis points down +y.
        // The transform maps font units (1/1000 em) to viewport space, so the
        // em size is 12 / UNITS_PER_EM (see em_estimate_box).
        let t = Affine::translate((50.0, 20.0))
            * Affine::rotate(90.0f64.to_radians())
            * Affine::scale(12.0 / UNITS_PER_EM);
        let box_geom = em_estimate_box(t);
        c.record("A".into(), t, t, &GlyphDrawMode::Fill, box_geom);
        let pt = c.into_page_text();
        let r = pt.spans[0].rect;
        let (x, y, w, h) = box_geom;
        assert_eq!(r, Rect::new(x, y, w, h));
        // Ink of the rotated glyph sits around x∈[50-12, 50] (width ≈ ascent),
        // y∈[20, 20+12] (advance direction). The box must intersect that area.
        assert!(
            r.x < 50.0 && r.x + r.w > 50.0 - 12.0,
            "box {r:?} misses ink x-range"
        );
    }

    #[test]
    fn empty_collector_produces_valid_empty_page_text() {
        // A page with no text operators (blank/image-only page) must yield a
        // valid empty PageText — no panic, no spurious spans. Guards against a
        // future regression where `refine_advances` or a `spans[0]` access
        // breaks on zero glyphs (C01-n1).
        let c = TextCollector::new(0, 200.0, 200.0);
        let pt = c.into_page_text();
        assert!(pt.text.is_empty(), "text must be empty");
        assert!(pt.spans.is_empty(), "spans must be empty");
        assert_eq!(pt.page_index, 0);
        assert_eq!((pt.width, pt.height), (200.0, 200.0));
    }

    #[test]
    fn zero_size_glyph_is_skipped() {
        // A glyph whose transform collapses to exactly zero width or height
        // (e.g. `0 Tf` font size) is truly invisible and must not produce a
        // 0.5×1.0 stub span that could create a spurious detection region
        // (C01-n3).
        let mut c = TextCollector::new(0, 100.0, 100.0);
        c.record(
            "x".into(),
            Affine::IDENTITY,
            Affine::IDENTITY,
            &GlyphDrawMode::Fill,
            (10.0, 10.0, 0.0, 12.0),
        );
        c.record(
            "y".into(),
            Affine::IDENTITY,
            Affine::IDENTITY,
            &GlyphDrawMode::Fill,
            (10.0, 10.0, 12.0, 0.0),
        );
        let pt = c.into_page_text();
        assert!(pt.text.is_empty(), "zero-size glyphs must be skipped");
        assert!(pt.spans.is_empty());
    }
}
