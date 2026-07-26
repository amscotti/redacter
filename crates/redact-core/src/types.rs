use serde::{Deserialize, Serialize};

/// Axis-aligned rectangle in top-left page render coordinates (unscaled).
///
/// Origin is the top-left of the page's render viewport (same space as hayro
/// `render_dimensions`). Units are PDF points of the rendered page size.
#[derive(Debug, Clone, Copy, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Rect {
    pub x: f32,
    pub y: f32,
    pub w: f32,
    pub h: f32,
}

/// Maximum magnitude (absolute value) of a rect coordinate or extent that is
/// accepted as valid for redaction.
///
/// Larger values are rejected by [`Rect::is_valid`]: they make the
/// floor/ceil → `i32` casts in [`rect_pixel_range`] saturate (f32 values ≥
/// ~2^31 clamp to `i32::MAX`/`i32::MIN`), which can silently collapse a
/// finite "valid" rect to an empty pixel range — the secret stays visible
/// while every verify check passes. The bound is far above any real page:
/// the PDF spec caps MediaBox at 14 400 pt and the render viewport is u16
/// (≤ 65 535 px per dimension), so 1e6 px of slack is ample.
pub const MAX_RECT_MAGNITUDE: f32 = 1e6;

impl Rect {
    pub fn new(x: f32, y: f32, w: f32, h: f32) -> Self {
        Self { x, y, w, h }
    }

    /// Whether this rect is usable for redaction: finite coordinates, a
    /// strictly positive width/height, and coordinates/extents within
    /// [`MAX_RECT_MAGNITUDE`]. A `NaN`/negative/zero rect would silently
    /// paint nothing (`floor() as i32` maps NaN to 0, negative dimensions
    /// yield an empty loop), leaving the secret fully visible — and so would
    /// a finite-but-huge rect: coordinates/extents ~1e9 make the floor/ceil
    /// `as i32` casts in [`rect_pixel_range`] saturate to an empty clamped
    /// pixel range (or make `x + w` overflow to infinity), so the backstop
    /// must reject them loudly instead of silently skipping.
    pub fn is_valid(self) -> bool {
        self.x.is_finite()
            && self.y.is_finite()
            && self.w.is_finite()
            && self.h.is_finite()
            && self.w > 0.0
            && self.h > 0.0
            && self.x.abs() <= MAX_RECT_MAGNITUDE
            && self.y.abs() <= MAX_RECT_MAGNITUDE
            && self.w <= MAX_RECT_MAGNITUDE
            && self.h <= MAX_RECT_MAGNITUDE
    }

    pub fn union(self, other: Rect) -> Rect {
        let x1 = self.x.min(other.x);
        let y1 = self.y.min(other.y);
        let x2 = (self.x + self.w).max(other.x + other.w);
        let y2 = (self.y + self.h).max(other.y + other.h);
        Rect::new(x1, y1, x2 - x1, y2 - y1)
    }

    pub fn pad(self, amount: f32) -> Rect {
        Rect::new(
            self.x - amount,
            self.y - amount,
            (self.w + amount * 2.0).max(0.0),
            (self.h + amount * 2.0).max(0.0),
        )
    }

    pub fn scale(self, s: f32) -> Rect {
        Rect::new(self.x * s, self.y * s, self.w * s, self.h * s)
    }
}

/// Shared line-break predicate: two spans are on the same text line when
/// their vertical origins are within a tolerance derived from BOTH heights,
/// so a single tall span (drop cap, large header) cannot widen the tolerance
/// and glue the following line onto it.
///
/// Lives here (not in `geometry`) so both `geometry` and the engine's text
/// device share one definition without `engine` depending on `geometry` —
/// the engine layer only depends on this shared kernel plus `error`.
pub fn same_line_rects(a: Rect, b: Rect) -> bool {
    (b.y - a.y).abs() < a.h.min(b.h).max(4.0) * 0.6
}

/// Clipped integer pixel range of a rect mapped onto an image, using the same
/// floor/ceil rounding both the painter (`paint_black_rects`) and the self-check
/// (`assert_rects_black`) must share so they never disagree by a 1-pixel fringe.
///
/// Returns `(x0, y0, x1, y1)` — the half-open `[x0, x1) × [y0, y1)` pixel
/// range, clamped to `[0, img_w] × [0, img_h]`. Both endpoints are clamped, so
/// a rect fully off the page collapses to an empty range (`x0 == x1`, or
/// `y0 == y1`, at the nearest page edge) instead of returning an inverted
/// `x0 > x1` range with an out-of-bounds start. The caller validates the rect
/// (`is_valid`) before calling this helper; `NaN`/non-finite inputs are
/// rejected upstream so the `floor`/`ceil` casts are well-defined.
pub fn rect_pixel_range(rect: Rect, img_w: i32, img_h: i32) -> (i32, i32, i32, i32) {
    let x0 = rect.x.floor() as i32;
    let y0 = rect.y.floor() as i32;
    let x1 = (rect.x + rect.w).ceil() as i32;
    let y1 = (rect.y + rect.h).ceil() as i32;
    (
        x0.max(0).min(img_w),
        y0.max(0).min(img_h),
        x1.max(0).min(img_w),
        y1.max(0).min(img_h),
    )
}

/// A character/glyph span with geometry for mapping string offsets → boxes.
#[derive(Debug, Clone)]
pub struct TextSpan {
    pub start: usize,
    pub end: usize,
    pub text: String,
    pub rect: Rect,
    /// Glyph ink width before advance refinement (`None` → use `rect.w`).
    ///
    /// The text device's `refine_advances` replaces `rect.w` with the
    /// origin-to-origin advance to the next glyph on the same line, so the
    /// raw width is useless for ink-gap computation afterwards. This field
    /// preserves the pre-refine ink width so `spaced_text` can still tell
    /// real word gaps apart from the (now refined) advance.
    pub ink_w: Option<f32>,
}

/// Extracted page text plus span geometry.
#[derive(Debug, Clone, Default)]
pub struct PageText {
    pub page_index: usize,
    pub text: String,
    pub spans: Vec<TextSpan>,
    /// Unscaled render viewport (width, height) in points.
    pub width: f32,
    pub height: f32,
}

/// Source of a detection hit.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum MatchSource {
    Regex,
    Manual,
    Search,
}

impl MatchSource {
    /// Stable label used in the findings JSON `source` field.
    pub fn as_str(self) -> &'static str {
        match self {
            MatchSource::Regex => "regex",
            MatchSource::Manual => "manual",
            MatchSource::Search => "search",
        }
    }
}

/// High-level PII category (CLI filters).
///
/// The serde names must match the crate's own string vocabulary
/// ([`Category::as_str`] / [`Category::all_str`]): findings.rs
/// `parse_category` and cert.rs validation reverse-lookup serialized category
/// strings through those labels, so a serde round-trip of a [`Region`] must
/// emit a category the crate's own parser and certificate validator accept.
/// Hence `kebab-case`, not `snake_case` (`credit-card`, not `credit_card`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum Category {
    Identity,
    Contact,
    Financial,
    Dates,
    Other,
    /// Fine-grained label kept for findings display.
    Email,
    Ssn,
    Phone,
    CreditCard,
    Iban,
    RoutingNumber,
    IpAddress,
    Passport,
    Date,
    DateOfBirth,
    NationalId,
    Person,
    Custom,
}

impl Category {
    pub fn group(self) -> Category {
        match self {
            Category::Email | Category::Phone => Category::Contact,
            Category::Ssn | Category::Passport | Category::NationalId | Category::Person => {
                Category::Identity
            }
            Category::CreditCard | Category::Iban | Category::RoutingNumber => Category::Financial,
            Category::Date | Category::DateOfBirth => Category::Dates,
            other => other,
        }
    }

    pub fn as_str(self) -> &'static str {
        match self {
            Category::Identity => "identity",
            Category::Contact => "contact",
            Category::Financial => "financial",
            Category::Dates => "dates",
            Category::Other => "other",
            Category::Email => "email",
            Category::Ssn => "ssn",
            Category::Phone => "phone",
            Category::CreditCard => "credit-card",
            Category::Iban => "iban",
            Category::RoutingNumber => "routing-number",
            Category::IpAddress => "ip-address",
            Category::Passport => "passport",
            Category::Date => "date",
            Category::DateOfBirth => "date-of-birth",
            Category::NationalId => "national-id",
            Category::Person => "person",
            Category::Custom => "custom",
        }
    }

    /// All valid `as_str()` values, for validating deserialized category
    /// strings (e.g. certificate fields) against the known vocabulary.
    pub fn all_str() -> &'static [&'static str] {
        &[
            "identity",
            "contact",
            "financial",
            "dates",
            "other",
            "email",
            "ssn",
            "phone",
            "credit-card",
            "iban",
            "routing-number",
            "ip-address",
            "passport",
            "date",
            "date-of-birth",
            "national-id",
            "person",
            "custom",
        ]
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rect_pad_union_scale() {
        let a = Rect::new(10.0, 20.0, 5.0, 5.0);
        let b = Rect::new(12.0, 22.0, 5.0, 5.0);
        let u = a.union(b);
        assert!((u.x - 10.0).abs() < f32::EPSILON);
        assert!((u.w - 7.0).abs() < f32::EPSILON);
        let p = a.pad(1.0);
        assert!((p.x - 9.0).abs() < f32::EPSILON);
        assert!((p.w - 7.0).abs() < f32::EPSILON);
        let s = a.scale(2.0);
        assert!((s.x - 20.0).abs() < f32::EPSILON);
        assert!((s.w - 10.0).abs() < f32::EPSILON);
    }

    #[test]
    fn is_valid_rejects_saturating_coordinates() {
        // Finite-but-huge coordinates/extents pass the old is_finite check but
        // make the floor/ceil `as i32` casts in `rect_pixel_range` saturate to
        // an empty clamped pixel range — a "valid" rect that silently paints
        // nothing. They must be rejected up front.
        assert!(Rect::new(0.0, 0.0, 10.0, 10.0).is_valid());
        assert!(Rect::new(-1e5, 5e5, 10.0, 10.0).is_valid());
        assert!(Rect::new(1e6, 0.0, 10.0, 10.0).is_valid()); // boundary inclusive
        assert!(!Rect::new(2e9, 0.0, 5.0, 5.0).is_valid());
        assert!(!Rect::new(0.0, -2e9, 5.0, 5.0).is_valid());
        assert!(!Rect::new(-3e9, -3e9, 6e9, 6e9).is_valid());
        assert!(!Rect::new(0.0, 0.0, 5.0, 5e9).is_valid());
        assert!(!Rect::new(0.0, 0.0, 5e9, 5.0).is_valid());
        assert!(!Rect::new(1e7, 0.0, 5.0, 5.0).is_valid());
    }

    #[test]
    fn category_groups_and_labels() {
        assert_eq!(Category::Email.group(), Category::Contact);
        assert_eq!(Category::Ssn.group(), Category::Identity);
        assert_eq!(Category::CreditCard.group(), Category::Financial);
        assert_eq!(Category::DateOfBirth.group(), Category::Dates);
        assert_eq!(Category::IpAddress.group(), Category::IpAddress);
        assert_eq!(Category::Email.as_str(), "email");
        assert_eq!(Category::CreditCard.as_str(), "credit-card");
        assert_eq!(Category::Custom.as_str(), "custom");
        assert_eq!(Category::RoutingNumber.group(), Category::Financial);
        assert_eq!(Category::RoutingNumber.as_str(), "routing-number");
    }

    #[test]
    fn category_serde_round_trip_uses_as_str_labels() {
        // `Category` is public API and embedded in `Region` (serde). The serde
        // names must equal `as_str()` labels — findings.rs `parse_category`
        // and cert.rs validation reverse-lookup serialized strings via
        // `as_str()`/`all_str()`. A mismatch (e.g. snake_case "credit_card"
        // vs kebab-case "credit-card") would make a serde round-trip of a
        // `Region` emit a category the crate's own parser rejects.
        let all = [
            Category::Identity,
            Category::Contact,
            Category::Financial,
            Category::Dates,
            Category::Other,
            Category::Email,
            Category::Ssn,
            Category::Phone,
            Category::CreditCard,
            Category::Iban,
            Category::RoutingNumber,
            Category::IpAddress,
            Category::Passport,
            Category::Date,
            Category::DateOfBirth,
            Category::NationalId,
            Category::Person,
            Category::Custom,
        ];
        for c in all {
            let json = serde_json::to_string(&c).unwrap();
            assert_eq!(json, format!("\"{}\"", c.as_str()), "{c:?}");
            let back: Category = serde_json::from_str(&json).unwrap();
            assert_eq!(back, c, "{c:?}");
        }
    }

    #[test]
    fn region_serde_round_trip_keeps_parseable_category() {
        // Direct regression for the reported bug: a `Region` serialized to
        // JSON must carry a category label that findings.rs `parse_category`
        // accepts (multi-word variants are the drift risk).
        let region = Region {
            page_index: 0,
            rects: vec![Rect::new(1.0, 2.0, 3.0, 4.0)],
            source_text: "4111 1111 1111 1111".into(),
            category: Category::CreditCard,
            confidence: 0.9,
            included: true,
            source: MatchSource::Regex,
        };
        let json = serde_json::to_string(&region).unwrap();
        assert!(json.contains("\"credit-card\""), "{json}");
        let back: Region = serde_json::from_str(&json).unwrap();
        assert_eq!(back.category, region.category);
        assert_eq!(back.category.as_str(), "credit-card");
    }

    #[test]
    fn rect_pixel_range_clamps_fully_offscreen_to_empty_range() {
        // A rect fully off the right/bottom edge must not return an inverted
        // x0 > x1 range with x0 outside [0, img_w): both endpoints clamp so
        // the range collapses to x0 == x1 at the page edge.
        let r = Rect::new(2000.0, 2000.0, 100.0, 100.0);
        assert_eq!(rect_pixel_range(r, 1000, 1000), (1000, 1000, 1000, 1000));
        // Fully off the left/top edge likewise collapses (previously
        // (0, 0, -50, -50) — an inverted, negative-width range).
        let r = Rect::new(-100.0, -100.0, 50.0, 50.0);
        assert_eq!(rect_pixel_range(r, 1000, 1000), (0, 0, 0, 0));
        // On-page rounding is unchanged.
        let r = Rect::new(2.2, 3.7, 4.1, 5.9);
        assert_eq!(rect_pixel_range(r, 1000, 1000), (2, 3, 7, 10));
        // Partially off-page clamps the overflowing side only.
        let r = Rect::new(-3.0, -3.0, 10.0, 10.0);
        assert_eq!(rect_pixel_range(r, 1000, 1000), (0, 0, 7, 7));
        let r = Rect::new(995.0, 995.0, 10.0, 10.0);
        assert_eq!(rect_pixel_range(r, 1000, 1000), (995, 995, 1000, 1000));
    }

    #[test]
    fn non_finite_min_confidence_falls_back_to_default_floor() {
        // NaN must not disable the floor (`conf < NaN` is always false).
        let nan = DetectOptions {
            min_confidence: f32::NAN,
            ..DetectOptions::default()
        };
        assert_eq!(nan.effective_min_confidence(), DEFAULT_MIN_CONFIDENCE);
        // Infinite input likewise falls back instead of silently dropping all hits.
        let inf = DetectOptions {
            min_confidence: f32::INFINITY,
            ..DetectOptions::default()
        };
        assert_eq!(inf.effective_min_confidence(), DEFAULT_MIN_CONFIDENCE);
        // Finite extremes still honor user intent (aggressive clamps to 0.15).
        let neg = DetectOptions {
            min_confidence: -1.0,
            aggressive: true,
            ..DetectOptions::default()
        };
        assert_eq!(neg.effective_min_confidence(), 0.15);
    }
}

/// A detection hit in page text (before geometry mapping).
#[derive(Debug, Clone)]
pub struct TextMatch {
    pub start: usize,
    pub end: usize,
    pub text: String,
    pub category: Category,
    pub confidence: f32,
    pub detector_id: String,
    pub source: MatchSource,
}

/// A concrete redaction region on a page.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Region {
    pub page_index: usize,
    pub rects: Vec<Rect>,
    pub source_text: String,
    pub category: Category,
    pub confidence: f32,
    pub included: bool,
    /// Origin of the hit (regex detector, manual rect, or search text).
    pub source: MatchSource,
}

/// Options controlling apply / run.
#[derive(Debug, Clone)]
pub struct ApplyOptions {
    /// Render scale (2.0 ≈ 144 dpi from 72 dpi).
    pub scale: f32,
    /// Expand each rect before painting (page points, unscaled).
    pub pad: f32,
}

impl Default for ApplyOptions {
    fn default() -> Self {
        Self {
            scale: 2.0,
            // Slightly generous default so glyph boxes fully cover ink.
            pad: 1.5,
        }
    }
}

/// Default minimum confidence floor (also the fallback for non-finite input).
pub const DEFAULT_MIN_CONFIDENCE: f32 = 0.35;

/// Detection options.
#[derive(Debug, Clone)]
pub struct DetectOptions {
    pub min_confidence: f32,
    pub categories: Option<Vec<Category>>,
    /// Lower confidence floor and accept weaker unlabeled ID-shaped hits
    /// (more false positives; still reviewable via findings).
    pub aggressive: bool,
    /// OCR text-acquisition policy (feature `ocr` only). Library default is Off.
    #[cfg(feature = "ocr")]
    pub ocr: crate::ocr::OcrOptions,
}

impl Default for DetectOptions {
    fn default() -> Self {
        Self {
            min_confidence: DEFAULT_MIN_CONFIDENCE,
            categories: None,
            aggressive: false,
            #[cfg(feature = "ocr")]
            ocr: crate::ocr::OcrOptions::default(),
        }
    }
}

impl DetectOptions {
    /// Effective minimum confidence after aggressive-mode adjustment.
    ///
    /// Non-finite input (`--min-confidence nan` / `inf` parses fine at the CLI)
    /// must never silently disable the floor: `conf < NaN` is false for every
    /// pattern, which would detect everything. Fall back to the default floor.
    pub fn effective_min_confidence(&self) -> f32 {
        let base = if self.min_confidence.is_finite() {
            self.min_confidence
        } else {
            DEFAULT_MIN_CONFIDENCE
        };
        if self.aggressive {
            (base - 0.12).clamp(0.15, 1.0)
        } else {
            base
        }
    }
}
