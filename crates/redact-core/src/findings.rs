//! Reviewable findings JSON (detect → human edit → redact).

use serde::{Deserialize, Serialize};

use crate::error::{RedactError, Result};
use crate::types::{Category, MatchSource, Rect, Region, TextMatch};

/// Reviewable findings JSON produced by `detect` and consumed by `redact`/
/// `verify`.
///
/// **Warning:** this file contains plaintext matches (e.g. `"123-45-6789"`)
/// so a human reviewer can audit what was detected. It is an *intermediate*
/// artifact — delete or securely store it after review; unlike the
/// certificate, it is never free of secret material.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FindingsFile {
    pub version: u32,
    pub source: SourceInfo,
    pub items: Vec<FindingItem>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SourceInfo {
    pub path: Option<String>,
    pub sha256: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FindingItem {
    pub id: String,
    pub page: usize,
    pub text: String,
    pub category: String,
    pub confidence: f32,
    pub source: String,
    pub rects: Vec<Rect>,
    pub included: bool,
    /// True when a detector hit could not be mapped to glyph geometry (text
    /// layer without usable spans, sticky-glue failure). Such items always
    /// carry `included: false` and empty `rects`: they exist so a detection
    /// that cannot be painted is *surfaced* to the human reviewer instead of
    /// vanishing silently (C10-M1). Older findings files without the field
    /// deserialize with `false`.
    #[serde(default)]
    pub unmapped: bool,
    /// Provenance: which detector fired this hit (e.g. `"regex:ssn-dashed"`).
    /// Useful for a human reviewer auditing *why* a match was produced —
    /// especially for unmapped items, where the reviewer must decide
    /// manually. `from_regions` (the legacy path) has no match object and
    /// leaves this `None`; `from_detect` populates it from `TextMatch`.
    /// Older findings files without the field deserialize with `None`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub detector_id: Option<String>,
}

impl FindingsFile {
    pub fn from_regions(
        source_path: Option<String>,
        source_sha256: String,
        regions: &[Region],
    ) -> Result<Self> {
        // `detector_ids` is `None` here, so `from_detect`'s length-mismatch
        // check cannot fire; the `Result` is part of the API contract so the
        // legacy path cannot diverge from `from_detect`'s error behavior.
        Self::from_detect(source_path, source_sha256, regions, &[], None)
    }

    /// Build a findings file from a detect pass, surfacing detector hits that
    /// could not be mapped to glyph geometry as excluded (`included: false`,
    /// `unmapped: true`, empty rects) items. Without this, an unmappable hit
    /// would be silently absent from the findings JSON and the human reviewer
    /// would never learn a secret was found but could not be painted
    /// (C10-M1). `unmapped` entries are `(page_index, match)` pairs.
    ///
    /// `detector_ids` optionally carries provenance (`detector_id`) for each
    /// *mapped* region, parallel to `regions` (same length or `None`; a
    /// length mismatch is a hard error — see below). The `Region` struct
    /// itself does not carry `detector_id`, so this side channel threads the
    /// originating detector through to the JSON so a human reviewer can audit
    /// *why* a mapped match was produced — not just the unmapped ones
    /// (C09-m1).
    ///
    /// # Errors
    ///
    /// Returns [`RedactError::Findings`] when `detector_ids` is supplied but
    /// its length differs from `regions.len()`. Detector provenance is the
    /// audit feature (C09-m1), so a mismatch must fail loudly instead of
    /// silently dropping provenance for trailing regions (or silently
    /// ignoring extra ids).
    pub fn from_detect(
        source_path: Option<String>,
        source_sha256: String,
        regions: &[Region],
        unmapped: &[(usize, TextMatch)],
        detector_ids: Option<&[String]>,
    ) -> Result<Self> {
        if let Some(ids) = detector_ids
            && ids.len() != regions.len()
        {
            return Err(RedactError::Findings(format!(
                "detector_ids length {} does not match regions length {} \
                 (detector provenance must be parallel to regions; a \
                 mismatch would silently drop or misattribute provenance \
                 — C09-m1)",
                ids.len(),
                regions.len()
            )));
        }
        let mut items: Vec<FindingItem> = regions
            .iter()
            .enumerate()
            .map(|(i, r)| FindingItem {
                id: format!("{}", i + 1),
                page: r.page_index,
                text: r.source_text.clone(),
                category: r.category.as_str().to_string(),
                // A non-finite confidence from a custom detector must not
                // serialize to JSON null and break the round-trip — the same
                // guard the unmapped branch applies below. A mapped hit with
                // a bogus confidence would otherwise produce a findings file
                // `from_json` cannot parse back ('invalid type: null,
                // expected f32') and `to_regions`' range check would never
                // run.
                confidence: if r.confidence.is_finite() {
                    r.confidence
                } else {
                    0.0
                },
                source: r.source.as_str().to_string(),
                rects: r.rects.clone(),
                included: r.included,
                unmapped: false,
                detector_id: detector_ids
                    .and_then(|ids| ids.get(i))
                    .filter(|s| !s.is_empty())
                    .cloned(),
            })
            .collect();
        // Unmapped hits continue the 1-based id sequence after the mapped items.
        for (i, (page, m)) in unmapped.iter().enumerate() {
            items.push(FindingItem {
                id: format!("{}", regions.len() + 1 + i),
                page: *page,
                text: m.text.clone(),
                category: m.category.as_str().to_string(),
                // A non-finite confidence from a custom detector must not
                // serialize to JSON null and break the round-trip.
                confidence: if m.confidence.is_finite() {
                    m.confidence
                } else {
                    0.0
                },
                source: m.source.as_str().to_string(),
                rects: Vec::new(),
                included: false,
                unmapped: true,
                detector_id: Some(m.detector_id.clone()),
            });
        }
        Ok(Self {
            version: 1,
            source: SourceInfo {
                path: source_path,
                sha256: source_sha256,
            },
            items,
        })
    }

    pub fn to_regions(&self) -> Result<Vec<Region>> {
        let mut regions = Vec::with_capacity(self.items.len());
        let mut seen_ids = std::collections::HashSet::new();
        for it in &self.items {
            if it.id.is_empty() {
                return Err(RedactError::Findings(
                    "item id must be non-empty (ids identify findings in errors and \
                     the certificate)"
                        .into(),
                ));
            }
            if !seen_ids.insert(it.id.as_str()) {
                return Err(RedactError::Findings(format!(
                    "duplicate item id {:?} (ids must be unique after human edits)",
                    it.id
                )));
            }
            // A finite f64 that overflows f32 (e.g. 1e300) deserializes to
            // f32::INFINITY without error, and negative / >1.0 values pass
            // through verbatim; all would break the JSON round-trip and are
            // meaningless confidences. This runs for *every* item (including
            // unmapped ones) so a hand-edited file cannot carry a bogus
            // confidence even on an advisory item.
            if !it.confidence.is_finite() || !(0.0..=1.0).contains(&it.confidence) {
                return Err(RedactError::Findings(format!(
                    "item {}: confidence {} out of range (must be finite, 0.0..=1.0)",
                    it.id, it.confidence
                )));
            }
            // Category/source are validated for *every* item (including
            // unmapped ones) so a hand-edited advisory item cannot carry an
            // invalid category/source string that would only be caught for
            // mapped items — the same reasoning as the confidence range check
            // above. The parsed values are reused for the mapped `Region`.
            let category = parse_category(&it.category).ok_or_else(|| {
                RedactError::Findings(format!(
                    "item {}: unknown category {:?}",
                    it.id, it.category
                ))
            })?;
            let source = parse_source(&it.source).ok_or_else(|| {
                RedactError::Findings(format!("item {}: unknown source {:?}", it.id, it.source))
            })?;
            // Unmapped items are informational only: they carry no geometry,
            // so they can never be painted. Skipping them keeps the review
            // workflow honest, and including one is refused outright (it would
            // silently redact nothing while looking included).
            if it.unmapped {
                if it.included {
                    return Err(RedactError::Findings(format!(
                        "item {}: unmapped finding cannot be included (it has no \
                         geometry to redact — the detector hit could not be mapped)",
                        it.id
                    )));
                }
                // An unmapped item means "no geometry" — a hand-edited file
                // carrying rects here is internally inconsistent and confusing
                // to a reviewer (the rects would never be painted anyway).
                if !it.rects.is_empty() {
                    return Err(RedactError::Findings(format!(
                        "item {}: unmapped finding must not carry rects \
                         (unmapped means no geometry was produced)",
                        it.id
                    )));
                }
                continue;
            }
            // An included item with no rects paints nothing and still "verifies"
            // clean (text removal is vacuous on image-only output) — a deleted or
            // truncated rect array must fail loudly, not leave the secret visible.
            if it.included && it.rects.is_empty() {
                return Err(RedactError::Findings(format!(
                    "item {}: included finding has no rects (an empty rect array \
                     would silently redact nothing)",
                    it.id
                )));
            }
            for rect in &it.rects {
                if !rect.is_valid() {
                    return Err(RedactError::Findings(format!(
                        "item {}: invalid rect {rect:?} \
                         (x/y/w/h must be finite, width and height > 0, \
                         magnitudes ≤ {})",
                        it.id,
                        crate::types::MAX_RECT_MAGNITUDE
                    )));
                }
            }
            regions.push(Region {
                page_index: it.page,
                rects: it.rects.clone(),
                source_text: it.text.clone(),
                category,
                confidence: it.confidence,
                included: it.included,
                source,
            });
        }
        Ok(regions)
    }

    /// Refuse to apply findings geometry to a different input than the one the
    /// file was produced from. The recorded `source.sha256` is otherwise dead
    /// data: stale rectangles would silently redact shifted content and leave
    /// new occurrences visible.
    pub fn check_source_sha256(&self, actual: &str) -> Result<()> {
        // Case-insensitive comparison: a human editor may accidentally change
        // the case of the hash. Normalize both sides to lowercase.
        if !self.source.sha256.eq_ignore_ascii_case(actual) {
            return Err(RedactError::Findings(format!(
                "findings file was produced for a different input \
                 (source.sha256 {} != input sha256 {actual})",
                self.source.sha256
            )));
        }
        Ok(())
    }

    pub fn to_json(&self) -> Result<String> {
        serde_json::to_string_pretty(self).map_err(|e| RedactError::Findings(e.to_string()))
    }

    pub fn from_json(s: &str) -> Result<Self> {
        let f: FindingsFile =
            serde_json::from_str(s).map_err(|e| RedactError::Findings(e.to_string()))?;
        if f.version != 1 {
            return Err(RedactError::Findings(format!(
                "unsupported findings version {} (expected 1)",
                f.version
            )));
        }
        Ok(f)
    }
}

/// All `Category` variants — a single source of truth used by
/// [`parse_category`] so the reverse-lookup cannot drift from `as_str()`.
const ALL_CATEGORIES: &[Category] = &[
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

fn parse_source(s: &str) -> Option<MatchSource> {
    // Reverse-lookup over `as_str()` labels so this can never drift from the
    // enum's own string mapping (n2).
    [MatchSource::Regex, MatchSource::Manual, MatchSource::Search]
        .into_iter()
        .find(|v| v.as_str() == s)
}

fn parse_category(s: &str) -> Option<Category> {
    // Reverse-lookup over variant `as_str()` labels so the only duplication
    // is the variant list itself (not string literals); a drift guard test
    // cross-checks against `Category::all_str()` (n2).
    ALL_CATEGORIES.iter().copied().find(|c| c.as_str() == s)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_region() -> Region {
        Region {
            page_index: 0,
            rects: vec![Rect::new(10.0, 20.0, 30.0, 4.0)],
            source_text: "123-45-6789".into(),
            category: Category::Ssn,
            confidence: 0.9,
            included: true,
            source: MatchSource::Regex,
        }
    }

    #[test]
    fn regions_round_trip_through_json() {
        let f = FindingsFile::from_regions(
            Some("input.pdf".into()),
            "deadbeef".into(),
            &[sample_region()],
        )
        .unwrap();
        let json = f.to_json().unwrap();
        assert!(json.contains("\"version\": 1"));
        let back = FindingsFile::from_json(&json).unwrap();
        let regions = back.to_regions().unwrap();
        assert_eq!(regions.len(), 1);
        assert_eq!(regions[0].source_text, "123-45-6789");
        assert_eq!(regions[0].category, Category::Ssn);
        assert_eq!(regions[0].rects, vec![Rect::new(10.0, 20.0, 30.0, 4.0)]);
        assert_eq!(regions[0].confidence, 0.9);
        assert_eq!(regions[0].source, MatchSource::Regex);
    }

    #[test]
    fn source_round_trips_through_json() {
        // n1: OCR/search/manual findings must not be relabeled "regex".
        let mut r = sample_region();
        r.source = MatchSource::Search;
        let f = FindingsFile::from_regions(None, "x".into(), &[r]).unwrap();
        assert!(f.to_json().unwrap().contains("\"source\": \"search\""));
        let back = FindingsFile::from_json(&f.to_json().unwrap()).unwrap();
        assert_eq!(back.to_regions().unwrap()[0].source, MatchSource::Search);
    }

    #[test]
    fn rejects_unknown_version() {
        let json = r#"{"version": 2, "source": {"path": null, "sha256": "x"}, "items": []}"#;
        let err = FindingsFile::from_json(json).unwrap_err();
        assert!(matches!(err, RedactError::Findings(_)));
    }

    #[test]
    fn rejects_unknown_category() {
        // Valid rect + confidence so the failure is specifically the category.
        let json = r#"{
            "version": 1,
            "source": {"path": null, "sha256": "x"},
            "items": [{"id": "1", "page": 0, "text": "t", "category": "catgory",
                       "confidence": 0.5, "source": "regex",
                       "rects": [{"x": 1.0, "y": 2.0, "w": 4.0, "h": 3.0}],
                       "included": true}]
        }"#;
        let f = FindingsFile::from_json(json).unwrap();
        let err = f.to_regions().unwrap_err();
        assert!(matches!(err, RedactError::Findings(_)));
    }

    #[test]
    fn rejects_non_positive_rect() {
        // NaN / negative / zero width rects must be rejected at load time,
        // not silently painted as nothing (leaving the secret visible).
        for rect in [
            "{\"x\": 1.0, \"y\": 2.0, \"w\": 0.0, \"h\": 3.0}",
            "{\"x\": 1.0, \"y\": 2.0, \"w\": -4.0, \"h\": 3.0}",
            "{\"x\": 1.0, \"y\": 2.0, \"w\": 4.0, \"h\": -3.0}",
        ] {
            let json = format!(
                r#"{{"version": 1, "source": {{"path": null, "sha256": "x"}},
                    "items": [{{"id": "1", "page": 0, "text": "t", "category": "ssn",
                               "confidence": 0.5, "source": "regex",
                               "rects": [{rect}], "included": true}}]}}"#
            );
            let f = FindingsFile::from_json(&json).unwrap();
            let err = f.to_regions().unwrap_err();
            assert!(
                matches!(err, RedactError::Findings(_)),
                "rect {rect} must be rejected, got {err:?}"
            );
        }
    }

    #[test]
    fn rejects_non_numeric_rect_field() {
        // A non-numeric rect field (e.g. a string "NaN") is not valid JSON for
        // an f32 and must be rejected at parse time, not silently coerced.
        let json = r#"{"version": 1, "source": {"path": null, "sha256": "x"},
            "items": [{"id": "1", "page": 0, "text": "t", "category": "ssn",
                       "confidence": 0.5, "source": "regex",
                       "rects": [{"x": "NaN", "y": 2.0, "w": 4.0, "h": 3.0}],
                       "included": true}]}"#;
        let err = FindingsFile::from_json(json).unwrap_err();
        assert!(
            matches!(err, RedactError::Findings(_)),
            "non-numeric rect field must be rejected, got {err:?}"
        );
    }

    #[test]
    fn parses_all_known_categories() {
        // Every variant must round-trip through its `as_str()` label. The
        // list is cross-checked against `Category::all_str()` so a new
        // variant can never silently drop out of this test (n1: previously
        // `RoutingNumber` — the only hyphenated label — was missing here).
        for c in [
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
        ] {
            assert_eq!(parse_category(c.as_str()), Some(c), "{}", c.as_str());
        }
        // Guard against drift: every value in `all_str()` must parse.
        for s in Category::all_str() {
            assert!(parse_category(s).is_some(), "{s:?} must round-trip");
        }
        assert_eq!(parse_category("bogus"), None);
    }

    #[test]
    fn rejects_included_item_with_empty_rects() {
        // m1: an included item with no rects would paint nothing and still
        // "verify" clean (text checks are vacuous on image-only output).
        let json = r#"{"version": 1, "source": {"path": null, "sha256": "x"},
            "items": [{"id": "1", "page": 0, "text": "t", "category": "ssn",
                       "confidence": 0.5, "source": "regex",
                       "rects": [], "included": true}]}"#;
        let f = FindingsFile::from_json(json).unwrap();
        let err = f.to_regions().unwrap_err();
        assert!(
            matches!(err, RedactError::Findings(_)),
            "included empty-rect item must be rejected, got {err:?}"
        );
    }

    #[test]
    fn excluded_item_may_have_no_rects() {
        // Excluded items are never painted or verified, so an empty rect array
        // is harmless there and must not block an otherwise valid file.
        let json = r#"{"version": 1, "source": {"path": null, "sha256": "x"},
            "items": [{"id": "1", "page": 0, "text": "t", "category": "ssn",
                       "confidence": 0.5, "source": "regex",
                       "rects": [], "included": false}]}"#;
        let f = FindingsFile::from_json(json).unwrap();
        assert!(f.to_regions().is_ok());
    }

    #[test]
    fn rejects_out_of_range_confidence() {
        // m4: 1e300 overflows f32 to INFINITY without a serde error, and
        // negative / >1.0 values are accepted verbatim — all must be rejected
        // at load so the JSON round-trip can never hit "float must be finite".
        for conf in ["1e300", "-0.1", "1.5"] {
            let json = format!(
                r#"{{"version": 1, "source": {{"path": null, "sha256": "x"}},
                    "items": [{{"id": "1", "page": 0, "text": "t", "category": "ssn",
                               "confidence": {conf}, "source": "regex",
                               "rects": [{{"x": 1.0, "y": 2.0, "w": 4.0, "h": 3.0}}],
                               "included": true}}]}}"#
            );
            let f = FindingsFile::from_json(&json).unwrap();
            let err = f.to_regions().unwrap_err();
            assert!(
                matches!(err, RedactError::Findings(_)),
                "confidence {conf} must be rejected, got {err:?}"
            );
        }
    }

    #[test]
    fn rejects_duplicate_and_empty_ids() {
        // n2: ids are 1-based index strings at export; after human deletion/
        // reordering duplicates and empty ids must fail rather than mis-attribute.
        let dup = r#"{"version": 1, "source": {"path": null, "sha256": "x"},
            "items": [
                {"id": "1", "page": 0, "text": "a", "category": "ssn", "confidence": 0.5,
                 "source": "regex", "rects": [{"x": 1.0, "y": 2.0, "w": 4.0, "h": 3.0}], "included": true},
                {"id": "1", "page": 0, "text": "b", "category": "email", "confidence": 0.5,
                 "source": "regex", "rects": [{"x": 1.0, "y": 2.0, "w": 4.0, "h": 3.0}], "included": true}
            ]}"#;
        let err = FindingsFile::from_json(dup)
            .unwrap()
            .to_regions()
            .unwrap_err();
        assert!(
            matches!(err, RedactError::Findings(_)),
            "dup id, got {err:?}"
        );

        let empty = r#"{"version": 1, "source": {"path": null, "sha256": "x"},
            "items": [{"id": "", "page": 0, "text": "a", "category": "ssn", "confidence": 0.5,
                       "source": "regex", "rects": [{"x": 1.0, "y": 2.0, "w": 4.0, "h": 3.0}], "included": true}]}"#;
        let err = FindingsFile::from_json(empty)
            .unwrap()
            .to_regions()
            .unwrap_err();
        assert!(
            matches!(err, RedactError::Findings(_)),
            "empty id, got {err:?}"
        );
    }

    #[test]
    fn rejects_unknown_source() {
        let json = r#"{"version": 1, "source": {"path": null, "sha256": "x"},
            "items": [{"id": "1", "page": 0, "text": "t", "category": "ssn",
                       "confidence": 0.5, "source": "heuristik",
                       "rects": [{"x": 1.0, "y": 2.0, "w": 4.0, "h": 3.0}], "included": true}]}"#;
        let err = FindingsFile::from_json(json)
            .unwrap()
            .to_regions()
            .unwrap_err();
        assert!(matches!(err, RedactError::Findings(_)));
    }

    #[test]
    fn rejects_unknown_fields() {
        // n3: a typo'd extra key (e.g. "includded") must not be silently ignored.
        let json = r#"{"version": 1, "source": {"path": null, "sha256": "x"},
            "items": [{"id": "1", "page": 0, "text": "t", "category": "ssn",
                       "confidence": 0.5, "source": "regex",
                       "rects": [{"x": 1.0, "y": 2.0, "w": 4.0, "h": 3.0}],
                       "included": true, "includded": true}]}"#;
        let err = FindingsFile::from_json(json).unwrap_err();
        assert!(matches!(err, RedactError::Findings(_)));
    }

    #[test]
    fn rejects_mismatched_source_sha256() {
        // m2: findings recorded against one input must refuse to apply to another.
        let f = FindingsFile::from_regions(None, "abc123".into(), &[sample_region()]).unwrap();
        assert!(f.check_source_sha256("abc123").is_ok());
        let err = f.check_source_sha256("def456").unwrap_err();
        assert!(matches!(err, RedactError::Findings(_)));
    }

    fn unmapped_match(text: &str) -> (usize, crate::types::TextMatch) {
        (
            2,
            crate::types::TextMatch {
                start: 0,
                end: text.len(),
                text: text.into(),
                category: Category::Ssn,
                confidence: 0.9,
                detector_id: "regex:ssn-dashed".into(),
                source: MatchSource::Regex,
            },
        )
    }

    #[test]
    fn unmapped_hits_surface_as_excluded_items() {
        // C10-M1: a detector hit that cannot be mapped to glyph geometry must
        // appear in the findings file (excluded, marked unmapped), not vanish.
        let f = FindingsFile::from_detect(
            None,
            "sha".into(),
            &[sample_region()],
            &[unmapped_match("123-45-6789")],
            None,
        )
        .unwrap();
        assert_eq!(f.items.len(), 2);
        let u = &f.items[1];
        assert!(u.unmapped, "unmapped hit must be marked");
        assert!(!u.included, "unmapped hit must start excluded");
        assert!(u.rects.is_empty(), "unmapped hit has no geometry");
        assert_eq!(u.page, 2);
        assert_eq!(u.text, "123-45-6789");
        assert_eq!(u.category, "ssn");
        assert_eq!(
            u.detector_id.as_deref(),
            Some("regex:ssn-dashed"),
            "unmapped hit must retain detector_id provenance"
        );
        // Round-trips through JSON (the marker survives).
        let back = FindingsFile::from_json(&f.to_json().unwrap()).unwrap();
        assert!(back.items[1].unmapped);
        assert_eq!(
            back.items[1].detector_id.as_deref(),
            Some("regex:ssn-dashed")
        );
    }

    #[test]
    fn unmapped_items_are_skipped_by_to_regions() {
        let f = FindingsFile::from_detect(
            None,
            "sha".into(),
            &[sample_region()],
            &[unmapped_match("123-45-6789")],
            None,
        )
        .unwrap();
        let regions = f.to_regions().unwrap();
        assert_eq!(regions.len(), 1, "only the mapped region survives");
        assert_eq!(regions[0].source_text, "123-45-6789");
    }

    #[test]
    fn including_an_unmapped_item_is_refused() {
        // The human cannot "include" a hit with no geometry: it would silently
        // redact nothing while the cert claims it redacted.
        let f =
            FindingsFile::from_detect(None, "sha".into(), &[], &[unmapped_match("secret")], None)
                .unwrap();
        let mut f2 = f.clone();
        f2.items[0].included = true;
        let err = f2.to_regions().unwrap_err();
        assert!(matches!(err, RedactError::Findings(_)), "{err:?}");
    }

    #[test]
    fn detector_id_optional_on_old_findings_files() {
        // n2: a findings file written before `detector_id` existed must still
        // load (the field defaults to `None`).
        let json = r#"{"version": 1, "source": {"path": null, "sha256": "x"},
            "items": [{"id": "1", "page": 0, "text": "t", "category": "ssn",
                       "confidence": 0.5, "source": "regex",
                       "rects": [{"x": 1.0, "y": 2.0, "w": 4.0, "h": 3.0}],
                       "included": true}]}"#;
        let f = FindingsFile::from_json(json).unwrap();
        let regions = f.to_regions().unwrap();
        assert_eq!(regions.len(), 1);
        assert!(f.items[0].detector_id.is_none());
        // The field is skipped on serialization when `None`.
        assert!(!f.to_json().unwrap().contains("detector_id"));
    }

    #[test]
    fn rejects_bad_confidence_on_unmapped_item() {
        // n5: confidence range check now applies to unmapped items too, so a
        // hand-edited advisory item cannot carry a bogus confidence.
        let f =
            FindingsFile::from_detect(None, "sha".into(), &[], &[unmapped_match("secret")], None)
                .unwrap();
        let mut f2 = f.clone();
        f2.items[0].confidence = f32::INFINITY;
        let err = f2.to_regions().unwrap_err();
        assert!(matches!(err, RedactError::Findings(_)), "{err:?}");
    }

    #[test]
    fn rejects_bad_category_and_source_on_unmapped_item() {
        // n5: category/source validation now applies to unmapped items too —
        // a hand-edited advisory item must not pass with an invalid string
        // (previously the `continue` skipped parse_category/parse_source).
        let f =
            FindingsFile::from_detect(None, "sha".into(), &[], &[unmapped_match("secret")], None)
                .unwrap();
        let mut bad_cat = f.clone();
        bad_cat.items[0].category = "catgory".into();
        let err = bad_cat.to_regions().unwrap_err();
        assert!(matches!(err, RedactError::Findings(_)), "{err:?}");
        let mut bad_src = f.clone();
        bad_src.items[0].source = "heuristik".into();
        let err = bad_src.to_regions().unwrap_err();
        assert!(matches!(err, RedactError::Findings(_)), "{err:?}");
        // The pristine file still validates (only the mutated copies fail).
        assert!(f.to_regions().is_ok());
    }

    #[test]
    fn mapped_non_finite_confidence_is_clamped_not_serialized_as_null() {
        // A custom detector yielding NaN/Inf confidence on a *mapped* hit must
        // be clamped to 0.0 like the unmapped branch: serde_json serializes
        // non-finite f32 as JSON null, so the findings file could not be
        // parsed back ('invalid type: null, expected f32') — the exact
        // round-trip break the clamp comment claims to prevent.
        for bad_conf in [f32::NAN, f32::INFINITY, f32::NEG_INFINITY] {
            let mut r = sample_region();
            r.confidence = bad_conf;
            let f = FindingsFile::from_detect(None, "sha".into(), &[r], &[], None).unwrap();
            assert_eq!(f.items[0].confidence, 0.0, "conf {bad_conf}");
            // The clamped file round-trips through JSON and passes to_regions.
            let back = FindingsFile::from_json(&f.to_json().unwrap()).unwrap();
            assert_eq!(back.items[0].confidence, 0.0);
            assert!(back.to_regions().is_ok());
        }
        // Finite confidences pass through untouched.
        let mut r = sample_region();
        r.confidence = 0.42;
        let f = FindingsFile::from_detect(None, "sha".into(), &[r], &[], None).unwrap();
        assert_eq!(f.items[0].confidence, 0.42);
    }

    #[test]
    fn detector_ids_thread_through_for_mapped_items() {
        // C09-m1: mapped regions get detector_id provenance from the side
        // channel, and it survives the JSON round-trip.
        let ids = vec!["regex:ssn-dashed".to_string()];
        let f = FindingsFile::from_detect(None, "sha".into(), &[sample_region()], &[], Some(&ids))
            .unwrap();
        assert_eq!(f.items[0].detector_id.as_deref(), Some("regex:ssn-dashed"));
        let back = FindingsFile::from_json(&f.to_json().unwrap()).unwrap();
        assert_eq!(
            back.items[0].detector_id.as_deref(),
            Some("regex:ssn-dashed")
        );
    }

    #[test]
    fn rejects_detector_ids_length_mismatch() {
        // C09-m1: detector provenance is the audit feature, so a length
        // mismatch must be a hard error — ids.get(i) would silently drop
        // provenance for trailing regions (and silently ignore extra ids).
        let too_many = vec!["a".to_string(), "b".to_string()];
        let err =
            FindingsFile::from_detect(None, "sha".into(), &[sample_region()], &[], Some(&too_many))
                .unwrap_err();
        assert!(matches!(err, RedactError::Findings(_)), "{err:?}");

        let empty: Vec<String> = Vec::new();
        let err =
            FindingsFile::from_detect(None, "sha".into(), &[sample_region()], &[], Some(&empty))
                .unwrap_err();
        assert!(matches!(err, RedactError::Findings(_)), "{err:?}");

        // No detector_ids (None) remains valid — the legacy from_regions path.
        assert!(
            FindingsFile::from_detect(None, "sha".into(), &[sample_region()], &[], None).is_ok()
        );
    }
}
