//! PII detection (regex catalog today; NER later).

mod catalog;
mod regex_detect;
pub mod validators;

pub use regex_detect::detect_regex;

use crate::types::{DetectOptions, TextMatch};

/// Extension point for detectors: implement to add a detection strategy
/// (NER, ML classifier, …) alongside the built-in regex detector.
pub trait Detector {
    /// Run this detector on `text`, returning candidate matches.
    fn detect(&self, text: &str, opts: &DetectOptions) -> Vec<TextMatch>;
}

/// The built-in regex + validator detector.
#[derive(Debug, Clone, Copy, Default)]
pub struct RegexDetector;

impl Detector for RegexDetector {
    fn detect(&self, text: &str, opts: &DetectOptions) -> Vec<TextMatch> {
        detect_regex(text, opts)
    }
}

/// Run all enabled detectors on text.
///
/// Registration point: append new detector strategies here to include them in
/// the default detection pass.
pub fn detect(text: &str, opts: &DetectOptions) -> Vec<TextMatch> {
    let detectors: &[&dyn Detector] = &[&RegexDetector];
    detect_with(text, opts, detectors)
}

/// Run an explicit set of detectors on text. Each `Detector` is expected to
/// return non-overlapping spans; cross-detector overlaps are left intact (the
/// downstream geometry pass simply paints overlapping rectangles, which is
/// harmless visually). This keeps the dispatcher generic and testable without
/// forcing a single dedup policy on every detector strategy.
///
/// The output is sorted by `start` offset so consumers that assume sorted
/// output (e.g. a binary search by offset) work correctly across multiple
/// detectors.
pub fn detect_with(
    text: &str,
    opts: &DetectOptions,
    detectors: &[&dyn Detector],
) -> Vec<TextMatch> {
    let mut out = Vec::new();
    for d in detectors {
        out.extend(d.detect(text, opts));
    }
    out.sort_by_key(|m| m.start);
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::{Category, MatchSource};

    #[test]
    fn detect_runs_all_registered_detectors() {
        let hits = detect("Contact jane.doe@example.com", &DetectOptions::default());
        assert!(
            hits.iter().any(|h| h.category == Category::Email),
            "hits: {hits:?}"
        );
    }

    /// A mock detector that always emits a fixed match, used to verify the
    /// `detect_with` dispatcher actually invokes and merges a second detector.
    struct StubDetector;

    impl Detector for StubDetector {
        fn detect(&self, _text: &str, _opts: &DetectOptions) -> Vec<TextMatch> {
            vec![TextMatch {
                start: 0,
                end: 4,
                text: "stub".to_string(),
                category: Category::Custom,
                confidence: 0.9,
                detector_id: "stub".to_string(),
                source: MatchSource::Regex,
            }]
        }
    }

    #[test]
    fn detect_with_merges_second_detector_output() {
        let text = "Contact jane.doe@example.com";
        let opts = DetectOptions::default();
        let detectors: &[&dyn Detector] = &[&RegexDetector, &StubDetector];
        let hits = detect_with(text, &opts, detectors);
        // Both the regex email hit and the stub hit must be present.
        assert!(
            hits.iter().any(|h| h.category == Category::Email),
            "regex hit missing: {hits:?}"
        );
        assert!(
            hits.iter()
                .any(|h| h.detector_id == "stub" && h.text == "stub"),
            "stub hit missing: {hits:?}"
        );
    }
}
