//! Score native PDF text-layer quality (poor layers should fall back to OCR).
//!
//! Inspired by VeriRedact's "poor text layer → replace with OCR" behavior,
//! implemented in pure Rust without external models.

/// Assessment of extractable page text usability for detection.
#[derive(Debug, Clone, PartialEq)]
pub struct TextLayerQuality {
    /// 0.0 = unusable / empty; 1.0 = clean digital text.
    pub score: f32,
    /// Human-readable reasons the score was reduced (empty if healthy).
    pub reasons: Vec<&'static str>,
}

impl TextLayerQuality {
    /// `min_score` and below counts as poor (inclusive, so a score sitting
    /// exactly on the default threshold 0.45 is never silently skipped).
    pub fn is_poor(&self, min_score: f32) -> bool {
        self.score <= min_score
    }
}

/// Scripts that conventionally do not insert spaces between words (CJK,
/// Thai, Lao, Khmer, Myanmar, Tibetan). The whitespace-based heuristics
/// below are meaningless for them, so pages dominated by these scripts are
/// exempt.
fn is_space_less_script(c: char) -> bool {
    let c = u32::from(c);
    matches!(
        c,
        0x1100..=0x11FF      // Hangul Jamo
            | 0x2E80..=0x2EFF // CJK Radicals Supplement
            | 0x3040..=0x309F // Hiragana
            | 0x30A0..=0x30FF // Katakana
            | 0x3400..=0x4DBF // CJK Unified Ideographs Extension A
            | 0x4E00..=0x9FFF // CJK Unified Ideographs
            | 0xAC00..=0xD7AF // Hangul Syllables
            | 0x0E00..=0x0E7F // Thai
            | 0x0E80..=0x0EFF // Lao
            | 0x1000..=0x109F // Myanmar
            | 0x1780..=0x17FF // Khmer
            | 0xF900..=0xFAFF // CJK Compatibility Ideographs
            | 0x0F00..=0x0FFF // Tibetan
            | 0x20000..=0x2FA1F // CJK Unified Ideographs Extension B–F + Compat Supplement
    )
}

/// Piecewise-linear ramp from 0 (at `lo`) to 1 (at `hi`), clamped outside.
///
/// When `lo == hi` the ramp is a step: 0 below `lo`, 1 at and above `lo`.
fn ramp(value: usize, lo: usize, hi: usize) -> f32 {
    if hi <= lo {
        // Step function (also guards against divide-by-zero).
        if value < lo { 0.0 } else { 1.0 }
    } else if value <= lo {
        0.0
    } else if value >= hi {
        1.0
    } else {
        (value - lo) as f32 / (hi - lo) as f32
    }
}

/// Assess text-layer quality for PII detection / OCR fallback decisions.
///
/// Heuristics (no ML), all piecewise-linear so a 1-char or 1-percent input
/// delta cannot flip the binary OCR decision:
/// - empty / very short
/// - low letter ratio (garbage encodings, binary-ish extracts)
/// - high control / replacement-char density
/// - mojibake density (Latin-1 Supplement + combining marks)
/// - few word-like tokens / long unbroken runs (exempt only when space-less
///   scripts like CJK / Thai are a majority of the page, since those
///   legitimately have no inter-word spaces)
pub fn assess_text_layer(text: &str) -> TextLayerQuality {
    let mut reasons = Vec::new();
    let chars: Vec<char> = text.chars().collect();
    let n = chars.len();

    if n == 0 {
        return TextLayerQuality {
            score: 0.0,
            reasons: vec!["empty"],
        };
    }

    let mut score = 1.0_f32;

    // Length: continuous ramp (0.65 → 0.45 → 0.2 → 0) so n = 11 vs 12,
    // 23 vs 24 and 79 vs 80 are smooth transitions, not decision cliffs.
    if n < 12 {
        score -= 0.65 - 0.2 * (n as f32 / 12.0);
        reasons.push("tiny");
    } else if n < 24 {
        score -= 0.45 - 0.25 * ((n - 12) as f32 / 12.0);
        reasons.push("very-short");
    } else if n < 80 {
        score -= 0.2 * (1.0 - (n - 24) as f32 / 56.0);
        reasons.push("short");
    }

    let letters = chars.iter().filter(|c| c.is_alphabetic()).count();
    let digits = chars.iter().filter(|c| c.is_ascii_digit()).count();
    let spaces = chars.iter().filter(|c| c.is_whitespace()).count();
    let controls = chars
        .iter()
        .filter(|c| c.is_control() && **c != '\n' && **c != '\r' && **c != '\t')
        .count();
    let replacement = chars.iter().filter(|c| **c == '\u{FFFD}').count();
    let alnum = letters + digits;

    let letter_ratio = letters as f32 / n as f32;
    let alnum_ratio = alnum as f32 / n as f32;
    let space_ratio = spaces as f32 / n as f32;

    // Letter ratio: 0.4 at 0% → 0.15 at 15% → 0 at 35% (continuous).
    if letter_ratio < 0.15 {
        score -= 0.4 - 0.25 * (letter_ratio / 0.15);
        reasons.push("few-letters");
    } else if letter_ratio < 0.35 {
        score -= 0.15 * (1.0 - (letter_ratio - 0.15) / 0.2);
        reasons.push("low-letter-ratio");
    }

    // Alnum ratio: 0.2 at 0% → 0 at 40% (continuous).
    // Suppress when the letter-ratio penalty already fired: `letters ⊆ alnum`
    // so the two signals are correlated and would double-penalize (m3).
    let low_letter = letter_ratio < 0.35;
    if !low_letter && alnum_ratio < 0.4 {
        score -= 0.2 * (1.0 - alnum_ratio / 0.4);
        reasons.push("low-alnum");
    }

    // Mojibake: broken ToUnicode CMaps often re-decode UTF-8 bytes as
    // Latin-1, producing dense runs of Latin-1 Supplement / Latin Extended
    // chars (Ã, Â, ƒ, ³, ½ …) and stray combining marks. Clean prose —
    // even heavily accented French or Polish — rarely exceeds 20% of these.
    let mojibake = chars
        .iter()
        .filter(|c| {
            let v = u32::from(**c);
            matches!(v, 0x0080..=0x024F | 0x0300..=0x036F)
        })
        .count();
    let mojibake_ratio = mojibake as f32 / n as f32;
    if mojibake_ratio > 0.2 {
        // 0 at 20% → 0.35 at 50% (continuous).
        score -= 0.35 * ((mojibake_ratio - 0.2) / 0.3).min(1.0);
        reasons.push("mojibake");
    }

    // Control / replacement-char density: a single stray glyph on a large
    // page should be negligible, so scale the penalty by density. The cap
    // at `n` keeps the ratio ≤ 1.0 when the page is mostly corrupted.
    let bad_chars = controls + replacement;
    if bad_chars > 0 {
        let density = bad_chars.min(n) as f32 / n as f32;
        score -= 0.3 * density;
        reasons.push("control-or-replacement-chars");
    }

    // Exempt the whitespace-based heuristics only when space-less script
    // chars are a strict majority of the page. An `any()`-based exemption
    // lets a single stray CJK char flip a garbage page (no word breaks, zero
    // word-like tokens) into "healthy" and skip OCR entirely; a majority rule
    // keeps clean CJK / Thai pages exempt while garbage stays poor.
    let space_less_chars = chars.iter().filter(|c| is_space_less_script(**c)).count();
    let space_less = space_less_chars > n / 2;

    // Real prose usually has some whitespace; pure garbage often does not.
    // Ramp in both length (40 → 80 chars) and space ratio (0% → 2%) so
    // there is no 1-char or 1-percent cliff. Space-less scripts are exempt.
    let mut no_word_breaks = false;
    if !space_less && space_ratio < 0.02 {
        let space_penalty = 0.25 * ramp(n, 40, 80) * (1.0 - space_ratio / 0.02);
        if space_penalty > 0.0 {
            score -= space_penalty;
            reasons.push("no-word-breaks");
            no_word_breaks = true;
        }
    }

    // Tokenize on whitespace; count "word-like" tokens (letters, length ≥ 2).
    // Skip when the page has no word breaks: `no-word-breaks` and
    // `few-word-tokens` are correlated symptoms of the same root cause, so
    // applying both would double-penalize (m3).
    let words: Vec<&str> = text.split_whitespace().collect();
    let word_like = words
        .iter()
        .filter(|w| {
            let letters = w.chars().filter(|c| c.is_alphabetic()).count();
            // `split_whitespace` never yields empty tokens, so the guard
            // is unnecessary — kept removed for clarity.
            letters >= 2 && letters as f32 / w.chars().count() as f32 > 0.5
        })
        .count();
    if !space_less && !no_word_breaks && word_like < 3 {
        // Ramp in both length (60 → 120 chars) and token count (0 → 3).
        let word_penalty = 0.25 * ramp(n, 60, 120) * (1.0 - word_like as f32 / 3.0);
        if word_penalty > 0.0 {
            score -= word_penalty;
            reasons.push("few-word-tokens");
        }
    }

    // Long runs without spaces look like broken CMaps / sticky garbage.
    // Ramp from 0 at 80 chars to 0.2 at 160 chars (no 80/81 cliff).
    let max_run = longest_nonspace_run(&chars);
    if !space_less && max_run > 80 {
        let run_penalty = 0.2 * ramp(max_run, 80, 160);
        if run_penalty > 0.0 {
            score -= run_penalty;
            reasons.push("long-unbroken-run");
        }
    }

    // Once the running score has dropped to 0, further penalties and
    // reasons only add noise — the OCR decision is already locked in.
    if score <= 0.0 {
        return TextLayerQuality {
            score: 0.0,
            reasons,
        };
    }

    TextLayerQuality {
        score: score.clamp(0.0, 1.0),
        reasons,
    }
}

fn longest_nonspace_run(chars: &[char]) -> usize {
    let mut best = 0usize;
    let mut cur = 0usize;
    for c in chars {
        if c.is_whitespace() {
            best = best.max(cur);
            cur = 0;
        } else {
            cur += 1;
        }
    }
    best.max(cur)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn empty_is_zero() {
        let q = assess_text_layer("");
        assert_eq!(q.score, 0.0);
        assert!(q.reasons.contains(&"empty"));
    }

    #[test]
    fn clean_prose_scores_high() {
        let q = assess_text_layer(
            "Kimberly Lawrence, born on 24/05/1977, is a 46-year-old Female. \
             SSN 123-45-6789 Hospital ID HOSP12345678",
        );
        assert!(q.score >= 0.7, "score={} reasons={:?}", q.score, q.reasons);
        assert!(!q.is_poor(0.45));
    }

    #[test]
    fn garbage_scores_poor() {
        let q = assess_text_layer("\u{0001}\u{0002}%%%%$$$$####@@@@!!!!");
        assert!(q.is_poor(0.45), "score={} reasons={:?}", q.score, q.reasons);
    }

    #[test]
    fn short_blob_is_poor() {
        let q = assess_text_layer("abc");
        assert!(q.is_poor(0.45));
    }

    /// Text with `n` chars, 3 word-like tokens, spaces, no long runs:
    /// isolates the length ramp from every other heuristic.
    fn length_only_text(n: usize) -> String {
        let mut s = String::from("aa bb ");
        s.push_str(&"c".repeat(n - 6));
        s
    }

    #[test]
    fn length_boundaries_are_smooth() {
        let score = |n: usize| assess_text_layer(&length_only_text(n)).score;
        // 11 vs 12, 23 vs 24, 79 vs 80: small deltas, strictly increasing.
        assert!((score(11) - score(12)).abs() < 0.05, "11 vs 12 cliff");
        assert!((score(23) - score(24)).abs() < 0.05, "23 vs 24 cliff");
        assert!((score(79) - score(80)).abs() < 0.05, "79 vs 80 cliff");
        assert!(score(11) < score(12) && score(12) < score(24) && score(24) < score(80));
        // Anchor values at the piecewise-linear segment ends.
        assert!((score(12) - 0.55).abs() < 1e-4, "n=12: {}", score(12));
        assert!((score(24) - 0.8).abs() < 1e-4, "n=24: {}", score(24));
        assert!((score(80) - 1.0).abs() < 1e-4, "n=80: {}", score(80));
    }

    #[test]
    fn length_reasons_are_distinct() {
        // n3: "tiny" (n < 12) and "very-short" (12 ≤ n < 24) must differ.
        let q = assess_text_layer(&length_only_text(11));
        assert!(q.reasons.contains(&"tiny"));
        assert!(!q.reasons.contains(&"very-short"));
        let q = assess_text_layer(&length_only_text(12));
        assert!(q.reasons.contains(&"very-short"));
        assert!(!q.reasons.contains(&"tiny"));
        let q = assess_text_layer(&length_only_text(24));
        assert!(q.reasons.contains(&"short"));
    }

    #[test]
    fn letter_ratio_boundaries_are_smooth() {
        // 200 chars, letters + digits only: letter_ratio = letters / 200.
        let score = |letters: usize| {
            let mut s = String::new();
            s.push_str(&"a".repeat(letters));
            s.push_str(&"0".repeat(200 - letters));
            assess_text_layer(&s).score
        };
        assert!((score(29) - score(30)).abs() < 0.05, "0.145 vs 0.15 cliff");
        assert!((score(69) - score(70)).abs() < 0.05, "0.345 vs 0.35 cliff");
        assert!(score(30) < score(70));
    }

    #[test]
    fn space_ratio_boundary_is_smooth() {
        // 1000 chars, ~6 word-like tokens so `few-word-tokens` never fires.
        // The 6 "word " prefixes contribute 6 spaces; we add `extra` more so
        // that total spaces straddle 20 (= 0.02 × 1000): 13 extra → 19 spaces
        // (0.019, below threshold), 14 extra → 20 spaces (0.02, at threshold).
        // Only `no-word-breaks` is in play.
        let score = |extra: usize| {
            let prefix = "word ".repeat(6); // 30 chars, 6 spaces
            let padding = "a".repeat(970 - extra);
            let s = format!("{prefix}{padding}{}", " ".repeat(extra));
            assert_eq!(s.chars().count(), 1000, "test string must be 1000 chars");
            assess_text_layer(&s).score
        };
        // extra=13 → 19 total spaces (ratio 0.019, below 0.02 threshold)
        // extra=14 → 20 total spaces (ratio 0.020, at threshold)
        assert!((score(13) - score(14)).abs() < 0.05, "0.019 vs 0.02 cliff");
        assert!(score(14) > score(13));
    }

    #[test]
    fn max_run_boundary_is_smooth() {
        let score = |len: usize| assess_text_layer(&"a".repeat(len)).score;
        assert!((score(80) - score(81)).abs() < 0.05, "80→81 cliff");
        assert!((score(81) - score(82)).abs() < 0.05);
        assert!(score(80) > score(82));
    }

    #[test]
    fn exact_min_score_counts_as_poor() {
        // n1: the boundary is inclusive.
        let q = TextLayerQuality {
            score: 0.45,
            reasons: vec![],
        };
        assert!(q.is_poor(0.45));
        let q = TextLayerQuality {
            score: 0.45_f32 + 1e-6_f32,
            reasons: vec![],
        };
        assert!(!q.is_poor(0.45));
    }

    #[test]
    fn all_digits_score_poor() {
        let q = assess_text_layer(&"0123456789".repeat(8)); // 80 chars
        assert!(q.is_poor(0.45), "score={} reasons={:?}", q.score, q.reasons);
        assert!(q.reasons.contains(&"few-letters"));
    }

    #[test]
    fn whitespace_only_scores_poor() {
        let q = assess_text_layer(&" ".repeat(30));
        assert!(q.is_poor(0.45), "score={} reasons={:?}", q.score, q.reasons);
    }

    #[test]
    fn single_stray_char_keeps_clean_page_usable() {
        // One replacement / control char in an otherwise clean page must not
        // trigger OCR on its own: the density-based penalty makes a single
        // stray glyph negligible (m2).
        let base = "Kimberly Lawrence, born on 24/05/1977, is a 46-year-old Female. \
                    SSN 123-45-6789 Hospital ID HOSP12345678";
        assert!(base.chars().count() >= 100, "test text too short");
        let q = assess_text_layer(&format!("{base}\u{FFFD}"));
        assert!(q.score >= 0.95, "score={}", q.score);
        assert!(!q.is_poor(0.45));
        let q = assess_text_layer(&format!("{base}\u{0001}"));
        assert!(q.score >= 0.95, "score={}", q.score);
        assert!(!q.is_poor(0.45));
    }

    #[test]
    fn clean_cjk_scores_high() {
        // m1: Han / Kana text has no inter-word spaces; whitespace-based
        // penalties must not make a clean native layer look poor.
        let zh = "这是一个用于测试的干净中文句子，包含个人信息例如姓名和电话号码，\
                  该页面不需要光学字符识别，因为文本图层质量良好，可以直接用于检测。\
                  中文不使用空格分词，因此空白相关的质量指标不应误判。";
        let q = assess_text_layer(zh);
        assert!(q.score >= 0.9, "score={} reasons={:?}", q.score, q.reasons);
        assert!(!q.is_poor(0.45));
        let ja = "これは日本語のテキストレイヤーで、ひらがなとカタカナと漢字が含まれています。\
                  日本語の文章は空白を使わないため、品質評価では空白ベースの指標を適用しません。";
        let q = assess_text_layer(ja);
        assert!(q.score >= 0.9, "score={} reasons={:?}", q.score, q.reasons);
        assert!(!q.is_poor(0.45));
    }

    #[test]
    fn clean_thai_scores_high() {
        let th = "นี่คือประโยคภาษาไทยที่สะอาดสำหรับการทดสอบคุณภาพของชั้นข้อความและตัวเลขหนึ่งสองสามสี่ห้า";
        let q = assess_text_layer(th);
        assert!(q.score >= 0.9, "score={} reasons={:?}", q.score, q.reasons);
        assert!(!q.is_poor(0.45));
    }

    #[test]
    fn stray_cjk_char_does_not_exempt_garbage_page() {
        // m7: one stray CJK char must not exempt a garbage page from the
        // whitespace-based penalties (the exemption is majority-based, not
        // any()-based) — otherwise garbage flips to "healthy" and skips OCR.
        let garbage = format!("{}日", "%%%%$$$$####@@@@!!!!".repeat(3)); // 72 junk + 1 CJK
        let q = assess_text_layer(&garbage);
        assert!(q.is_poor(0.45), "score={} reasons={:?}", q.score, q.reasons);
        assert!(
            q.reasons.contains(&"no-word-breaks")
                || q.reasons.contains(&"few-word-tokens")
                || q.reasons.contains(&"long-unbroken-run"),
            "whitespace penalties must still fire: {:?}",
            q.reasons
        );
    }

    #[test]
    fn majority_space_less_page_keeps_exemption() {
        // A page dominated by a space-less script (long unbroken run, no
        // spaces) stays exempt under the majority rule.
        let cjk = "日本語のテキストレイヤー品質評価テスト".repeat(5); // 95 chars, no spaces
        let q = assess_text_layer(&cjk);
        assert!(
            !q.reasons.contains(&"no-word-breaks")
                && !q.reasons.contains(&"few-word-tokens")
                && !q.reasons.contains(&"long-unbroken-run"),
            "space-less majority must stay exempt: {:?}",
            q.reasons
        );
        assert!(
            !q.is_poor(0.45),
            "score={} reasons={:?}",
            q.score,
            q.reasons
        );
    }

    #[test]
    fn mojibake_scores_poor() {
        // m2: broken ToUnicode CMap emitting UTF-8-as-Latin-1 mojibake.
        let q = assess_text_layer("LÃƒÂ³pez GarcÃƒÂ\u{AD}a");
        assert!(q.is_poor(0.45), "score={} reasons={:?}", q.score, q.reasons);
        assert!(q.reasons.contains(&"mojibake"));
    }

    #[test]
    fn mojibake_penalty_is_continuous() {
        // 50 chars, 10 vs 11 mojibake chars → ratio 0.2 vs 0.22.
        let score = |moj: usize| {
            let mut s = String::from("a");
            s.push_str(&"Ã".repeat(moj));
            s.push_str(&"a".repeat(49 - moj));
            assess_text_layer(&s).score
        };
        assert!((score(10) - score(11)).abs() < 0.05, "0.2 vs 0.22 cliff");
        assert!(score(10) > score(11));
        // Boundary itself is penalty-free.
        assert!((score(10) - score(9)).abs() < 1e-4);
    }

    #[test]
    fn heavy_mojibake_hits_full_penalty() {
        let q = assess_text_layer(&"ÃÂƒ³".repeat(20)); // 80 chars, all mojibake
        assert!(q.is_poor(0.45), "score={} reasons={:?}", q.score, q.reasons);
        assert!(q.reasons.contains(&"mojibake"));
    }

    #[test]
    fn clean_accented_latin_scores_high() {
        // m6: legitimate Vietnamese/Czech prose with many precomposed
        // diacritics in 0x0100–0x024F must not be falsely flagged as mojibake.
        let vi = "Nguyễn Thị Kimberly sinh ngày hai tư tháng năm một chín bảy bảy, \
                  là một bệnh nhân nữ bốn sáu tuổi, số bảo hiểm xã hội một hai ba bốn \
                  năm sáu bảy tám chín, mã bệnh viện HOSP12345678.";
        let q = assess_text_layer(vi);
        assert!(
            !q.reasons.contains(&"mojibake"),
            "score={} reasons={:?}",
            q.score,
            q.reasons
        );
        assert!(
            !q.is_poor(0.45),
            "score={} reasons={:?}",
            q.score,
            q.reasons
        );

        let cs = "Paní Kimberlyová Svobodná, narozená čtyřiadvátého května jedna \
                  tisíc devět set sedmdesát sedm, je šestačtyřicetiletá žena. \
                  Rodné číslo jedna dva tři čtyři pět šest sedm osm devět.";
        let q = assess_text_layer(cs);
        assert!(
            !q.reasons.contains(&"mojibake"),
            "score={} reasons={:?}",
            q.score,
            q.reasons
        );
        assert!(
            !q.is_poor(0.45),
            "score={} reasons={:?}",
            q.score,
            q.reasons
        );
    }

    #[test]
    fn long_unbroken_run_fires_isolated() {
        // Normal prose (good letter ratio, word breaks, many word-like
        // tokens) but with one 120-char non-space token injected. Only the
        // `long-unbroken-run` reason should fire.
        let long_token = "x".repeat(120);
        let text = format!(
            "Kimberly Lawrence born on 24/05/1977 is a patient {long_token} \
             with SSN 123-45-6789 and hospital ID HOSP12345678 today."
        );
        let q = assess_text_layer(&text);
        assert!(
            q.reasons.contains(&"long-unbroken-run"),
            "score={} reasons={:?}",
            q.score,
            q.reasons
        );
        // Score should be reduced but not poor (single heuristic).
        assert!(
            !q.is_poor(0.45),
            "score={} reasons={:?}",
            q.score,
            q.reasons
        );
        assert!(q.score < 1.0, "score should be reduced: {}", q.score);
    }
}
