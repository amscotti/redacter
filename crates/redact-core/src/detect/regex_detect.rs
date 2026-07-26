//! Regex + validator detector.

use super::catalog::PATTERNS;
use crate::types::{Category, DetectOptions, MatchSource, TextMatch};
use std::sync::LazyLock;

/// Run the default regex catalog on `text`.
pub fn detect_regex(text: &str, opts: &DetectOptions) -> Vec<TextMatch> {
    let mut out = Vec::new();

    for pat in PATTERNS.iter() {
        // Keywords are lowercase in the catalog; lower and tokenize them lazily
        // so patterns that never match on a page do not pay for the allocation,
        // and the per-keyword token split is not redone for every match.
        let mut keywords: Option<Vec<(String, Vec<String>)>> = None;
        for m in pat.re.find_iter(text) {
            let raw = m.as_str();
            let mut matched = raw.to_string();
            // Byte deltas describing how the sanitized text relates to the raw
            // match. When the sanitizer only shrinks from the front/back (no
            // internal character removal), the offsets are exact:
            //   start = m.start() + leading_trim
            //   end   = m.end() - trailing_trim
            // When characters are removed internally (e.g. newlines in phone
            // numbers) `internal_edit` is set so the generic substring search
            // is skipped and the full raw range is preserved instead.
            let mut leading_trim: usize = 0;
            let mut trailing_trim: usize = 0;
            let mut internal_edit = false;
            // Soft-trim sticky suffixes from raw glyph streams (lines glued together).
            if pat.id == "email" {
                if let Some(cleaned) = sanitize_email_match(&matched) {
                    (matched, leading_trim, trailing_trim) = cleaned;
                } else {
                    continue;
                }
            }
            if pat.id == "iban" {
                if let Some(cleaned) = sanitize_iban_match(&matched) {
                    matched = cleaned;
                } else {
                    continue;
                }
            }
            if pat.id == "ssn-dashed" {
                // Sticky layers glue "123-45-6789Hospital": shrink glued tails
                // so the finding/redaction covers exactly the SSN.
                if let Some(cleaned) = sanitize_ssn_match(&matched) {
                    matched = cleaned;
                } else {
                    continue;
                }
            }
            if pat.id == "age-labeled" {
                // The catalog regex consumes the char before "Age" to reject
                // "Page: 46"/"Image: 46" without lookbehind ("1977Age: 46"
                // matches "7Age: 46"); drop that prefix so the finding and
                // span cover only the labeled field.
                let trimmed = matched
                    .trim_start_matches(|c: char| !c.is_ascii_alphabetic())
                    .to_string();
                leading_trim += matched.len() - trimmed.len();
                matched = trimmed;
            }
            if pat.id == "person-born-on" || pat.id == "person-before-date" {
                if let Some(cleaned) = sanitize_person_context_match(&matched, pat.id) {
                    matched = trim_trailing_name_junk(&cleaned);
                } else {
                    continue;
                }
            }
            if pat.id == "person-labeled-spaced"
                || pat.id == "person-labeled-glued"
                || pat.id == "person-patient-name"
            {
                if let Some(cleaned) = sanitize_labeled_person_match(&matched) {
                    // Sticky layers glue the next label ("CherylBlankenshipDoctor").
                    let mut cleaned = if pat.id == "person-labeled-glued" {
                        crate::detect::validators::trim_glued_person_name(&cleaned)
                            .unwrap_or(cleaned)
                    } else {
                        cleaned
                    };
                    cleaned = trim_trailing_name_junk(&cleaned);
                    matched = cleaned;
                } else {
                    continue;
                }
            }
            if pat.id == "person-dr-title" {
                // Strip leading "Dr. " and trailing OCR junk.
                if let Some(rest) = matched
                    .strip_prefix("Dr.")
                    .or_else(|| matched.strip_prefix("Dr "))
                    .map(str::trim)
                {
                    matched = trim_trailing_name_junk(rest);
                }
            }
            if pat.id == "us-city-before-state" {
                // Keep city only: drop trailing state token(s).
                if let Some(cleaned) = strip_trailing_us_state(&matched) {
                    matched = cleaned;
                }
            }
            if pat.id == "phone-intl" || pat.id == "us-phone-bare" {
                // OCR often inserts newlines inside phone numbers.
                let cleaned: String = matched
                    .chars()
                    .filter(|c| *c != '\n' && *c != '\r')
                    .collect();
                if cleaned.len() != matched.len() {
                    // Newlines were removed (possibly internally): keep the
                    // reported range covering the whole original match so no
                    // digit falls outside it, and mark it as internally edited
                    // so the generic offset recalculation below is skipped.
                    internal_edit = true;
                }
                matched = cleaned;
            }

            // Compute `start`/`end` delimiting exactly the sanitized text so
            // offset-based consumers never over-redact around sticky tails or
            // labels. Sanitizers that only shrink from the ends expose explicit
            // trim deltas (exact offsets). When internal characters were edited
            // (phone newlines), fall back to the full raw range; otherwise the
            // cleaned text is still a substring of the raw match and its first
            // occurrence pins the offsets.
            let (start, end) = if internal_edit {
                (m.start(), m.end())
            } else if leading_trim != 0 || trailing_trim != 0 {
                (m.start() + leading_trim, m.end() - trailing_trim)
            } else if let Some(rel) = raw.find(matched.as_str()) {
                let s = m.start() + rel;
                (s, s + matched.len())
            } else {
                (m.start(), m.end())
            };

            if let Some(v) = pat.validate
                && !v(&matched)
            {
                continue;
            }

            // Category filter: cheap set-membership test that short-circuits
            // before the context-keyword window scan (to_ascii_lowercase +
            // tokenization) so filtered categories skip the expensive work.
            if let Some(cats) = &opts.categories {
                let g = pat.category.group();
                if !cats.iter().any(|c| *c == pat.category || *c == g) {
                    continue;
                }
            }

            let mut conf = pat.base_confidence;
            // Context boost: look at a window around the match. Regex offsets
            // are char boundaries, but the ±40-byte margin is not: round to
            // char boundaries so multibyte (CJK/Arabic/Hebrew) text cannot
            // panic the slice. Only lowercase the window slice (not the whole
            // page) so pages with no context-keyword patterns pay nothing.
            let window_start = floor_char_boundary(text, m.start().saturating_sub(40));
            let window_end = ceil_char_boundary(text, (m.end() + 40).min(text.len()));
            let window = &text[window_start..window_end];
            let window_lower = window.to_ascii_lowercase();
            let keywords = keywords.get_or_insert_with(|| {
                pat.context_keywords
                    .iter()
                    .map(|k| {
                        let lower = k.to_ascii_lowercase();
                        let tokens = lower
                            .split(|c: char| !c.is_ascii_alphanumeric())
                            .filter(|t| !t.is_empty())
                            .map(str::to_string)
                            .collect();
                        (lower, tokens)
                    })
                    .collect()
            });
            let has_ctx = window_has_keyword(&window_lower, keywords);
            if has_ctx {
                conf = (conf + 0.2).min(0.99);
            } else if conf < 0.5 {
                // Weak patterns without context stay weak / drop later.
            }

            // Aggressive: keep weak patterns that would otherwise drop without context.
            if opts.aggressive && conf < 0.5 && !has_ctx {
                conf = (conf + 0.08).min(0.99);
            }

            if conf < opts.effective_min_confidence() {
                continue;
            }

            out.push(TextMatch {
                start,
                end,
                text: matched,
                category: pat.category,
                confidence: conf,
                detector_id: format!("regex:{}", pat.id),
                source: MatchSource::Regex,
            });
        }
    }

    // Prefer higher confidence / longer matches when overlapping.
    out.sort_by(|a, b| {
        b.confidence
            .partial_cmp(&a.confidence)
            .unwrap_or(std::cmp::Ordering::Equal)
            .then((b.end - b.start).cmp(&(a.end - a.start)))
            .then(a.start.cmp(&b.start))
    });
    let mut kept: Vec<TextMatch> = Vec::new();
    for m in out {
        // `kept` stays sorted by start; only entries starting before m.end can
        // overlap, so the scan is bounded by the overlapping prefix. The
        // `insert` below is O(n) memmove, but `kept` only holds the
        // non-overlapping survivors (deduplicated against the confidence-sorted
        // `out`), which is small even for text-heavy pages, so the total cost
        // stays well below O(n²) in practice.
        let prefix_end = kept.partition_point(|k| k.start < m.end);
        let mut replaced = false;
        for k in &mut kept[..prefix_end] {
            if m.start == k.start && m.end == k.end && cross_family_overlap(m.category, k.category)
            {
                // Identical span with different categories that can represent
                // the same secret (e.g. bare 9-digit run matching both
                // `ssn-contiguous` and `us-aba-routing`). Keep the higher
                // confidence finding so the same span is not doubly redacted.
                if m.confidence > k.confidence
                    || (m.confidence == k.confidence
                        && category_specificity(m.category) > category_specificity(k.category))
                {
                    *k = m.clone();
                }
                replaced = true;
                break;
            }
            if m.start == k.start && m.end == k.end && same_family(m.category, k.category) {
                // Identical span: prefer the more specific category
                // (e.g. DateOfBirth over generic Date) even if it has lower confidence.
                if category_specificity(m.category) > category_specificity(k.category) {
                    *k = m.clone();
                }
                replaced = true;
                break;
            }
        }
        if replaced {
            continue;
        }
        let overlaps = kept[..prefix_end]
            .iter()
            .any(|k| m.start < k.end && same_family(m.category, k.category));
        if !overlaps {
            let pos = kept.partition_point(|k| k.start < m.start);
            kept.insert(pos, m);
        }
    }
    kept.sort_by_key(|m| m.start);
    kept
}

/// More specific categories win when two same-family matches cover the same span.
fn category_specificity(c: Category) -> u8 {
    match c {
        Category::DateOfBirth => 2,
        Category::Date => 1,
        _ => 0,
    }
}

/// Whether two matches belong to the same semantic family (and thus a
/// partial overlap should drop the lower-confidence one).
///
/// `Category::Other` is a catch-all bucket, not a real family: age, address,
/// and org patterns all share it. Two `Other`-tagged matches of unrelated PII
/// types (e.g. `age-labeled` vs `age-years-old`, or `us-zip` vs `org-corporate`)
/// must therefore never be treated as the same family, otherwise an overlap
/// would silently drop a valid finding.
fn same_family(a: Category, b: Category) -> bool {
    if a == Category::Other && b == Category::Other {
        return false;
    }
    a == b || a.group() == b.group()
}

/// Whether two *different*-category matches can represent the same secret on
/// the same span and thus must be deduplicated even though they are not
/// same-family. Currently only `Ssn` (Identity) and `RoutingNumber`
/// (Financial) share the identical `\b\d{9}\b` regex, so a bare 9-digit run
/// that passes both validators produces two same-span findings unless we
/// treat them as cross-family duplicates here.
fn cross_family_overlap(a: Category, b: Category) -> bool {
    a != b
        && matches!(
            (a, b),
            (Category::Ssn, Category::RoutingNumber) | (Category::RoutingNumber, Category::Ssn)
        )
}

/// Compiled once: trailing date (any of `/` `.` `-` separators, 2–4 digit
/// year) for `person-before-date` matches.
static BEFORE_DATE_RE: LazyLock<regex::Regex> = LazyLock::new(|| {
    regex::Regex::new(r"^(.*\S)\s+\d{1,2}[/\-.]\d{1,2}[/\-.]\d{2,4}$")
        .expect("valid before-date regex")
});

/// Round `i` down to the nearest UTF-8 char boundary in `s` (byte offset).
#[inline]
fn floor_char_boundary(s: &str, i: usize) -> usize {
    s.floor_char_boundary(i)
}

/// Round `i` up to the nearest UTF-8 char boundary in `s` (byte offset).
#[inline]
fn ceil_char_boundary(s: &str, i: usize) -> usize {
    s.ceil_char_boundary(i)
}

fn sanitize_iban_match(s: &str) -> Option<String> {
    use crate::detect::validators::iban_valid;
    // Shrink from the end until mod-97 validates (drops sticky "Notes" tails).
    // IBANs are 15–34 chars, so cap the filtered string at 34 chars + a small
    // margin before the shrink loop: a pathological long sticky tail is thus
    // O(1) validator calls instead of O(n²) (the mod-97 check is itself O(n)).
    let t: String = s
        .chars()
        .filter(|c| c.is_ascii_alphanumeric() || c.is_ascii_whitespace())
        .take(42)
        .collect();
    let mut end = t.len();
    while end >= 15 {
        if iban_valid(&t[..end]) {
            return Some(t[..end].trim().to_string());
        }
        end -= 1;
    }
    None
}

/// Keep only the name portion of "Jane Doe, born on" / "Jane Doe  01/02/2000"
/// / "Jane Doe 01.02.2000" / "Smith 24/05/1977".
fn sanitize_person_context_match(s: &str, pat_id: &str) -> Option<String> {
    let t = s.trim();
    let name = if pat_id == "person-born-on" {
        // Comma optional since the m8 fix: with a comma, split at it; without
        // one, the match is "<name> born on" — cut at the label phrase.
        t.split(',')
            .next()?
            .split("born on")
            .next()
            .unwrap_or(t)
            .trim()
    } else {
        // person-before-date: strip trailing date
        let caps = BEFORE_DATE_RE.captures(t)?;
        caps.get(1)?.as_str().trim()
    };
    if name.is_empty() {
        return None;
    }
    // A bare single-token name is fine for person-before-date (a date always
    // follows); "born on" prose needs at least two name tokens to be specific.
    if pat_id == "person-born-on" && name.split_whitespace().count() < 2 {
        return None;
    }
    Some(name.to_string())
}

fn sanitize_labeled_person_match(s: &str) -> Option<String> {
    let t = s.trim();
    // Aligned with `validators::strip_name_label`: the catalog regex accepts
    // both "Name:" and "Name :" (0+ spaces before the colon). Use a
    // case-insensitive `strip_prefix` instead of `find`+slice so the byte
    // offsets always index the original string (case-folding some Unicode
    // chars changes byte length, which would make `t[i..]` slice at the wrong
    // boundary or panic).
    for prefix in [
        "patient name:",
        "patient name :",
        "doctor name:",
        "doctor name :",
        "name:",
        "name :",
    ] {
        if let Some(rest) = t
            .strip_prefix(prefix)
            .or_else(|| {
                // Case-insensitive fallback: ASCII labels only, so a manual
                // compare is enough and stays byte-accurate.
                if t.len() >= prefix.len() && t[..prefix.len()].eq_ignore_ascii_case(prefix) {
                    Some(&t[prefix.len()..])
                } else {
                    None
                }
            })
            .map(str::trim)
            .filter(|r| !r.is_empty())
        {
            return Some(trim_trailing_name_junk(rest));
        }
    }
    None
}

/// Trailing tokens that are clearly not part of a person name.
fn is_name_stopword(s: &str) -> bool {
    s.len() <= 2
        || s.eq_ignore_ascii_case("date")
        || s.eq_ignore_ascii_case("contact")
        || s.eq_ignore_ascii_case("dob")
        || s.eq_ignore_ascii_case("ssn")
        || s.eq_ignore_ascii_case("md")
        || s.eq_ignore_ascii_case("fnp")
        || s.eq_ignore_ascii_case("fnp-c")
}

/// Drop trailing non-name tokens from OCR glue ("Martin Date", "Gallagher Contact").
fn trim_trailing_name_junk(s: &str) -> String {
    use crate::detect::validators::person_name_valid;
    let mut parts: Vec<&str> = s.split_whitespace().collect();
    while parts.len() > 2 {
        let candidate = parts.join(" ");
        if person_name_valid(&candidate) {
            // Still try dropping trailing junk if last token is stopword-like.
            if is_name_stopword(parts[parts.len() - 1]) {
                parts.pop();
                continue;
            }
            break;
        }
        parts.pop();
    }
    // One more pass: if full string invalid, shrink from end until valid or 2 tokens.
    while parts.len() >= 2 {
        let candidate = parts.join(" ");
        if person_name_valid(&candidate) {
            return candidate;
        }
        parts.pop();
    }
    // Fallback: drop trailing stopwords even if the remaining name is short.
    while let Some(last) = parts.last()
        && is_name_stopword(last)
    {
        parts.pop();
    }
    if parts.is_empty() {
        // All tokens were stopwords: return empty so the downstream `continue`
        // (empty match / validator rejection) drops this candidate rather than
        // emitting a spurious finding with the original text.
        String::new()
    } else {
        parts.join(" ")
    }
}

/// All US state names used by `strip_trailing_us_state` and by the
/// `us-city-before-state` validator. Single source of truth lives in
/// `validators::US_STATES` (shared with `validators::city_before_state_valid`,
/// which drops the trailing state from raw "City State" input).
use super::validators::US_STATES;

fn strip_trailing_us_state(s: &str) -> Option<String> {
    let t = s.trim();
    for st in US_STATES {
        // Match "City State", "City, State", or glued "CityState" (OCR): the
        // remainder after `strip_suffix` keeps the separator, so a plain trim
        // covers all three forms without allocating per state.
        let city = t
            .strip_suffix(st)
            .map(|p| p.trim().trim_end_matches([',', '.']).trim())
            .filter(|c| c.len() >= 3);
        if let Some(c) = city {
            return Some(c.to_string());
        }
    }
    None
}

/// Returns `(cleaned, leading_trim, trailing_trim)` where the trims are the
/// byte counts removed from the front/back of the raw match. Both are
/// non-negative and the cleaned email is exactly
/// `raw[leading_trim .. raw.len() - trailing_trim]`, so the caller can compute
/// exact `start`/`end` offsets without a post-hoc substring search (which is
/// fragile when the rebuilt local part legitimately re-appears earlier in the
/// raw match).
fn sanitize_email_match(s: &str) -> Option<(String, usize, usize)> {
    let (local, domain) = s.rsplit_once('@')?;
    let (host, tld) = domain.rsplit_once('.')?;
    // Prefer lowercase TLD run so sticky "comSSN" becomes "com".
    let mut tld_clean: String = tld
        .chars()
        .take_while(|c| c.is_ascii_lowercase())
        .take(24)
        .collect();
    if tld_clean.len() < 2 {
        tld_clean = tld
            .chars()
            .take_while(|c| c.is_ascii_alphabetic())
            .take(6)
            .collect();
    }
    if tld_clean.len() < 2 {
        return None;
    }
    // Sticky layers glue label words to the address ("Contactjane.doe@…"):
    // drop the glued label prefix so the finding/redaction starts at the
    // actual local part.
    let local_trimmed = trim_glued_email_prefix(local);
    let leading_trim = local.len() - local_trimmed.len();
    let trailing_trim = tld.len() - tld_clean.len();
    // Invariant: the cleaned email must be an exact substring of `s` so the
    // caller's offset recalculation (trim deltas → `raw.find` → full range)
    // always succeeds. The trim deltas already pin offsets, but assert the
    // substring invariant in debug builds so a future edit to
    // `trim_glued_email_prefix` or TLD cleaning that changes text content
    // (not just trims ends) is caught immediately.
    debug_assert!(
        s.contains(&format!("{local_trimmed}@{host}.{tld_clean}")),
        "sanitized email is not a substring of the raw match"
    );
    Some((
        format!("{local_trimmed}@{host}.{tld_clean}"),
        leading_trim,
        trailing_trim,
    ))
}

/// Drop a glued label word from the front of an email local part
/// ("Contactjane.doe" → "jane.doe", "Emailjohn.doe" → "john.doe"). The label
/// must be a real OCR field label — rendered capitalized ("Contact",
/// "EMAIL"), since text-layer glue comes from form labels — immediately
/// followed by a name-like remainder (≥ 3 chars starting with a lowercase
/// letter). Legitimate local parts that merely start with a label word in
/// lowercase ("contact123@…", "mailbox42@…", "mail@…") are never shortened,
/// so the finding span keeps the full local part.
fn trim_glued_email_prefix(local: &str) -> &str {
    const LABELS: &[&str] = &["contact", "email", "e-mail", "mail", "tel", "phone", "call"];
    for label in LABELS {
        if local.len() < label.len() {
            continue;
        }
        // OCR field labels are Title Case / ALL CAPS ("Contactjane.doe",
        // "EMAILjohn.doe"); real local parts starting with a label word are
        // lowercase ("contact123@…", "mailbox42@…") and must be left intact.
        // The email regex only matches ASCII local parts, so byte slicing is
        // on a char boundary.
        let rendered = &local[..label.len()];
        if !local.as_bytes()[0].is_ascii_uppercase() || !rendered.eq_ignore_ascii_case(label) {
            continue;
        }
        let rest = &local[label.len()..];
        // The remainder must look like a glued name: at least 3 chars
        // starting with a lowercase letter, so "Contact123@…" stays untouched.
        if rest.len() >= 3 && rest.as_bytes()[0].is_ascii_lowercase() {
            return rest;
        }
    }
    local
}

/// Shrink glued alphanumeric tails from a dashed SSN match ("123-45-6789Hospital"
/// → "123-45-6789"). Mirrors `sanitize_iban_match`: filter to the SSN charset
/// first (letters cannot be part of an SSN) then shrink from the end until the
/// validator accepts.
fn sanitize_ssn_match(s: &str) -> Option<String> {
    use crate::detect::validators::ssn_valid;
    // Shrink glued alphanumeric tails from a dashed SSN match ("123-45-6789Hospital"
    // → "123-45-6789"). Mirrors `sanitize_iban_match`: filter to the SSN charset
    // first (letters cannot be part of an SSN) then shrink from the end until the
    // validator accepts. Cap the filtered string (SSN is exactly 11 chars) so a
    // pathological long sticky tail is O(1) validator calls, not O(n²).
    let mut t: String = s
        .chars()
        .filter(|c| c.is_ascii_digit() || *c == '-')
        .take(20)
        .collect();
    while t.len() >= 9 {
        if ssn_valid(&t) {
            // The validator counts only digits; drop any trailing separator
            // the raw glue left behind ("…6789-" → "…6789").
            while t.ends_with('-') {
                t.pop();
            }
            return Some(t);
        }
        t.pop();
    }
    None
}

/// Context-keyword match on token boundaries: "date" must not match inside
/// "updated", "ip" inside "ship/trip", "age" inside "page", "born" inside
/// "corn". Splits the (already lowercased) window on non-alphanumeric runs;
/// multi-word keywords ("social security", "e-mail", "united states") must
/// appear as consecutive tokens. The keyword list arrives pre-tokenized (the
/// lowercased keyword string plus its token split) so per-match work is
/// constant per keyword.
fn window_has_keyword(window: &str, keywords: &[(String, Vec<String>)]) -> bool {
    let tokens: Vec<&str> = window
        .split(|c: char| !c.is_ascii_alphanumeric())
        .filter(|t| !t.is_empty())
        .collect();
    if tokens.is_empty() {
        return false;
    }
    keywords.iter().any(|(_, kw_tokens)| {
        if kw_tokens.len() == 1 {
            tokens.contains(&kw_tokens[0].as_str())
        } else {
            tokens.windows(kw_tokens.len()).any(|w| {
                w.iter()
                    .map(|s| &s[..])
                    .eq(kw_tokens.iter().map(|s| &s[..]))
            })
        }
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn empty_input_returns_no_matches() {
        assert!(detect_regex("", &DetectOptions::default()).is_empty());
    }

    #[test]
    fn whitespace_only_input_returns_no_matches() {
        assert!(detect_regex("   \n  \t ", &DetectOptions::default()).is_empty());
    }

    #[test]
    fn dob_context_prefers_date_of_birth_category() {
        let text = "DOB: 24/05/1977";
        let hits = detect_regex(text, &DetectOptions::default());
        let dob = hits
            .iter()
            .find(|h| matches!(h.category, Category::Date | Category::DateOfBirth))
            .expect("date hit");
        assert_eq!(dob.category, Category::DateOfBirth, "hits: {hits:?}");
    }

    #[test]
    fn plain_date_stays_generic_category() {
        let text = "Expires 24/05/2025";
        let hits = detect_regex(text, &DetectOptions::default());
        let d = hits
            .iter()
            .find(|h| matches!(h.category, Category::Date | Category::DateOfBirth))
            .expect("date hit");
        assert_eq!(d.category, Category::Date, "hits: {hits:?}");
    }

    #[test]
    fn phone_with_newline_keeps_full_range() {
        // Spaced text can contain a newline inside a phone number (OCR line break).
        let text = "Call 555-121\n23 today";
        let hits = detect_regex(text, &DetectOptions::default());
        let phone = hits
            .iter()
            .find(|h| h.category == Category::Phone && h.text == "555-12123")
            .unwrap_or_else(|| panic!("cleaned phone hit missing; hits: {hits:?}"));
        // The reported range must cover the whole original match (incl. the digit
        // after the removed newline), not just a prefix of it.
        assert_eq!(&text[phone.start..phone.end], "555-121\n23");
    }

    #[test]
    fn finds_email_and_ssn() {
        let text = "Contact jane.doe@example.com SSN 123-45-6789";
        let hits = detect_regex(text, &DetectOptions::default());
        assert!(hits.iter().any(|h| h.category == Category::Email));
        assert!(hits.iter().any(|h| h.category == Category::Ssn));
    }

    #[test]
    fn credit_card_luhn() {
        let text = "Card 4111 1111 1111 1111";
        let hits = detect_regex(text, &DetectOptions::default());
        assert!(hits.iter().any(|h| h.category == Category::CreditCard));
    }

    #[test]
    fn clinical_ids_and_ages() {
        // Sticky tokens mimic hayro text-layer glue (no spaces between fields).
        let text = "\
Kimberly Lawrence, is a 46-year-old Female.\
DOB: 24/05/1977Age: 46Sex: FemaleSSN: 567-45-5412Hospital ID: HOSP26508961Patient Lifestyle\
Doctor Unique ID:DR14144BSierra Valley\
Heart Rate: 72Respiratory Rate: 16";
        let hits = detect_regex(text, &DetectOptions::default());
        let texts: Vec<&str> = hits.iter().map(|h| h.text.as_str()).collect();
        assert!(
            texts.iter().any(|t| t.eq_ignore_ascii_case("HOSP26508961")),
            "hospital id: {texts:?}"
        );
        assert!(
            texts.iter().any(|t| t.eq_ignore_ascii_case("DR14144B")),
            "provider id: {texts:?}"
        );
        assert!(
            texts.iter().any(|t| t.eq_ignore_ascii_case("46-year-old")),
            "age phrase: {texts:?}"
        );
        assert!(
            hits.iter().any(|h| {
                h.detector_id.contains("age-labeled") && h.text.to_ascii_lowercase().contains("46")
            }),
            "labeled age: {hits:?}"
        );
        // Date fragments and vitals must not become ages.
        assert!(
            !hits.iter().any(|h| {
                h.detector_id.contains("age")
                    && (h.text == "24" || h.text == "72" || h.text == "16")
            }),
            "age false positives: {texts:?}"
        );
        // Spaced text (pipeline) recovers dashed SSNs; sticky glue can hide trailing \b.
        let spaced = text.replace("5412Hospital", "5412 Hospital");
        let spaced_hits = detect_regex(&spaced, &DetectOptions::default());
        assert!(spaced_hits.iter().any(|h| h.category == Category::Ssn));
    }

    #[test]
    fn medium_ocr_style_patient_and_address() {
        let text = "\
Patient Name:Susan Frances Martin Date O Firth : 09031951 \
Dr. Brittany Gallagher Contact \
5891 Kenneth Ports. New Amandafort. Wyoming United States- 97375 Tel: (253) 095-5181 \
577 Norman Villages, North Bradleytown, Oklahoma United States 55962 \
Susan Frances Martin, born on 09/03/1951 is a 74-year-old female \
SSN 103-15-0825 HOSP20831933 DR94303A 20102023";
        let hits = detect_regex(text, &DetectOptions::default());
        let texts: Vec<&str> = hits.iter().map(|h| h.text.as_str()).collect();
        assert!(
            texts
                .iter()
                .any(|t| t.contains("Susan") && t.contains("Martin")),
            "patient name: {texts:?}"
        );
        assert!(
            texts.contains(&"Brittany Gallagher"),
            "doctor without Contact glue: {texts:?}"
        );
        assert!(
            !texts.iter().any(|t| t.contains('\n')),
            "no newline in findings: {texts:?}"
        );
        assert!(
            texts.iter().any(|t| t.contains("Kenneth Ports")),
            "street: {texts:?}"
        );
        assert!(
            texts
                .iter()
                .any(|t| t.contains("Amandafort") || t.contains("Bradleytown")),
            "city: {texts:?}"
        );
        assert!(hits.iter().any(|h| h.category == Category::Ssn));
        assert!(hits.iter().any(|h| h.text.contains("74-year-old")));
    }

    #[test]
    fn aged_prose_and_sticky_provider_id() {
        let text = "Elizabeth Williams, born on 07/06/1949 and aged 56, is a female.\
Sierra Valley Medical Institute INCDR58463ADoctor Notes";
        let hits = detect_regex(text, &DetectOptions::default());
        assert!(
            hits.iter().any(|h| h.text.eq_ignore_ascii_case("aged 56")),
            "aged prose: {:?}",
            hits.iter().map(|h| &h.text).collect::<Vec<_>>()
        );
        assert!(
            hits.iter().any(|h| h.text.eq_ignore_ascii_case("DR58463A")),
            "sticky provider id: {:?}",
            hits.iter().map(|h| &h.text).collect::<Vec<_>>()
        );
    }

    #[test]
    fn person_and_org_patterns() {
        let text = "\
Patient SummaryKimberly Lawrence, born on 24/05/1977, is a 46-year-old Female.\
Sierra Valley Medical Institute INCPatient Demographics\
Name: KimberlyLawrenceDOB: 24/05/1977\
Doctor Name: CherylBlankenshipDoctor Unique ID:DR14144B\
HealthcareRecoveryTraumaCenterKimberly Lawrence     24/05/1977Sierra Valley";
        let hits = detect_regex(text, &DetectOptions::default());
        let persons: Vec<&str> = hits
            .iter()
            .filter(|h| h.category == Category::Person)
            .map(|h| h.text.as_str())
            .collect();
        assert!(
            persons.contains(&"Kimberly Lawrence"),
            "patient name: {persons:?}"
        );
        assert!(
            persons
                .iter()
                .any(|t| *t == "CherylBlankenship" || t.contains("Cheryl")),
            "doctor glued name: {persons:?}"
        );
        assert!(
            persons
                .iter()
                .any(|t| *t == "KimberlyLawrence" || t.contains("Kimberly")),
            "patient glued name: {persons:?}"
        );
        assert!(
            hits.iter()
                .any(|h| h.text.contains("Sierra Valley Medical Institute")),
            "org: {:?}",
            hits.iter().map(|h| &h.text).collect::<Vec<_>>()
        );
    }

    #[test]
    fn cjk_before_match_does_not_panic() {
        // Regression: the ±40-byte context window used to slice mid-UTF-8-char
        // and panic on any multibyte (CJK) text near an ASCII match.
        let text = format!("abc{}phone 555-1212", "日".repeat(14));
        let hits = detect_regex(&text, &DetectOptions::default());
        assert!(
            hits.iter().any(|h| h.category == Category::Phone),
            "hits: {hits:?}"
        );
    }

    #[test]
    fn cjk_after_match_does_not_panic() {
        let text = format!("phone 555-1212{}", "日".repeat(14));
        let hits = detect_regex(&text, &DetectOptions::default());
        assert!(hits.iter().any(|h| h.category == Category::Phone));
    }

    #[test]
    fn cjk_context_keyword_still_boosts() {
        // The context window must still find keywords when multibyte chars sit
        // between the keyword and the match.
        let text = format!("phone{}555-1212", "日".repeat(10));
        let hits = detect_regex(&text, &DetectOptions::default());
        let phone = hits
            .iter()
            .find(|h| h.category == Category::Phone)
            .expect("phone hit");
        assert!(
            phone.confidence >= 0.5,
            "expected context boost, got: {phone:?}"
        );
    }

    #[test]
    fn labeled_name_with_space_before_colon() {
        // The catalog regex accepts "Name : " (space before the colon); the
        // sanitizer must not drop it.
        let text = "Name : Jane Doe";
        let hits = detect_regex(text, &DetectOptions::default());
        assert!(
            hits.iter()
                .any(|h| h.category == Category::Person && h.text.contains("Jane")),
            "hits: {hits:?}"
        );
    }

    #[test]
    fn doctor_label_with_space_before_colon() {
        let text = "Doctor Name : Anthony Rivera";
        let hits = detect_regex(text, &DetectOptions::default());
        assert!(
            hits.iter()
                .any(|h| h.category == Category::Person && h.text.contains("Anthony")),
            "hits: {hits:?}"
        );
    }

    #[test]
    fn email_sticky_tail_span_delimited_by_offsets() {
        let text = "Contact jane.doe@example.comSSN 123-45-6789";
        let hits = detect_regex(text, &DetectOptions::default());
        let email = hits
            .iter()
            .find(|h| h.category == Category::Email)
            .unwrap_or_else(|| panic!("email hit missing: {hits:?}"));
        assert_eq!(email.text, "jane.doe@example.com");
        assert_eq!(&text[email.start..email.end], email.text);
    }

    #[test]
    fn email_label_prefix_only_trims_real_glue() {
        // Glued OCR field labels (capitalized) are still trimmed.
        assert_eq!(trim_glued_email_prefix("Contactjane.doe"), "jane.doe");
        assert_eq!(trim_glued_email_prefix("Emailjohn.doe"), "john.doe");
        assert_eq!(trim_glued_email_prefix("EMAILjohn.doe"), "john.doe");
        // Legitimate local parts that merely start with a label word are kept
        // whole — their labels are lowercase, not OCR glue.
        assert_eq!(trim_glued_email_prefix("contact123"), "contact123");
        assert_eq!(trim_glued_email_prefix("mailbox42"), "mailbox42");
        assert_eq!(trim_glued_email_prefix("mail"), "mail");
        assert_eq!(trim_glued_email_prefix("contact"), "contact");
    }

    #[test]
    fn email_local_parts_starting_with_label_words_not_mangled() {
        let text = "Contact contact123@example.com and mailbox42@x.com";
        let hits = detect_regex(text, &DetectOptions::default());
        let emails: Vec<&str> = hits
            .iter()
            .filter(|h| h.category == Category::Email)
            .map(|h| h.text.as_str())
            .collect();
        assert!(
            emails.contains(&"contact123@example.com"),
            "emails: {emails:?}"
        );
        assert!(emails.contains(&"mailbox42@x.com"), "emails: {emails:?}");
    }

    #[test]
    fn dob_iso_date_detected_as_date_of_birth() {
        // "DOB: 1951-09-03" must be caught by date-of-birth (ISO alternative),
        // not left to the generic date pattern (which has no dob/birth keyword
        // to boost it above the 0.35 floor).
        let text = "DOB: 1951-09-03";
        let hits = detect_regex(text, &DetectOptions::default());
        let dob = hits
            .iter()
            .find(|h| matches!(h.category, Category::Date | Category::DateOfBirth))
            .unwrap_or_else(|| panic!("date hit missing; hits: {hits:?}"));
        assert_eq!(dob.category, Category::DateOfBirth, "hits: {hits:?}");
        assert_eq!(dob.text, "1951-09-03");
    }

    #[test]
    fn born_on_person_span_delimited_by_offsets() {
        let text = "Kimberly Lawrence, born on 24/05/1977";
        let hits = detect_regex(text, &DetectOptions::default());
        let person = hits
            .iter()
            .find(|h| h.category == Category::Person && h.text.contains("Kimberly"))
            .unwrap_or_else(|| panic!("person hit missing: {hits:?}"));
        assert_eq!(person.text, "Kimberly Lawrence");
        assert_eq!(&text[person.start..person.end], person.text);
    }

    #[test]
    fn iban_sticky_tail_span_delimited_by_offsets() {
        let text = "IBAN GB82 WEST 1234 5698 7654 32Notes";
        let hits = detect_regex(text, &DetectOptions::default());
        let iban = hits
            .iter()
            .find(|h| h.category == Category::Iban)
            .unwrap_or_else(|| panic!("iban hit missing: {hits:?}"));
        assert_eq!(iban.text, "GB82 WEST 1234 5698 7654 32");
        assert_eq!(&text[iban.start..iban.end], iban.text);
    }

    #[test]
    fn city_before_state_trims_trailing_period() {
        let text = "New Amandafort. Wyoming United States- 97375";
        let hits = detect_regex(text, &DetectOptions::default());
        let city = hits
            .iter()
            .find(|h| h.detector_id.contains("us-city-before-state"))
            .unwrap_or_else(|| panic!("city hit missing: {hits:?}"));
        assert_eq!(city.text, "New Amandafort");
        assert_eq!(&text[city.start..city.end], city.text);
    }
}
