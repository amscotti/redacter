//! Checksum and format validators for PII patterns.

use std::sync::OnceLock;

/// SSN shape `###-##-####` — used to reject SSNs in `phone_valid`.
static SSN_SHAPE: OnceLock<regex::Regex> = OnceLock::new();
/// EIN shape `##-#######` — used to reject EINs in `phone_valid`.
static EIN_SHAPE: OnceLock<regex::Regex> = OnceLock::new();

fn ssn_shape() -> &'static regex::Regex {
    SSN_SHAPE.get_or_init(|| regex::Regex::new(r"^\d{3}-\d{2}-\d{4}$").expect("static regex"))
}

fn ein_shape() -> &'static regex::Regex {
    EIN_SHAPE.get_or_init(|| regex::Regex::new(r"^\d{2}-\d{7}$").expect("static regex"))
}

/// Email shape: local@domain.tld with alphabetic TLD (rejects sticky "comSSN").
pub fn email_valid(raw: &str) -> bool {
    let Some((local, domain)) = raw.rsplit_once('@') else {
        return false;
    };
    if local.is_empty() || domain.is_empty() {
        return false;
    }
    let Some((host, tld)) = domain.rsplit_once('.') else {
        return false;
    };
    if host.is_empty() {
        return false;
    }
    // Alphabetic TLD. Accept all-uppercase (ccTLDs like "IO", "US") and
    // capitalized/lowercase forms, but reject glued uppercase tails where the
    // characters after the first are a mix of upper- and lowercase
    // ("example.ComSSN", "example.cOm").
    let all_upper = tld.chars().all(|c| c.is_ascii_uppercase());
    let tail_ok = tld.chars().skip(1).all(|c| c.is_ascii_lowercase());
    (2..=24).contains(&tld.len())
        && tld.chars().all(|c| c.is_ascii_alphabetic())
        && (all_upper || tail_ok)
}

/// Dotted numbers look like phones when dots split the digits into 3/3/4 (US)
/// or 1-3/3/3/4 (country code) groups; anything else with dots (currency like
/// "7421.15", ratios) is not a phone.
fn dotted_phone_like(t: &str) -> bool {
    let groups: Vec<&str> = t.split('.').collect();
    if groups.len() != 3 && groups.len() != 4 {
        return false;
    }
    groups.iter().enumerate().all(|(i, g_raw)| {
        if g_raw.is_empty() {
            return false;
        }
        let g: String = g_raw
            .chars()
            .filter(|c| !matches!(c, '-' | ' ' | '(' | ')'))
            .collect();
        // A leading country-code group ("1.415.555.0132") is at most 3 digits.
        // For the 3-group US dotted format, the first group is also the area
        // code (≤ 3 digits). When separators are present within the group
        // (mixed format like "1-415"), use the more permissive limit.
        let has_sep = g_raw.chars().any(|c| matches!(c, '-' | ' ' | '(' | ')'));
        let max = if i == 0 && groups.len() == 3 && has_sep {
            4
        } else if i == 0 {
            3
        } else {
            4
        };
        !g.is_empty() && g.len() <= max && g.chars().all(|c| c.is_ascii_digit())
    })
}

/// Phone-like number; rejects SSNs, EINs, currency, and IBAN-style groups.
pub fn phone_valid(s: &str) -> bool {
    let t = s.trim();
    let digits: String = t.chars().filter(|c| c.is_ascii_digit()).collect();
    let n = digits.len();
    if !(7..=15).contains(&n) {
        return false;
    }
    // SSN ###-##-####
    if ssn_shape().is_match(t) {
        return false;
    }
    // EIN ##-#######
    if ein_shape().is_match(t) {
        return false;
    }
    // Currency / decimals (e.g. 7421.15): allow dotted phone formats like
    // 415.555.0132, but reject dotted numbers whose groups do not look like a
    // phone (fewer than 3 groups, or any group longer than 4 digits).
    if t.contains('.') && !t.contains('+') && !dotted_phone_like(t) {
        return false;
    }
    // IBAN tails look like "1234 5698 7654 32": a 2-digit last group preceded
    // by 4-digit groups. Reject only that shape so spaced phone formats
    // ("1 415 555 0132", "020 7946 0958 123", "415 555 0132 x123") pass.
    let spaced: Vec<&str> = t.split_whitespace().collect();
    if !t.contains('+') && !t.contains('(') && spaced.len() >= 3 {
        let iban_like = spaced
            .last()
            .is_some_and(|g| g.len() == 2 && g.chars().all(|c| c.is_ascii_digit()))
            && spaced[..spaced.len() - 1]
                .iter()
                .all(|g| g.len() == 4 && g.chars().all(|c| c.is_ascii_digit()));
        if iban_like {
            return false;
        }
    }
    // Require phone-like structure: leading +, parens, hyphen groups, or
    // spaced digit groups (3/3/4 US, 1-3/3/3/4 international, 4-group UK,
    // optionally with a trailing extension like "x123").
    let ext_like = |g: &str| {
        let g = g.to_ascii_lowercase();
        (g.len() >= 2 && g.starts_with('x') && g[1..].chars().all(|c| c.is_ascii_digit()))
            || (g.len() > 3 && g.starts_with("ext") && g[3..].chars().all(|c| c.is_ascii_digit()))
    };
    let structured = t.contains('+')
        || t.contains('(')
        || t.matches('-').count() >= 1
        || (spaced.len() >= 2
            && spaced.len() <= 4
            && spaced.iter().enumerate().all(|(i, g)| {
                (i == spaced.len() - 1 && ext_like(g))
                    || (!g.is_empty() && g.len() <= 4 && g.chars().all(|c| c.is_ascii_digit()))
            }))
        || (!spaced.is_empty() && n == 10 && {
            // Bare 10-digit: first digit must be 2–9 (NANP area code).
            let first = digits.as_bytes().first().copied().unwrap_or(b'0');
            first >= b'2'
        })
        || (!spaced.is_empty() && n == 11 && digits.starts_with('1') && {
            // Bare 11-digit (1 + area code): area-code lead must be 2–9.
            digits.as_bytes().get(1).copied().unwrap_or(b'0') >= b'2'
        });
    if !structured {
        return false;
    }
    // Reject all-identical-digit numbers (not real phones), mirroring the
    // guard used in luhn_valid / aba_routing_valid.
    let first_digit = digits.as_bytes().first().copied();
    if first_digit.is_some_and(|b| digits.bytes().all(|c| c == b)) {
        return false;
    }
    true
}

/// Luhn check for credit card numbers (digits only).
pub fn luhn_valid(digits: &str) -> bool {
    let digits: Vec<u32> = digits
        .chars()
        .filter(|c| c.is_ascii_digit())
        .map(|c| c.to_digit(10).unwrap())
        .collect();
    if digits.len() < 13 || digits.len() > 19 || digits.iter().all(|&d| d == digits[0]) {
        return false;
    }
    let mut sum = 0u32;
    let mut alt = false;
    for &d in digits.iter().rev() {
        let mut d = d;
        if alt {
            d *= 2;
            if d > 9 {
                d -= 9;
            }
        }
        sum += d;
        alt = !alt;
    }
    sum.is_multiple_of(10)
}

/// Per-country IBAN structure: (country code, total length, BBAN pattern).
/// Pattern chars: 'a' = ASCII alphabetic, 'd' = ASCII digit, 'n' = alphanumeric.
/// Countries not in the table fall back to the generic mod-97 check.
/// The table covers common SEPA countries; expanding it reduces the ~1/97
/// random-string false-positive rate for omitted countries.
static IBAN_SPECS: &[(&str, usize, &str)] = &[
    ("AT", 20, "dddddddddddddddd"),
    ("BE", 16, "dddddddddddd"),
    ("CH", 21, "dddddnnnnnnnnnnnn"),
    ("DE", 22, "dddddddddddddddddd"),
    ("DK", 18, "dddddddddddddd"),
    ("ES", 24, "dddddddddddddddddddd"),
    ("FI", 18, "dddddddddddddd"),
    ("FR", 27, "nnnnnnnnnnnnnnnnnnnnnnn"),
    ("GB", 22, "aaaadddddddddddddd"),
    ("IE", 22, "aaaadddddddddddddd"),
    ("IT", 27, "nddddddddddnnnnnnnnnnnn"),
    ("NL", 18, "aaaadddddddddd"),
    ("NO", 15, "ddddddddddd"),
    ("PL", 28, "ddddddddnnnnnnnnnnnnnnnn"),
    ("PT", 25, "nnnnnnnnnnnnnnnnnnnnn"),
    ("SE", 24, "dddddddddddddddddddd"),
];

/// Does the BBAN match a per-country pattern ('a'/'d'/'n' per position)?
fn bban_matches(bban: &str, pattern: &str) -> bool {
    bban.len() == pattern.len()
        && bban
            .chars()
            .zip(pattern.chars())
            .all(|(c, kind)| match kind {
                'a' => c.is_ascii_alphabetic(),
                'd' => c.is_ascii_digit(),
                'n' => c.is_ascii_alphanumeric(),
                _ => false,
            })
}

/// IBAN mod-97 validation.
pub fn iban_valid(raw: &str) -> bool {
    let s: String = raw
        .chars()
        .filter(|c| !c.is_whitespace())
        .map(|c| c.to_ascii_uppercase())
        .collect();
    if s.len() < 15 || s.len() > 34 {
        return false;
    }
    if !s.chars().take(2).all(|c| c.is_ascii_alphabetic()) {
        return false;
    }
    if !s.chars().skip(2).take(2).all(|c| c.is_ascii_digit()) {
        return false;
    }
    // Per-country BBAN structure: reject IBANs whose length or BBAN character
    // classes are impossible for their country (cuts ~1/97 random-string
    // false positives for the countries in the table).
    if let Some(&(_, expected_len, pattern)) =
        IBAN_SPECS.iter().find(|(cc, _, _)| s.starts_with(*cc))
        && (s.len() != expected_len || !bban_matches(&s[4..], pattern))
    {
        return false;
    }
    // Safe: the checks above guarantee the prefix is single-byte ASCII
    // (2 country letters + 2 check digits), so byte offset 4 is on a
    // char boundary.
    let rearranged = format!("{}{}", &s[4..], &s[..4]);
    let mut expanded = String::new();
    for c in rearranged.chars() {
        if c.is_ascii_digit() {
            expanded.push(c);
        } else if c.is_ascii_alphabetic() {
            let n = (c as u8 - b'A') as u32 + 10;
            expanded.push_str(&n.to_string());
        } else {
            return false;
        }
    }
    // mod 97 on large number
    let mut rem = 0u32;
    for ch in expanded.chars() {
        let d = ch.to_digit(10).unwrap();
        rem = (rem * 10 + d) % 97;
    }
    rem == 1
}

/// US ABA routing number checksum.
pub fn aba_routing_valid(digits: &str) -> bool {
    let d: Vec<u32> = digits
        .chars()
        .filter(|c| c.is_ascii_digit())
        .map(|c| c.to_digit(10).unwrap())
        .collect();
    if d.len() != 9 {
        return false;
    }
    let sum = 3 * (d[0] + d[3] + d[6]) + 7 * (d[1] + d[4] + d[7]) + (d[2] + d[5] + d[8]);
    sum != 0 && sum.is_multiple_of(10)
}

/// Basic SSN area/group rejection (no 000, 666, 900-999 areas; no 00 group; no 0000 serial).
/// The SSA's issued-groups sequence is not modeled, so unissued groups like
/// "123-45-6789" pass (best-effort detection). ITINs (area 900–999) are
/// explicitly out of scope; they are intentionally rejected to avoid
/// false-positive noise from unrelated 9-digit numbers in that range.
pub fn ssn_valid(raw: &str) -> bool {
    let d: String = raw.chars().filter(|c| c.is_ascii_digit()).collect();
    if d.len() != 9 {
        return false;
    }
    let area: u32 = d[0..3].parse().unwrap_or(0);
    let group: u32 = d[3..5].parse().unwrap_or(0);
    let serial: u32 = d[5..9].parse().unwrap_or(0);
    if area == 0 || area == 666 || (900..=999).contains(&area) {
        return false;
    }
    if group == 0 || serial == 0 {
        return false;
    }
    true
}

/// Age in years as a bare integer (1–120).
pub fn age_number_valid(raw: &str) -> bool {
    let t = raw.trim();
    if t.is_empty() || !t.chars().all(|c| c.is_ascii_digit()) {
        return false;
    }
    // Reject leading zeros ("05" day-of-month fragments).
    if t.len() > 1 && t.starts_with('0') {
        return false;
    }
    t.parse::<u32>()
        .map(|n| (1..=120).contains(&n))
        .unwrap_or(false)
}

/// Phrase like "46-year-old".
pub fn age_years_old_valid(raw: &str) -> bool {
    let t = raw.trim().to_ascii_lowercase();
    let Some((num, rest)) = t.split_once('-') else {
        return false;
    };
    if rest != "year-old" && rest != "years-old" {
        return false;
    }
    age_number_valid(num)
}

/// Labeled field match like "Age: 46" / "age:12".
pub fn age_labeled_valid(raw: &str) -> bool {
    let t = raw.trim();
    let lower = t.to_ascii_lowercase();
    let Some(rest) = lower.strip_prefix("age") else {
        return false;
    };
    let rest = rest.trim_start();
    let Some(rest) = rest.strip_prefix(':') else {
        return false;
    };
    age_number_valid(rest.trim())
}

/// Prose form "aged 56".
pub fn age_aged_valid(raw: &str) -> bool {
    let t = raw.trim().to_ascii_lowercase();
    let Some(rest) = t.strip_prefix("aged") else {
        return false;
    };
    age_number_valid(rest.trim())
}

/// Map a month name (abbreviation or full name, lowercase, optional trailing
/// dot stripped by the caller) to 1–12.
fn month_number(name: &str) -> Option<u32> {
    Some(match name {
        "jan" | "january" => 1,
        "feb" | "february" => 2,
        "mar" | "march" => 3,
        "apr" | "april" => 4,
        "may" => 5,
        "jun" | "june" => 6,
        "jul" | "july" => 7,
        "aug" | "august" => 8,
        "sep" | "sept" | "september" => 9,
        "oct" | "october" => 10,
        "nov" | "november" => 11,
        "dec" | "december" => 12,
        _ => return None,
    })
}

/// Upper horizon for plausible calendar years: the current year + [`MAX_YEAR_AHEAD`].
///
/// Personal-document dates (DOBs, visits, expiries — passports run 10 years)
/// never lie decades in the future, while OCR on noisy scans routinely
/// hallucinates far-future years (`05/06/2077` for a 1977 DOB). The bound is
/// clock-derived, not a fixed constant, so it cannot rot.
const MAX_YEAR_AHEAD: u32 = 15;

/// Approximate current year from the system clock (no chrono dependency).
/// Uses a 365-day year, which slightly *over*-estimates the year count — the
/// safe direction for an upper bound (it can only over-allow near the
/// boundary, never reject a legitimate near-term date).
fn current_year_approx() -> Option<u32> {
    let days = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .ok()?
        .as_secs()
        / 86_400;
    Some(1970 + (days / 365) as u32)
}

fn max_sane_year() -> u32 {
    match current_year_approx() {
        Some(now) => now.saturating_add(MAX_YEAR_AHEAD),
        // Clock unavailable (system time before epoch): fail open to the
        // legacy fixed ceiling rather than rejecting every real date.
        None => 2100,
    }
}

/// Plausible calendar-year window for a date found in a document: 1900 (old
/// DOBs/records) through the clock-derived horizon above.
fn year_in_range(year: u32) -> bool {
    (1900..=max_sane_year()).contains(&year)
}

/// Calendar date sanity (rejects OCR garbage like `15/09/023`, `05/06/2077`, month 00).
pub fn date_valid(raw: &str) -> bool {
    let t = raw.trim();
    // ISO YYYY-MM-DD
    if let Some((y, rest)) = t.split_once('-')
        && y.len() == 4
        && let Ok(year) = y.parse::<u32>()
        && let Some((m, d)) = rest.split_once('-')
    {
        return date_ymd_ok(year, m, d);
    }
    // D/M/Y, M/D/Y, or YYYY/MM/DD with / - . separators.
    let seps: &[char] = &['/', '-', '.'];
    for sep in seps {
        let parts: Vec<&str> = t.split(*sep).collect();
        if parts.len() == 3 {
            let (a, b, c) = (parts[0], parts[1], parts[2]);
            if let (Ok(x), Ok(y), Ok(z)) = (a.parse::<u32>(), b.parse::<u32>(), c.parse::<u32>()) {
                // Leading 4-digit year: YYYY/MM/DD.
                if a.len() == 4 {
                    return date_ymd_ok(x, b, c);
                }
                // Prefer day-month-year when first > 12 (common in JSL corpus).
                if x > 31 || y > 31 {
                    return false;
                }
                let year = match c.len() {
                    4 => z,
                    2 if z <= 35 => 2000 + z,
                    2 if z >= 36 => 1900 + z,
                    _ => return false, // 3-digit years, etc.
                };
                if !year_in_range(year) {
                    return false;
                }
                // Accept either DMY or MDY if both month slots plausible.
                let dmy = date_parts_ok(x, y, year); // d, m, y
                let mdy = date_parts_ok(y, x, year); // swapped
                return dmy || mdy;
            }
            return false;
        }
    }
    // OCR glued 8 digits: DDMMYYYY or MMDDYYYY
    if t.len() == 8 && t.chars().all(|c| c.is_ascii_digit()) {
        let d1: u32 = t[0..2].parse().unwrap_or(0);
        let d2: u32 = t[2..4].parse().unwrap_or(0);
        let year: u32 = t[4..8].parse().unwrap_or(0);
        if !year_in_range(year) {
            return false;
        }
        return date_parts_ok(d1, d2, year) || date_parts_ok(d2, d1, year);
    }
    // Month-name forms: "Feb 30, 2024" / "December 5, 2024" / "Sept. 3 2024".
    // Anything that is not a recognized month-name shape is rejected.
    let tokens: Vec<&str> = t.split_whitespace().collect();
    if tokens.len() == 3 {
        let mon = tokens[0].trim_end_matches('.').to_ascii_lowercase();
        if let Some(month) = month_number(&mon) {
            let day: u32 = tokens[1].trim_end_matches(',').parse().unwrap_or(0);
            let year: u32 = tokens[2].parse().unwrap_or(0);
            return year_in_range(year) && date_parts_ok(day, month, year);
        }
    }
    false
}

fn date_ymd_ok(year: u32, m: &str, d: &str) -> bool {
    let Ok(month) = m.parse::<u32>() else {
        return false;
    };
    let Ok(day) = d.parse::<u32>() else {
        return false;
    };
    year_in_range(year) && date_parts_ok(day, month, year)
}

fn date_parts_ok(day: u32, month: u32, year: u32) -> bool {
    if !(1..=12).contains(&month) || day == 0 {
        return false;
    }
    let max_day = match month {
        2 if year.is_multiple_of(4) && (year.is_multiple_of(100) == year.is_multiple_of(400)) => 29,
        2 => 28,
        4 | 6 | 9 | 11 => 30,
        _ => 31,
    };
    day <= max_day
}

/// US ZIP (5 digit). Rejects obvious non-zips when used with validation alone.
pub fn us_zip_valid(raw: &str) -> bool {
    let t = raw.trim();
    if t.len() != 5 || !t.chars().all(|c| c.is_ascii_digit()) {
        return false;
    }
    // 00000 is invalid; all same digit unlikely
    t != "00000"
}

/// Street-like line: leading number + words + suffix (Ports, Ways, Street, …).
pub fn street_address_valid(raw: &str) -> bool {
    let t = raw.trim();
    if t.len() < 8 || t.len() > 80 {
        return false;
    }
    let lower = t.to_ascii_lowercase();
    let has_suffix = [
        "street",
        "st",
        "avenue",
        "ave",
        "road",
        "rd",
        "boulevard",
        "blvd",
        "lane",
        "ln",
        "drive",
        "dr",
        "way",
        "ways",
        "court",
        "ct",
        "place",
        "pl",
        "ports",
        "mountain",
        "villages",
        "heights",
        "circle",
        "cir",
        "parkway",
        "pkwy",
        "extension",
        "points",
    ]
    .iter()
    .any(|s| {
        // All suffixes must form a whole trailing word so "123 Record"
        // cannot pass as "…rd" and "123 Forroad" cannot pass as "…road".
        lower
            .split_whitespace()
            .any(|w| w.trim_end_matches(',').eq_ignore_ascii_case(s))
    });
    if !has_suffix {
        return false;
    }
    // Starts with a house number (1–6 digits).
    let leading = t.chars().take_while(|c| c.is_ascii_digit()).count();
    (1..=6).contains(&leading)
}

/// Multi-word person name (spaced) or PascalCase-glued name.
pub fn person_name_valid(raw: &str) -> bool {
    let t = raw.trim();
    if t.len() < 4 || t.len() > 80 {
        return false;
    }
    // Strip common labels if present.
    let t = strip_name_label(t);
    if t.is_empty() {
        return false;
    }
    // Spaced: "Kimberly Lawrence" / "James James Choi"
    // Trim trailing stopwords ("Susan Frances Martin Date" from OCR glue).
    if t.contains(' ') {
        let mut parts: Vec<&str> = t.split_whitespace().collect();
        while parts.len() > 2 && !is_name_token(parts[parts.len() - 1]) {
            parts.pop();
        }
        if !(2..=4).contains(&parts.len()) {
            return false;
        }
        return parts.iter().all(|p| is_name_token(p));
    }
    // Glued PascalCase (after optional trailing-stopword trim).
    let cleaned = trim_glued_person_name(t).unwrap_or_else(|| t.to_string());
    let parts = split_pascal_case(&cleaned);
    if !(2..=4).contains(&parts.len()) {
        return false;
    }
    parts.iter().all(|p| is_name_token(p))
}

/// Drop trailing PascalCase tokens that are form labels ("…BlankenshipDoctor" → name).
pub fn trim_glued_person_name(raw: &str) -> Option<String> {
    let t = strip_name_label(raw.trim());
    if t.contains(' ') {
        return None;
    }
    let mut parts = split_pascal_case(t);
    while parts.len() > 2 {
        let last = parts.last()?.as_str();
        if is_name_token(last) {
            break;
        }
        parts.pop();
    }
    if parts.len() >= 2 && parts.iter().all(|p| is_name_token(p)) {
        Some(parts.concat())
    } else {
        None
    }
}

fn split_pascal_case(t: &str) -> Vec<String> {
    let mut parts = Vec::new();
    let mut cur = String::new();
    for ch in t.chars() {
        if ch.is_ascii_uppercase() && !cur.is_empty() {
            parts.push(std::mem::take(&mut cur));
        }
        cur.push(ch);
    }
    if !cur.is_empty() {
        parts.push(cur);
    }
    parts
}

fn strip_name_label(s: &str) -> &str {
    let lower = s.to_ascii_lowercase();
    for prefix in [
        "patient name:",
        "patient name :",
        "doctor name:",
        "doctor name :",
        "name:",
        "name :",
    ] {
        if lower.starts_with(prefix) {
            return s[prefix.len()..].trim();
        }
    }
    // Handle "Dr. " title prefix (regex captures it for person-dr-title).
    if lower.starts_with("dr.") {
        return s[3..].trim();
    }
    s
}

fn is_name_token(p: &str) -> bool {
    if p.len() < 2 || p.len() > 24 {
        return false;
    }
    let mut chars = p.chars();
    let Some(first) = chars.next() else {
        return false;
    };
    if !first.is_ascii_uppercase() {
        return false;
    }
    // Rest must be lowercase, except an uppercase letter immediately after an
    // apostrophe or hyphen ("O'Brien", "Jean-Luc").
    let mut after_sep = false;
    for c in chars {
        match c {
            '\'' | '-' => after_sep = true,
            c if c.is_ascii_lowercase() => after_sep = false,
            c if c.is_ascii_uppercase() && after_sep => after_sep = false,
            _ => return false,
        }
    }
    // Reject trailing apostrophes/hyphens ("Mary'", "O'").
    if p.ends_with(['\'', '-']) {
        return false;
    }
    // Reject common non-name title-case tokens (forms, labs, vitals, instructions).
    !matches!(
        p,
        "Patient"
            | "Hospital"
            | "Doctor"
            | "Medical"
            | "Recorded"
            | "Healthcare"
            | "Recovery"
            | "Trauma"
            | "Center"
            | "Female"
            | "Male"
            | "Status"
            | "Institute"
            | "Clinic"
            | "Information"
            | "Demographics"
            | "Lifestyle"
            | "Vitals"
            | "Notes"
            | "Subjective"
            | "Observations"
            | "Assessment"
            | "Assesment" // corpus typo
            | "Recommendations"
            | "Follow"
            | "Instruction"
            | "Current"
            | "Medications"
            | "Medication"
            | "Tests"
            | "Test"
            | "Date"
            | "Reason"
            | "Once"
            | "Twice"
            | "Three"
            | "Daily"
            | "Never"
            | "Rarely"
            | "Mild"
            | "Type"
            | "Diabetes"
            | "Mellitus"
            | "Peripheral"
            | "Neuropathy"
            | "Firth" // OCR for "Birth"
            | "Birth"
            | "Of"
            | "The"
            | "And"
            | "For"
            | "With"
            | "From"
            | "Signed"
            | "Electronically"
            | "Confirmation"
            | "Appointment"
            | "Provider"
            | "Participant"
            | "Encounter"
            | "Coordinator"
            | "Healthplans"
            | "Contents"
            | "Table"
            | "Physical"
            | "Exam"
            | "Panel"
            | "Done"
            | "Pending"
            | "Study"
            | "Checkup"
            | "Infection"
            | "Level"
            | "Count"
            | "Blood"
            | "Nerve"
            | "Conduction"
            | "Respiratory"
            | "Routine"
            | "Lipid"
            | "Metabolic"
            | "Comprehensive"
            | "Urinalysis"
            | "Microalbumin"
            | "Glucose"
            | "Insulin"
            | "Vitamin"
            | "Aspirin"
            | "Dosage"
            | "Frequency"
            | "Heart"
            | "Rate"
            | "Oxygen"
            | "Saturation"
            | "Percent"
            | "Pressure"
            | "Temperature"
            | "Celsius"
            | "Smoking"
            | "Alcohol"
            | "Consumption"
            | "Diet"
            | "Preference"
            | "Exercise"
            | "Habits"
            | "Past"
            | "Visits"
            | "Annual"
            | "Foot"
            | "Eye"
            | "Flu"
            | "Symptoms"
            | "Ray"
            | "Scan"
            | "Imaging"
            | "Culture"
            | "Screen"
            | "Screening"
            | "Lab"
            | "Labs"
            | "Results"
            | "Normal"
            | "Abnormal"
            | "Stable"
            | "Chronic"
            | "Acute"
            | "History"
            | "Allergy"
            | "Allergies"
            | "Monday"
            | "Tuesday"
            | "Wednesday"
            | "Thursday"
            | "Friday"
            | "Saturday"
            | "Sunday"
            | "January"
            | "February"
            | "March"
            | "April"
            | "May"
            | "June"
            | "July"
            | "August"
            | "September"
            | "October"
            | "November"
            | "December"
    )
}

/// Person-name shape for `person-before-date`: 1–4 capitalized name tokens.
/// A single token is acceptable when a date follows ("Smith 24/05/1977"),
/// where `person_name_valid` would reject the 1-token name outright.
pub fn person_before_date_name_valid(raw: &str) -> bool {
    let t = strip_name_label(raw.trim());
    let parts: Vec<&str> = t.split_whitespace().collect();
    if parts.is_empty() || parts.len() > 4 {
        return false;
    }
    parts.iter().all(|p| is_name_token(p))
}

/// Organization / facility name ending in a corporate or care suffix.
pub fn org_name_valid(raw: &str) -> bool {
    let t = raw.trim();
    if t.len() < 8 || t.len() > 120 {
        return false;
    }
    let lower = t.to_ascii_lowercase();
    let has_suffix = lower.ends_with(" inc")
        || lower.ends_with(" inc.")
        || lower.ends_with(" llc")
        || lower.ends_with(" ltd")
        || lower.ends_with(" ltd.")
        || lower.contains("institute")
        || lower.contains("hospital")
        || lower.contains(" medical center")
        || lower.contains(" clinic");
    if !has_suffix {
        return false;
    }
    // At least two title-case words.
    let words: Vec<&str> = t.split_whitespace().collect();
    words.len() >= 2
        && words.iter().any(|w| {
            w.chars()
                .next()
                .map(|c| c.is_ascii_uppercase())
                .unwrap_or(false)
        })
}

/// All US state names, shared with `regex_detect::strip_trailing_us_state`
/// (which strips the trailing state from the raw `us-city-before-state`
/// match) and used here to accept raw "City State" input. Single source of
/// truth for the crate.
///
/// IMPORTANT: multi-word states must be listed before any state that could be
/// a suffix of another (e.g. "New York" before a hypothetical "York").
/// `strip_suffix` matches the entire trailing token(s), so the order only
/// matters when one state name is a suffix of another — keep longest-first.
pub(crate) const US_STATES: &[&str] = &[
    "District of Columbia",
    "New Hampshire",
    "New Jersey",
    "New Mexico",
    "New York",
    "North Carolina",
    "North Dakota",
    "Rhode Island",
    "South Carolina",
    "South Dakota",
    "West Virginia",
    "Alabama",
    "Alaska",
    "Arizona",
    "Arkansas",
    "California",
    "Colorado",
    "Connecticut",
    "Delaware",
    "Florida",
    "Georgia",
    "Hawaii",
    "Idaho",
    "Illinois",
    "Indiana",
    "Iowa",
    "Kansas",
    "Kentucky",
    "Louisiana",
    "Maine",
    "Maryland",
    "Massachusetts",
    "Michigan",
    "Minnesota",
    "Mississippi",
    "Missouri",
    "Montana",
    "Nebraska",
    "Nevada",
    "Ohio",
    "Oklahoma",
    "Oregon",
    "Pennsylvania",
    "Tennessee",
    "Texas",
    "Utah",
    "Vermont",
    "Virginia",
    "Washington",
    "Wisconsin",
    "Wyoming",
];

/// Whether `s` is a whole US state name (used to drop the state token from
/// raw "City State" input before the city-token checks run).
fn is_us_state(s: &str) -> bool {
    US_STATES.contains(&s)
}

/// Hospital / provider city-style token before a US state name.
/// Rejects common non-city title-case words that are not place names
/// (similar to the `is_name_token` stoplist for person names).
///
/// Accepts both the city-only form produced by
/// `regex_detect::strip_trailing_us_state` ("Springfield", "New Amandafort")
/// and the raw "City State" match ("Springfield, Illinois"): a trailing state
/// token is dropped first. Every remaining token must be a plausible city
/// word, so single-word cities like "Springfield, Illinois" are accepted
/// while "New Meeting, Texas" is rejected (the "Meeting" stopword is checked,
/// not just the leading "New").
pub fn city_before_state_valid(raw: &str) -> bool {
    let t = raw.trim();
    let parts: Vec<&str> = t.split_whitespace().collect();
    // Drop a trailing state name when the raw "City State" / "City, State"
    // form is passed in; city-only input from detect_regex (state already
    // stripped) has no state token to drop.
    let city_tokens: &[&str] = if parts.len() >= 2 && is_us_state(parts[parts.len() - 1]) {
        &parts[..parts.len() - 1]
    } else {
        &parts
    };
    if city_tokens.is_empty() || city_tokens.len() > 4 {
        return false;
    }
    // Every token must be a plausible city name token (capitalized, not a
    // common non-place title-case word). Trailing state separators
    // ("Springfield," from raw input) are trimmed before the check.
    city_tokens
        .iter()
        .all(|tok| is_city_token(tok.trim_end_matches([',', '.'])))
}

/// Whether a single token looks like a city name (capitalized word that is
/// not a common non-place title-case word like "Meeting", "Pizza", "Page").
fn is_city_token(p: &str) -> bool {
    if p.len() < 2 {
        return false;
    }
    let mut chars = p.chars();
    let first = chars.next().unwrap();
    if !first.is_ascii_uppercase() {
        return false;
    }
    // Rest must be lowercase.
    if !chars.all(|c| c.is_ascii_lowercase()) {
        return false;
    }
    // Reject trailing punctuation (state separator glued by OCR).
    let clean = p.trim_end_matches([',', '.']);
    !NON_CITY_TOKENS.contains(&clean)
}

/// Common title-case words that are not city names, used to reject false
/// positives from `us-city-before-state` (e.g. "Meeting California").
static NON_CITY_TOKENS: &[&str] = &[
    "Page",
    "Image",
    "Table",
    "Meeting",
    "Summary",
    "Report",
    "Letter",
    "Memo",
    "Note",
    "Notes",
    "Form",
    "Section",
    "Chapter",
    "Appendix",
    "Document",
    "Record",
    "Records",
    "Patient",
    "Doctor",
    "Provider",
    "Hospital",
    "Clinic",
    "Medical",
    "Healthcare",
    "Appointment",
    "Encounter",
    "Visit",
    "Visits",
    "Exam",
    "Test",
    "Tests",
    "Lab",
    "Labs",
    "Result",
    "Results",
    "Phone",
    "Email",
    "Address",
    "Location",
    "Contact",
    "Date",
    "Name",
    "Title",
    "Subject",
    "Re",
    "Item",
    "Items",
    "Total",
    "Amount",
    "Price",
    "Cost",
    "Payment",
    "Balance",
    "Due",
    "Paid",
    "Date",
];

/// Clinical-style hospital / facility record id (e.g. HOSP26508961).
pub fn hospital_id_valid(raw: &str) -> bool {
    let t = raw.trim();
    let upper = t.to_ascii_uppercase();
    if !upper.starts_with("HOSP") {
        return false;
    }
    // Safe: HOSP prefix is single-byte ASCII (checked by starts_with).
    let digits = &upper[4..];
    (6..=12).contains(&digits.len()) && digits.chars().all(|c| c.is_ascii_digit())
}

/// Clinical-style provider id (e.g. DR14144B, DR4509A).
pub fn provider_id_valid(raw: &str) -> bool {
    let t = raw.trim();
    let upper = t.to_ascii_uppercase();
    if !upper.starts_with("DR") {
        return false;
    }
    // Safe: DR prefix is single-byte ASCII (checked by starts_with).
    let rest = &upper[2..];
    if rest.is_empty() {
        return false;
    }
    // Digits, optionally one trailing letter.
    let digits = match rest.chars().last() {
        Some(c) if c.is_ascii_alphabetic() => &rest[..rest.len() - 1],
        _ => rest,
    };
    (3..=8).contains(&digits.len())
        && digits.chars().all(|c| c.is_ascii_digit())
        && rest
            .chars()
            .all(|c| c.is_ascii_digit() || c.is_ascii_alphabetic())
}

/// IPv4 with each octet 0-255.
pub fn ipv4_valid(raw: &str) -> bool {
    let parts: Vec<&str> = raw.split('.').collect();
    if parts.len() != 4 {
        return false;
    }
    parts.iter().all(|p| {
        // Reject multi-digit octets with leading zeros (e.g. "192.168.001.001")
        // for consistency with age_number_valid — leading-zero octets are
        // ambiguous (could be interpreted as octal on some systems).
        !(p.len() > 1 && p.starts_with('0')) && p.parse::<u32>().is_ok_and(|n| n <= 255)
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn luhn_visa_test_number() {
        assert!(luhn_valid("4111111111111111"));
        assert!(!luhn_valid("4111111111111112"));
    }

    #[test]
    fn luhn_rejects_short_and_long() {
        assert!(!luhn_valid("411111111111")); // too short
        assert!(!luhn_valid("41111111111111111111")); // 20 digits
    }

    #[test]
    fn iban_example() {
        assert!(iban_valid("GB82 WEST 1234 5698 7654 32"));
        assert!(!iban_valid("GB82 WEST 1234 5698 7654 33"));
    }

    #[test]
    fn iban_rejects_bad_shape() {
        assert!(!iban_valid("XX"));
        assert!(!iban_valid("123456789012345")); // no country letters
        assert!(!iban_valid("GBXXWEST12345698765432")); // non-digit check digits
    }

    #[test]
    fn ssn_rejects_zeros() {
        assert!(!ssn_valid("000-12-3456"));
        assert!(!ssn_valid("666-12-3456"));
        assert!(!ssn_valid("900-12-3456"));
        assert!(!ssn_valid("123-00-3456"));
        assert!(!ssn_valid("123-45-0000"));
        assert!(ssn_valid("123-45-6789"));
    }

    #[test]
    fn email_valid_edges() {
        assert!(email_valid("a@b.co"));
        assert!(!email_valid("not-an-email"));
        assert!(!email_valid("@nodomain.com"));
        assert!(!email_valid("user@"));
        assert!(!email_valid("user@nodot"));
        assert!(!email_valid("user@host.x")); // tld too short
    }

    #[test]
    fn phone_valid_edges() {
        assert!(phone_valid("+1 415-555-0132"));
        assert!(phone_valid("(415) 555-0132"));
        assert!(!phone_valid("123-45-6789")); // SSN shape
        assert!(!phone_valid("12-3456789")); // EIN shape
        assert!(!phone_valid("7421.15")); // currency
        assert!(!phone_valid("1234 5698 7654 32")); // IBAN-like groups
        assert!(!phone_valid("12345")); // too few digits
        assert!(!phone_valid("5550132")); // bare digits without structure
    }

    #[test]
    fn aba_routing() {
        // Known valid test routing used in examples: 021000021
        assert!(aba_routing_valid("021000021"));
        assert!(!aba_routing_valid("021000022"));
        assert!(!aba_routing_valid("12345"));
    }

    #[test]
    fn ipv4_edges() {
        assert!(ipv4_valid("192.168.1.1"));
        assert!(ipv4_valid("0.0.0.0"));
        assert!(!ipv4_valid("1.2.3"));
        assert!(!ipv4_valid("1.2.3.256"));
        assert!(!ipv4_valid("a.b.c.d"));
    }

    #[test]
    fn date_rejects_impossible_days() {
        assert!(!date_valid("31/02/2020")); // Feb 31
        assert!(!date_valid("30/02/1999")); // Feb 30 (non-leap)
        assert!(!date_valid("29/02/2023")); // Feb 29 (non-leap)
        assert!(!date_valid("31/04/2021")); // Apr 31
        assert!(date_valid("29/02/2024")); // leap year
        assert!(date_valid("31/01/2020")); // Jan 31
    }

    #[test]
    fn person_names_with_separators() {
        assert!(person_name_valid("Mary O'Brien"));
        assert!(person_name_valid("Jean-Luc Picard"));
        assert!(!person_name_valid("X-Ray Results"));
        assert!(!person_name_valid("Once daily"));
    }

    #[test]
    fn age_and_clinical_ids() {
        assert!(age_number_valid("46"));
        assert!(age_number_valid("1"));
        assert!(age_number_valid("120"));
        assert!(!age_number_valid("0"));
        assert!(!age_number_valid("121"));
        assert!(!age_number_valid("05"));
        assert!(!age_number_valid("46a"));

        assert!(age_years_old_valid("46-year-old"));
        assert!(age_years_old_valid("9-year-old"));
        assert!(!age_years_old_valid("200-year-old"));
        assert!(!age_years_old_valid("year-old"));

        assert!(age_labeled_valid("Age: 46"));
        assert!(age_labeled_valid("age:12"));
        assert!(!age_labeled_valid("Age: 999"));
        assert!(!age_labeled_valid("Age 46"));

        assert!(age_aged_valid("aged 56"));
        assert!(age_aged_valid("Aged 9"));
        assert!(!age_aged_valid("aged 200"));
        assert!(!age_aged_valid("age 56"));

        assert!(hospital_id_valid("HOSP26508961"));
        assert!(hospital_id_valid("hosp123456"));
        assert!(!hospital_id_valid("HOSP12"));
        assert!(!hospital_id_valid("HOSPITAL1"));

        assert!(provider_id_valid("DR14144B"));
        assert!(provider_id_valid("DR4509A"));
        assert!(provider_id_valid("DR6853C"));
        assert!(!provider_id_valid("DR12"));
        assert!(!provider_id_valid("DR"));
        assert!(!provider_id_valid("DRA1234"));

        assert!(person_name_valid("Kimberly Lawrence"));
        assert!(person_name_valid("James James Choi"));
        assert!(person_name_valid("KimberlyLawrence"));
        assert!(person_name_valid("Name: CherylBlankenship"));
        assert_eq!(
            trim_glued_person_name("CherylBlankenshipDoctor").as_deref(),
            Some("CherylBlankenship")
        );
        assert!(person_name_valid("CherylBlankenshipDoctor"));
        assert!(!person_name_valid("Patient Summary"));
        assert!(!person_name_valid("X"));

        assert!(org_name_valid("Sierra Valley Medical Institute INC"));
        assert!(org_name_valid("Sierra  Valley Medical Institute INC"));
        assert!(!org_name_valid("Once daily"));
        assert!(!org_name_valid("Type 2 Diabetes Mellitus"));

        assert!(date_valid("09/03/1951"));
        assert!(date_valid("1951-09-03"));
        assert!(date_valid("09031951")); // OCR glued
        assert!(!date_valid("15/09/023"));
        assert!(!date_valid("05/06/2107")); // beyond 2100 ceiling
        assert!(!date_valid("15/00/2024"));
        assert!(!date_valid("29/10/3024"));

        assert!(us_zip_valid("97375"));
        assert!(!us_zip_valid("00000"));
        assert!(!us_zip_valid("1234"));

        assert!(street_address_valid("5891 Kenneth Ports"));
        assert!(street_address_valid("848 Ortiz Ways"));
        assert!(!street_address_valid("Osteoarthritis"));
    }

    #[test]
    fn phone_dotted_and_spaced_formats() {
        assert!(phone_valid("415.555.0132")); // dotted US
        assert!(phone_valid("1.415.555.0132")); // dotted with country code
        assert!(phone_valid("1-415.555.0132")); // mixed separators
        assert!(!phone_valid("7421.15000")); // currency with a 5-digit group
        assert!(!phone_valid("12.34")); // too few groups
        assert!(phone_valid("1 415 555 0132")); // spaced country code
        assert!(phone_valid("020 7946 0958 123")); // 4-group UK
        assert!(phone_valid("415 555 0132 x123")); // extension
        assert!(phone_valid("415\t555\t0132")); // tab separated
        assert!(!phone_valid("1234 5698 7654 32")); // IBAN-like groups
    }

    #[test]
    fn date_month_name_forms() {
        assert!(date_valid("Feb 28, 2024"));
        assert!(date_valid("December 5, 2024"));
        assert!(date_valid("Sept. 3 2024"));
        assert!(!date_valid("Feb 30, 2024")); // impossible day
        assert!(!date_valid("Dec 00, 1900")); // month-00 style day
        assert!(!date_valid("Jan 99, 9999")); // year out of range
        assert!(!date_valid("99/99-9999")); // mixed separators
        assert!(!date_valid("Not a date"));
    }

    #[test]
    fn date_year_forms() {
        assert!(date_valid("15/09/47")); // 1947 (two-digit year 36-99)
        assert!(date_valid("15/09/77")); // 1977
        assert!(date_valid("2024/05/06")); // YYYY/MM/DD
        assert!(!date_valid("2024/13/01")); // bad month
        assert!(date_valid("05/06/2024"));
    }

    #[test]
    fn luhn_rejects_all_zero() {
        assert!(!luhn_valid("0000000000000"));
        assert!(!luhn_valid("0000000000000000000"));
        assert!(luhn_valid("4111111111111111"));
    }

    #[test]
    fn street_address_suffix_boundary() {
        assert!(street_address_valid("123 Main Street"));
        assert!(street_address_valid("123 Oak Dr"));
        assert!(!street_address_valid("123 Record")); // ends "rd"
        assert!(!street_address_valid("123 Forest")); // ends "st"
        assert!(!street_address_valid("123 Have")); // ends "ave"
    }

    #[test]
    fn email_rejects_uppercase_sticky_tld() {
        assert!(email_valid("user@example.com"));
        assert!(email_valid("user@example.Com")); // capitalized TLD ok
        assert!(!email_valid("user@example.comSSN"));
        assert!(!email_valid("user@example.ComSSN"));
    }

    #[test]
    fn name_tokens_reject_trailing_separators() {
        assert!(!is_name_token("Mary'"));
        assert!(!is_name_token("O'"));
        assert!(!is_name_token("Jean-"));
        assert!(is_name_token("Mary"));
        assert!(is_name_token("O'Brien"));
        assert!(is_name_token("Jean-Luc"));
    }

    #[test]
    fn iban_specs_are_consistent() {
        for &(cc, len, pattern) in IBAN_SPECS {
            assert_eq!(cc.len(), 2, "{cc}");
            assert_eq!(pattern.len(), len - 4, "{cc}");
            assert!(
                pattern.chars().all(|c| matches!(c, 'a' | 'd' | 'n')),
                "{cc}"
            );
        }
    }

    #[test]
    fn iban_country_bban_structure() {
        assert!(iban_valid("GB82 WEST 1234 5698 7654 32"));
        assert!(iban_valid("DE89 3704 0044 0532 0130 00"));
        assert!(iban_valid("FR14 2004 1010 0505 0001 3M02 606"));
        assert!(!iban_valid("GB82 WEST 1234 5698 7654 3")); // wrong length for GB
        assert!(!iban_valid("DE89 3704 0044 0532 0130 0A")); // letter in DE digits
    }

    #[test]
    fn iban_alpha_bban_countries() {
        // Known-good real IBANs for entries with mixed a/n/d BBAN patterns,
        // guarding against transcription errors like the NL bug (C03-01).
        assert!(iban_valid("NL91 ABNA 0417 1643 00")); // NL: 4 alpha + 10 digit
        assert!(iban_valid("CH93 0076 2011 6238 5295 7")); // CH: 5 alpha + 12 digit
        assert!(iban_valid("IE29 AIBK 9311 5212 3456 78")); // IE: 4 alpha + 14 digit
        assert!(iban_valid("IT60 X054 2811 1010 0000 0123 456")); // IT: 1 n + 10 d + 12 a
        assert!(iban_valid("FR14 2004 1010 0505 0001 3M02 606")); // FR: 23 alphanumeric
        assert!(iban_valid("PL61 1090 1014 0000 0712 1981 2874")); // PL: 8 d + 16 n
        assert!(iban_valid("PT50 0002 0123 1234 5678 9015 4")); // PT: 21 alphanumeric
        // NL with wrong BBAN structure (digits where alpha bank code expected).
        assert!(!iban_valid("NL91 0417 1643 0016"));
    }

    #[test]
    fn dotted_phone_rejects_4digit_first_group() {
        // 3-group dotted format: first group must be ≤ 3 digits (US area code).
        assert!(!phone_valid("1234.555.0132"));
        assert!(phone_valid("415.555.0132"));
    }

    #[test]
    fn street_address_rejects_glued_suffix() {
        assert!(!street_address_valid("123 Forroad")); // glued "road"
        assert!(!street_address_valid("123 Subcourt")); // glued "court"
        assert!(street_address_valid("123 Forest Road")); // distinct word
        assert!(street_address_valid("123 Oak Court")); // distinct word
    }

    #[test]
    fn date_accepts_future_years() {
        assert!(date_valid("15/01/2040")); // post-2035
        assert!(date_valid("2040-01-15")); // ISO post-2035
        assert!(!date_valid("15/01/2101")); // beyond 2100 ceiling
    }

    #[test]
    fn date_rejects_far_future_ocr_hallucinations() {
        // OCR on noisy scans hallucinates decades-out years (real Medium/Hard
        // FPs: `05/06/2077`, `01/8/2073` for 1977/1973 DOBs). No personal
        // document date lies that far ahead; the horizon is clock-derived.
        assert!(!date_valid("05/06/2077"));
        assert!(!date_valid("01/8/2073"));
        assert!(!date_valid("2077-06-05")); // ISO path
        assert!(!date_valid("June 5, 2077")); // month-name path
        assert!(!date_valid("05062077")); // OCR-glued path
        // Dynamic boundary: horizon and horizon+1 stay on opposite sides no
        // matter when this test runs.
        let cap = super::max_sane_year();
        assert!(date_valid(&format!("15/06/{cap}")));
        assert!(!date_valid(&format!("15/06/{}", cap + 1)));
        // Near-term scheduling dates always pass.
        let next_year = super::current_year_approx().unwrap_or(2026) + 1;
        assert!(date_valid(&format!("15/06/{next_year}")));
    }

    #[test]
    fn email_accepts_uppercase_cctld() {
        assert!(email_valid("user@x.IO"));
        assert!(email_valid("user@x.US"));
        assert!(email_valid("user@x.UK"));
        assert!(email_valid("user@x.EU"));
        assert!(email_valid("user@x.io")); // lowercase still ok
        assert!(email_valid("user@x.Co")); // capitalized still ok
        // Glued uppercase tails still rejected.
        assert!(!email_valid("user@example.comSSN"));
        assert!(!email_valid("user@example.ComSSN"));
    }

    #[test]
    fn phone_rejects_all_same_digit_and_bad_area_code() {
        assert!(!phone_valid("5555555555")); // all-same 10-digit
        assert!(!phone_valid("11111111111")); // all-same 11-digit
        assert!(!phone_valid("10000000000")); // 11-digit, area code 000
        assert!(phone_valid("14155550132")); // valid bare 11-digit
    }

    #[test]
    fn luhn_rejects_all_same_nonzero_digit() {
        assert!(!luhn_valid("1111111111111")); // 13 ones
        assert!(!luhn_valid("2222222222222")); // 13 twos
        assert!(!luhn_valid("0000000000000")); // all zeros still rejected
        assert!(luhn_valid("4111111111111111")); // valid test number
    }

    #[test]
    fn city_before_state_accepts_single_word_and_multi_token_cities() {
        // City-only form (as produced by detect_regex's strip_trailing_us_state).
        assert!(city_before_state_valid("Springfield"));
        assert!(city_before_state_valid("New Amandafort"));
        assert!(city_before_state_valid("North Bradleytown"));
        // Raw "City State" form: the trailing state token is dropped inside
        // the validator before the city tokens are checked.
        assert!(city_before_state_valid("Springfield, Illinois"));
        assert!(city_before_state_valid("New Amandafort, Wyoming"));
        assert!(city_before_state_valid("Springfield, New York"));
    }

    #[test]
    fn city_before_state_applies_stoplist_to_all_city_tokens() {
        // "New" alone passes, but the city is "New Meeting" — the "Meeting"
        // stopword must be checked, not just the leading prefix token.
        assert!(!city_before_state_valid("New Meeting"));
        assert!(!city_before_state_valid("New Meeting, Texas"));
        assert!(!city_before_state_valid("Meeting, Texas"));
        assert!(!city_before_state_valid(""));
    }
}
