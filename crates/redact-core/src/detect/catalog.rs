//! Regex pattern catalog for PII detection.

use super::validators::{
    aba_routing_valid, age_aged_valid, age_labeled_valid, age_years_old_valid,
    city_before_state_valid, date_valid, email_valid, hospital_id_valid, iban_valid, ipv4_valid,
    luhn_valid, org_name_valid, person_before_date_name_valid, person_name_valid, phone_valid,
    provider_id_valid, ssn_valid, street_address_valid, us_zip_valid,
};
use crate::types::Category;
use regex::Regex;
use std::sync::LazyLock;

pub struct PatternDef {
    pub id: &'static str,
    pub category: Category,
    pub regex: &'static str,
    pub base_confidence: f32,
    pub context_keywords: &'static [&'static str],
    pub validate: Option<fn(&str) -> bool>,
}

pub static PATTERNS: LazyLock<Vec<CompiledPattern>> =
    LazyLock::new(|| DEFS.iter().map(CompiledPattern::from_def).collect());

pub struct CompiledPattern {
    pub id: &'static str,
    pub category: Category,
    pub re: Regex,
    pub base_confidence: f32,
    pub context_keywords: &'static [&'static str],
    pub validate: Option<fn(&str) -> bool>,
}

impl CompiledPattern {
    /// Compile a `PatternDef` into a `CompiledPattern`, sharing the static
    /// field references so future field additions only need updating in one
    /// struct, not in the mapping closure.
    fn from_def(d: &PatternDef) -> Self {
        Self {
            id: d.id,
            category: d.category,
            re: Regex::new(d.regex).expect("valid pattern"),
            base_confidence: d.base_confidence,
            context_keywords: d.context_keywords,
            validate: d.validate,
        }
    }
}

/// All US state names, as a regex alternation (used by city/state patterns).
macro_rules! us_states_alt {
    () => {
        "Alabama|Alaska|Arizona|Arkansas|California|Colorado|Connecticut|Delaware|District of Columbia|Florida|Georgia|Hawaii|Idaho|Illinois|Indiana|Iowa|Kansas|Kentucky|Louisiana|Maine|Maryland|Massachusetts|Michigan|Minnesota|Mississippi|Missouri|Montana|Nebraska|Nevada|New Hampshire|New Jersey|New Mexico|New York|North Carolina|North Dakota|Ohio|Oklahoma|Oregon|Pennsylvania|Rhode Island|South Carolina|South Dakota|Tennessee|Texas|Utah|Vermont|Virginia|Washington|West Virginia|Wisconsin|Wyoming"
    };
}

static DEFS: &[PatternDef] = &[
    PatternDef {
        id: "email",
        category: Category::Email,
        // TLD limited to letters; validate trims sticky suffixes from raw extracts.
        regex: r"[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,24}",
        base_confidence: 0.95,
        context_keywords: &["email", "e-mail", "mail", "contact"],
        validate: Some(email_valid),
    },
    PatternDef {
        id: "ssn-dashed",
        category: Category::Ssn,
        // No trailing \b: text-layer glue ("123-45-6789Hospital") must still
        // match; the sanitizer shrinks glued alphanumeric tails before ssn_valid.
        regex: r"\b\d{3}-\d{2}-\d{4}",
        base_confidence: 0.85,
        context_keywords: &["ssn", "social security", "taxpayer", "tin"],
        validate: Some(ssn_valid),
    },
    PatternDef {
        id: "ssn-contiguous",
        category: Category::Ssn,
        regex: r"\b\d{9}\b",
        base_confidence: 0.3,
        context_keywords: &["ssn", "social security", "taxpayer", "tin"],
        validate: Some(ssn_valid),
    },
    PatternDef {
        id: "credit-card",
        category: Category::CreditCard,
        regex: r"\b(?:\d[ \-]?){12,18}\d\b",
        base_confidence: 0.75,
        context_keywords: &[
            "card",
            "visa",
            "mastercard",
            "amex",
            "credit",
            "debit",
            "payment",
        ],
        validate: Some(luhn_valid),
    },
    PatternDef {
        id: "iban",
        category: Category::Iban,
        // Trailing boundary: avoid requiring \b so sticky "…32Notes" still matches.
        regex: r"\b[A-Z]{2}\d{2}(?:\s?[A-Z0-9]{4}){2,7}(?:\s?[A-Z0-9]{1,4})?",
        base_confidence: 0.8,
        context_keywords: &["iban", "account", "bank", "transfer", "swift", "bic"],
        validate: Some(iban_valid),
    },
    PatternDef {
        id: "us-aba-routing",
        // A routing number is not an IBAN; own category so `--categories iban`
        // does not select routing numbers and findings label them correctly.
        category: Category::RoutingNumber,
        regex: r"\b\d{9}\b",
        // Below the default floor: requires a routing/bank keyword so bare
        // 9-digit runs passing the ABA checksum are not flagged in
        // numeric-heavy documents (the regex is identical to ssn-contiguous).
        base_confidence: 0.3,
        context_keywords: &["routing", "aba", "ach", "wire", "bank"],
        validate: Some(aba_routing_valid),
    },
    PatternDef {
        id: "phone-intl",
        category: Category::Phone,
        regex: r"(?:\+\d{1,3}[\s\-.]?)?(?:\(\d{1,4}\)[\s\-.]?)?\d{2,4}(?:[\s\-.]\d{2,6}){1,4}",
        // Below the default floor: digit-separator sequences are common in
        // non-phone contexts (measurements, scores, version numbers). Requires
        // a phone/tel/fax keyword, consistent with `us-phone-bare`.
        base_confidence: 0.3,
        context_keywords: &["phone", "tel", "mobile", "cell", "fax", "call"],
        validate: Some(phone_valid),
    },
    PatternDef {
        id: "us-phone-bare",
        category: Category::Phone,
        regex: r"\b[2-9]\d{2}[2-9]\d{6}\b",
        base_confidence: 0.3,
        context_keywords: &["phone", "tel", "mobile", "cell", "fax", "call"],
        validate: None,
    },
    PatternDef {
        id: "ipv4",
        category: Category::IpAddress,
        regex: r"\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b",
        base_confidence: 0.7,
        context_keywords: &["ip", "address", "server", "host"],
        validate: Some(ipv4_valid),
    },
    PatternDef {
        id: "date",
        category: Category::Date,
        regex: r"\b(?:\d{1,2}[/\-.]\d{1,2}[/\-.]\d{2,4}|\d{4}-\d{2}-\d{2}|(?:Jan|Feb|Mar|Apr|May|Jun|Jul|Aug|Sep|Oct|Nov|Dec)[a-z]*\.? \d{1,2},? \d{4})\b",
        // Below the default floor: date-shaped strings (invoice numbers,
        // version dates, reference numbers) are extremely common in non-PII
        // contexts. Requires a date-related keyword to fire, consistent with
        // `date-ocr-glued` and `date-of-birth`.
        base_confidence: 0.3,
        context_keywords: &["date", "valid until", "expires", "expiry", "issued"],
        validate: Some(date_valid),
    },
    // OCR often drops separators: "09031951" for 09/03/1951.
    // Below the default floor: any 8-digit run (invoice/order numbers) is
    // date-shaped, so a date/birth keyword is required.
    PatternDef {
        id: "date-ocr-glued",
        category: Category::Date,
        regex: r"\b\d{8}\b",
        base_confidence: 0.3,
        context_keywords: &["date", "dob", "birth", "born", "firth"], // OCR "birth"→"firth"
        validate: Some(date_valid),
    },
    PatternDef {
        id: "date-of-birth",
        category: Category::DateOfBirth,
        // ISO YYYY-MM-DD alternative mirrors the generic `date` pattern so
        // "DOB: 1951-09-03" is caught here (with a dob/birth keyword boost)
        // instead of falling through to `date`, whose keywords exclude
        // dob/birth/born and would leave it below the confidence floor.
        regex: r"\b(?:\d{1,2}[/\-.]\d{1,2}[/\-.]\d{2,4}|\d{4}-\d{2}-\d{2}|(?:Jan|Feb|Mar|Apr|May|Jun|Jul|Aug|Sep|Oct|Nov|Dec)[a-z]*\.? \d{1,2},? \d{4})\b",
        base_confidence: 0.15,
        context_keywords: &["dob", "date of birth", "born", "birthdate", "birthday"],
        validate: Some(date_valid),
    },
    PatternDef {
        id: "us-passport",
        category: Category::Passport,
        regex: r"\b[A-Z]\d{8}\b",
        base_confidence: 0.2,
        context_keywords: &["passport"],
        validate: None,
    },
    // Clinical / medical record style ids (JSL de-id corpus and similar notes).
    // No trailing \b: PDF text layers often glue tokens ("HOSP26508961Patient").
    PatternDef {
        id: "hospital-id",
        category: Category::NationalId,
        // Unbounded digit run: the validator rejects >12 digits, so a longer
        // HOSP run is never partially redacted (its first 12 digits only).
        regex: r"(?i)\bHOSP\d{6,}",
        base_confidence: 0.9,
        context_keywords: &[
            "hospital id",
            "hospital",
            "mrn",
            "medical record",
            "patient id",
            "record id",
        ],
        validate: Some(hospital_id_valid),
    },
    // No leading \b: sticky layers glue "INCDR58463ADoctor".
    PatternDef {
        id: "provider-id",
        category: Category::NationalId,
        regex: r"(?i)DR\d{3,8}[A-Za-z]?",
        base_confidence: 0.8,
        context_keywords: &[
            "doctor",
            "provider",
            "physician",
            "unique id",
            "doctor id",
            "npi",
        ],
        validate: Some(provider_id_valid),
    },
    // "46-year-old" in clinical prose — high confidence, no context required.
    PatternDef {
        id: "age-years-old",
        category: Category::Other,
        regex: r"(?i)\b\d{1,3}-year-old\b",
        base_confidence: 0.85,
        context_keywords: &["age", "patient", "female", "male", "born"],
        validate: Some(age_years_old_valid),
    },
    // Alternate prose: "and aged 56, is a female…"
    PatternDef {
        id: "age-aged",
        category: Category::Other,
        regex: r"(?i)\baged\s+\d{1,3}\b",
        base_confidence: 0.85,
        context_keywords: &["born", "patient", "female", "male", "years"],
        validate: Some(age_aged_valid),
    },
    // Labeled age field only ("Age: 46") — bare digits are too noisy as a pattern.
    // No leading/trailing \b: sticky layers glue "1977Age: 46Sex". The regex
    // crate has no lookbehind, so the pattern consumes the char before "Age"
    // (digits/punct/start ok; a letter — "Page: 46", "Image: 46" — rejects);
    // detect_regex strips that consumed prefix before validation.
    PatternDef {
        id: "age-labeled",
        category: Category::Other,
        regex: r"(?i)(?:^|[^A-Za-z])Age\s*:\s*\d{1,3}",
        base_confidence: 0.8,
        context_keywords: &["age", "demographics", "patient"],
        validate: Some(age_labeled_valid),
    },
    // Person names in clinical prose: "Kimberly Lawrence, born on …" / "… born on …"
    // No leading \b: sticky layers glue "SummaryKimberly Lawrence".
    // [ \t] only — avoid newline-glued false matches. Comma optional (prose
    // often drops it: "Kimberly Lawrence born on …").
    PatternDef {
        id: "person-born-on",
        category: Category::Person,
        regex: r"[A-Z][a-z]+(?:[ \t]+[A-Z][a-z]+){1,3},?[ \t]*born[ \t]+on",
        base_confidence: 0.92,
        context_keywords: &["patient", "born", "summary"],
        validate: Some(person_name_valid),
    },
    // Header-style "Kimberly Lawrence     24/05/1977" (also "24.05.1977",
    // "24-05-77", and single-token names when a date follows: "Smith 24/05/1977").
    // Low base conf — needs context boost; stopwords reject lab/exam titles.
    PatternDef {
        id: "person-before-date",
        category: Category::Person,
        regex: r"[A-Z][a-z]+(?:[ \t]+[A-Z][a-z]+){0,3}[ \t]+\d{1,2}[/\-.]\d{1,2}[/\-.]\d{2,4}",
        base_confidence: 0.25,
        context_keywords: &["patient", "name", "dob", "born"],
        validate: Some(person_before_date_name_valid),
    },
    // "Name: Kimberly Lawrence" / "Doctor Name: Anthony Rivera" (spaced).
    // Use [ \t]+ not \s+ so OCR newlines do not glue "Gallagher\nContact".
    PatternDef {
        id: "person-labeled-spaced",
        category: Category::Person,
        regex: r"(?:Doctor[ \t]+)?Name[ \t]*:[ \t]*[A-Z][a-z]+(?:[ \t]+[A-Z][a-z]+)+",
        base_confidence: 0.9,
        context_keywords: &["name", "doctor", "patient", "demographics"],
        validate: Some(person_name_valid),
    },
    // Sticky form fields: "Name: KimberlyLawrence" / "Doctor Name: CherylBlankenship"
    PatternDef {
        id: "person-labeled-glued",
        category: Category::Person,
        regex: r"(?:Doctor[ \t]+)?Name[ \t]*:[ \t]*[A-Z][a-z]+(?:[A-Z][a-z]+)+",
        base_confidence: 0.88,
        context_keywords: &["name", "doctor", "patient", "demographics"],
        validate: Some(person_name_valid),
    },
    // Facility / org with corporate or care suffix (sticky "INCPatient" ok — no trailing \b).
    // [ \t]+ not \s+ so a newline cannot glue "Medical\nInstitute INC" across lines.
    PatternDef {
        id: "org-corporate",
        category: Category::Other,
        regex: r"[A-Z][a-z]+(?:[ \t]+[A-Z][a-z]+){1,6}[ \t]+(?:INC|Inc|LLC|Ltd)",
        base_confidence: 0.75,
        context_keywords: &["institute", "hospital", "clinic", "medical", "facility"],
        validate: Some(org_name_valid),
    },
    // OCR / form: "Patient Name: Susan Frances Martin" (optional space after :).
    // Stop before "Date" by limiting to 2–4 name tokens; trailing stopwords trimmed in validate.
    PatternDef {
        id: "person-patient-name",
        category: Category::Person,
        regex: r"Patient[ \t]+Name[ \t]*:[ \t]*[A-Z][a-z]+(?:[ \t]+[A-Z][a-z]+){1,3}",
        base_confidence: 0.9,
        context_keywords: &["patient", "name", "demographics"],
        validate: Some(person_name_valid),
    },
    // "Dr. Brittany Gallagher" / "Provider: Dr. …"
    PatternDef {
        id: "person-dr-title",
        category: Category::Person,
        regex: r"Dr\.[ \t]+[A-Z][a-z]+(?:[ \t]+[A-Z][a-z]+){0,3}",
        base_confidence: 0.75,
        context_keywords: &["doctor", "provider", "physician", "signed", "fnp"],
        validate: Some(person_name_valid),
    },
    // Street line: "5891 Kenneth Ports" — spaces only (not \s) so years+newlines cannot glue.
    PatternDef {
        id: "us-street-address",
        category: Category::Other,
        regex: r"\b\d{1,6}[ \t]+[A-Z][A-Za-z]+(?:[ \t]+[A-Z][A-Za-z]+){0,4}[ \t]+(?:Street|St|Avenue|Ave|Road|Rd|Boulevard|Blvd|Lane|Ln|Drive|Dr|Way|Ways|Court|Ct|Place|Pl|Ports|Mountain|Villages|Heights|Circle|Cir|Parkway|Pkwy|Extension|Points)\b",
        base_confidence: 0.7,
        context_keywords: &["address", "location", "contact", "street", "mail"],
        validate: Some(street_address_valid),
    },
    // City-like: "New Amandafort" / "North Bradleytown" before a US state (OCR may use ". ").
    // Below the default floor (like us-state): adjacent state names ("Georgia,
    // Texas") are too common in prose to redact without an address keyword.
    PatternDef {
        id: "us-city-before-state",
        category: Category::Other,
        regex: concat!(
            r"(?i)\b(?:(?:New|North|South|West|East|Fort|Port|Lake|Mount|San|Saint)[ \t]+)?[A-Z][a-z]+(?:[ \t]+[A-Z][a-z]+)?[ \t,.]+(?:",
            us_states_alt!(),
            r")\b"
        ),
        base_confidence: 0.3,
        context_keywords: &[
            "address",
            "location",
            "united states",
            "contact",
            "ports",
            "villages",
        ],
        validate: Some(city_before_state_valid),
    },
    // US ZIP — weak alone; needs context boost to clear min_confidence.
    PatternDef {
        id: "us-zip",
        category: Category::Other,
        regex: r"\b\d{5}\b",
        base_confidence: 0.28,
        context_keywords: &[
            "zip",
            "postal",
            "address",
            "location",
            "united states",
            "states",
            "street",
            "ave",
            "road",
            "ports",
            "villages",
            "wyoming",
            "oklahoma",
            "idaho",
            "indiana",
            "texas",
            "florida",
            "california",
            "new york",
        ],
        validate: Some(us_zip_valid),
    },
    // US state names (common address PHI component in clinical corpora).
    // Low base: needs address context to clear the default floor (avoids
    // flagging every "Washington"/"Georgia" in prose and company names).
    PatternDef {
        id: "us-state",
        category: Category::Other,
        regex: concat!(r"(?i)\b(?:", us_states_alt!(), r")\b"),
        base_confidence: 0.3,
        context_keywords: &[
            "address",
            "location",
            "united states",
            "states",
            "zip",
            "contact",
            "ports",
            "villages",
            "street",
        ],
        validate: None,
    },
    // Below the default floor: "United States" appears in ordinary prose; only
    // redact when an address/location keyword is near.
    PatternDef {
        id: "country-us",
        category: Category::Other,
        regex: r"(?i)\bUnited States\b",
        base_confidence: 0.3,
        context_keywords: &["address", "location", "contact"],
        validate: None,
    },
];

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashSet;

    /// Patterns intentionally placed below the default 0.35 floor: they must
    /// only fire when a context keyword boosts them above it.
    /// **Adding a new pattern below the floor? Add its id here too.**
    const BELOW_FLOOR: &[&str] = &[
        "ssn-contiguous",
        "us-aba-routing",
        "us-phone-bare",
        "phone-intl",
        "date",
        "date-ocr-glued",
        "date-of-birth",
        "us-passport",
        "person-before-date",
        "us-city-before-state",
        "us-zip",
        "us-state",
        "country-us",
    ];

    #[test]
    fn every_pattern_compiles_and_ids_are_unique() {
        let mut ids = HashSet::new();
        for d in DEFS {
            assert!(ids.insert(d.id), "duplicate pattern id: {}", d.id);
            // Compile now (not lazily on first detection) so a catalog typo is
            // caught by the test suite instead of panicking at runtime.
            regex::Regex::new(d.regex)
                .unwrap_or_else(|e| panic!("pattern {:?} does not compile: {e}", d.id));
            assert!(
                (0.0..=1.0).contains(&d.base_confidence),
                "{}: base confidence {} out of range",
                d.id,
                d.base_confidence
            );
            assert!(
                !d.context_keywords.is_empty(),
                "{}: context_keywords must not be empty",
                d.id
            );
        }
        // Force the lazily-compiled catalog too (the one used in production).
        assert!(!PATTERNS.is_empty());
    }

    #[test]
    fn floor_intent_is_respected() {
        for d in DEFS {
            let below = d.base_confidence < crate::types::DEFAULT_MIN_CONFIDENCE;
            assert_eq!(
                below,
                BELOW_FLOOR.contains(&d.id),
                "{}: base {} is {} the 0.35 floor but should be the opposite",
                d.id,
                d.base_confidence,
                if below { "below" } else { "above" }
            );
        }
    }

    /// Catalog-level smoke test: each pattern's regex must match at least one
    /// known positive sample. Catches boundary/typo bugs that compile fine but
    /// match nothing.
    #[test]
    fn every_pattern_matches_a_positive_sample() {
        // (pattern id, positive sample string). The sample need only match the
        // regex — validator/keyword logic is tested elsewhere.
        let samples: &[(&str, &str)] = &[
            ("email", "jane.doe@example.com"),
            ("ssn-dashed", "SSN: 123-45-6789"),
            ("ssn-contiguous", "123456789"),
            ("credit-card", "4111 1111 1111 1111"),
            ("iban", "GB82 WEST 1234 5698 7654 32"),
            ("us-aba-routing", "021000021"),
            ("phone-intl", "+1 415-555-0132"),
            ("us-phone-bare", "4155550132"),
            ("ipv4", "192.168.1.1"),
            ("date", "Expires 24/05/2025"),
            ("date-ocr-glued", "DOB 09031951"),
            ("date-of-birth", "dob 09/03/1951"),
            ("date-of-birth", "dob 1951-09-03"), // ISO alternative
            ("us-passport", "passport A12345678"),
            ("hospital-id", "HOSP26508961"),
            ("provider-id", "DR14144B"),
            ("age-years-old", "46-year-old"),
            ("age-aged", "aged 56"),
            ("age-labeled", "Age: 46"),
            ("person-born-on", "Kimberly Lawrence, born on"),
            ("person-before-date", "Smith 24/05/1977"),
            ("person-labeled-spaced", "Name: Jane Doe"),
            ("person-labeled-glued", "Name: JaneDoe"),
            ("org-corporate", "Acme Institute INC"),
            ("person-patient-name", "Patient Name: Susan Frances Martin"),
            ("person-dr-title", "Dr. Brittany Gallagher"),
            ("us-street-address", "5891 Kenneth Ports"),
            ("us-city-before-state", "New Amandafort, Wyoming"),
            ("us-zip", "ZIP 97375"),
            ("us-state", "address Wyoming"),
            ("country-us", "United States"),
        ];
        for (id, sample) in samples {
            let pat = PATTERNS
                .iter()
                .find(|p| p.id == *id)
                .unwrap_or_else(|| panic!("unknown pattern id: {id}"));
            let m = pat
                .re
                .find(sample)
                .unwrap_or_else(|| panic!("pattern {id} does not match sample: {sample:?}"));
            // Verify the positive sample also passes the pattern's validator
            // (when one is present), so the smoke test does not silently accept
            // a sample that the validator would reject. Some patterns
            // intentionally capture trailing non-name context in the regex
            // (e.g. "Kimberly Lawrence, born on") so their validator only
            // validates the PII portion; skip those.
            const SKIP_VALIDATOR: &[&str] = &["person-born-on", "person-before-date"];
            if !SKIP_VALIDATOR.contains(id)
                && let Some(validate) = pat.validate
            {
                assert!(
                    validate(m.as_str()),
                    "pattern {id}: validator rejected positive sample {sample:?} (matched {m:?})",
                );
            }
        }
    }

    /// C04-01: `ssn-contiguous` and `us-aba-routing` share an identical regex
    /// (`\b\d{9}\b`). When a 9-digit number passes both validators on the same
    /// span, the cross-family dedup in `regex_detect` must keep only the
    /// higher-confidence finding. This test exercises the full detect path
    /// (regex + validator + dedup) by providing a number that satisfies both
    /// `ssn_valid` and `aba_routing_valid`, with keywords for both so both
    /// patterns clear the default floor.
    #[test]
    fn cross_family_dedup_for_shared_9digit_regex() {
        use crate::detect::regex_detect::detect_regex;
        use crate::types::{Category, DetectOptions};

        // 100010013 passes both ssn_valid and aba_routing_valid.
        // Keywords for both "ssn" and "routing" boost both patterns above
        // the default 0.35 floor.
        let text = "SSN: 100010013  routing number";
        let opts = DetectOptions::default();
        let matches = detect_regex(text, &opts);

        // At most one finding should survive on the 9-digit span — the dedup
        // keeps only the higher-confidence match.
        let nine_digit_matches: Vec<_> = matches.iter().filter(|m| m.text == "100010013").collect();
        assert_eq!(
            nine_digit_matches.len(),
            1,
            "expected exactly one finding on the 9-digit span, got {}: {:?}",
            nine_digit_matches.len(),
            nine_digit_matches,
        );

        // The survivor should be one of the two categories (ssn or routing).
        let cat = nine_digit_matches[0].category;
        assert!(
            cat == Category::Ssn || cat == Category::RoutingNumber,
            "expected Ssn or RoutingNumber, got {cat:?}",
        );
    }
}
