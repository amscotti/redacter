//! Independent verification of a redacted PDF.
//!
//! We always check **both**:
//! 1. **Parsed document** — re-open with hayro, re-extract text (decompressed
//!    content streams), inspect metadata.
//! 2. **Raw file bytes** — scan the emitted buffer for redacted strings, but
//!    **mask PDF stream bodies** first so compressed image/content binary
//!    cannot cause false positives on short numeric strings.
//!
//! Our writer (`apply`) always produces a **full save** (new document, no
//! incremental update / no `/Prev` chain). Deleted content is not left behind
//! as superseded objects. See PDF 32000 §7.5.6.

use serde::{Deserialize, Serialize};

use crate::apply::assert_rects_black;
use crate::engine::HayroDocument;
use crate::error::Result;
use crate::geometry::spaced_text;
use crate::types::{Rect, Region};

/// Minimum secret length verified by the content checks (text-removal and
/// raw-byte-scan).
///
/// Shorter secrets collide with ordinary words and PDF structure tokens
/// (a 2-char string like "10" appears in object numbers and lengths), so a
/// byte/text probe on them would be pure noise. The floor is shared by both
/// checks so a secret is never verified by one and silently skipped by the
/// other (C07-m3); secrets below it are skipped deliberately, not silently
/// (C07-n4).
///
/// The floor is applied to each *effective search form* independently: for
/// text-removal the normalized form is probed when it clears the floor and
/// the compact form only when it too clears it; raw-byte-scan applies the
/// same rule to the raw bytes and its compact form (see
/// [`contains_str_bytes`]). So a whitespace-spaced secret whose compact form
/// is short (e.g. `"1 2 3"` — norm 5 chars, compact 3) never probes the
/// compact form as a bare substring, and the two checks agree. The
/// `below_floor` counts are reported separately per check (C07-nit-1).
pub const MIN_SECRET_LEN: usize = 4;

/// Backward-compatible alias for [`MIN_SECRET_LEN`] (the raw scan's
/// historical name; kept for the public API and existing tests).
pub const RAW_SCAN_MIN_LEN: usize = MIN_SECRET_LEN;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CheckResult {
    pub id: String,
    pub passed: bool,
    pub detail: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VerificationResult {
    pub passed: bool,
    pub checks: Vec<CheckResult>,
}

/// Normalize text for containment checks (collapse whitespace, lowercase).
pub fn normalize_text(s: &str) -> String {
    s.chars()
        .map(|c| if c.is_whitespace() { ' ' } else { c })
        .collect::<String>()
        .split_whitespace()
        .collect::<Vec<_>>()
        .join(" ")
        .to_ascii_lowercase()
}

/// Whitespace-stripped lowercase form used for line-break/hyphenation-safe
/// containment checks (complement to [`normalize_text`]).
fn compact_text(s: &str) -> String {
    s.chars()
        .filter(|c| !c.is_whitespace())
        .collect::<String>()
        .to_ascii_lowercase()
}

fn extract_all_text(doc: &HayroDocument) -> Result<String> {
    let mut all = String::new();
    for i in 0..doc.page_count() {
        let page = doc.page_text(i)?;
        let (spaced, _) = spaced_text(&page);
        all.push_str(&spaced);
        // The '\n' separator feeds `compact_text`'s cross-page join: a secret
        // split across a page boundary is tested as whitespace-joined (safe
        // side). Removing this separator would weaken the compact check.
        // Note: `normalize_text` already collapses any whitespace (including
        // `\n`) to single spaces, so this separator only affects the compact
        // form (`compact_extracted`), not `norm_extracted` (C07-nit-2).
        all.push('\n');
    }
    Ok(all)
}

/// True when the secret (given as its precomputed normalized `n` and compact
/// `c` forms) still appears in the re-extracted text.
///
/// Each effective search form is probed only when it clears
/// [`MIN_SECRET_LEN`] itself — mirroring [`contains_str_bytes`], which guards
/// its compact probe the same way. In particular a short compact form derived
/// from a longer whitespace-spaced secret (`"1 2 3"` → `"123"`, 3 chars) is
/// never probed as a bare substring: any `"123"` in the extracted text (e.g.
/// inside an SSN) would otherwise spuriously fail text-removal.
fn extracted_still_contains(
    norm_extracted: &str,
    compact_extracted: &str,
    n: &str,
    c: &str,
) -> bool {
    (n.len() >= MIN_SECRET_LEN && norm_extracted.contains(n))
        || (c.len() >= MIN_SECRET_LEN && compact_extracted.contains(c))
}

/// Verify output bytes against the list of redacted source strings / regions.
///
/// Failures mean the caller must not write the file (pipeline enforces this).
pub fn verify_output(output: &[u8], regions: &[Region]) -> Result<VerificationResult> {
    Ok(verify_output_with_page_count(output, regions)?.0)
}

/// [`verify_output`] but also returns the output document's page count, so the
/// pipeline can feed it into the certificate without re-parsing the output a
/// second time (C10-1).
pub(crate) fn verify_output_with_page_count(
    output: &[u8],
    regions: &[Region],
) -> Result<(VerificationResult, usize)> {
    let secrets: Vec<String> = regions
        .iter()
        .filter(|r| r.included && !r.source_text.is_empty())
        .map(|r| r.source_text.clone())
        // Multi-hit redaction creates many regions with the same source text;
        // check each unique secret once.
        .collect::<std::collections::BTreeSet<_>>()
        .into_iter()
        .collect();

    let mut checks = Vec::new();

    // --- 1) text-removal (parsed / decompressed) ---
    let doc = HayroDocument::open(output.to_vec())?;
    let extracted = extract_all_text(&doc)?;
    let norm_extracted = normalize_text(&extracted);
    // Whitespace-stripped form: a secret split across a line break or
    // hyphenation ("jane.doe@example\n.com", "super-\nsecret") normalizes to
    // "jane.doe@example .com" / "super- secret", which the collapsed form
    // misses. Mirror contains_str_bytes so the parsed check sees what the raw
    // byte scan sees (C07-M2).
    //
    // `compact_text` is applied to both `norm_extracted` (above) and the raw
    // secret (line 115 below) deliberately: the normalized form collapses
    // whitespace to single spaces while the compact form strips *all*
    // whitespace, so the two inputs cover different gap-handling semantics
    // (C07-minor-4).
    let compact_extracted = compact_text(&norm_extracted);
    let mut still = Vec::new();
    let mut below_floor = 0usize;
    for s in &secrets {
        let n = normalize_text(s);
        let c = compact_text(s);
        // Below MIN_SECRET_LEN the probe is noise (see the constant's docs);
        // skip consistently with raw-byte-scan rather than silently checking.
        if n.len() < MIN_SECRET_LEN && c.len() < MIN_SECRET_LEN {
            below_floor += 1;
            continue;
        }
        // Probe each effective form only when it clears the floor itself
        // (see `extracted_still_contains`): a sub-floor compact form like
        // "123" must not be probed as a bare substring.
        if extracted_still_contains(&norm_extracted, &compact_extracted, &n, &c) {
            still.push(s.clone());
        }
    }
    let pages_touched: std::collections::BTreeSet<usize> = regions
        .iter()
        .filter(|r| r.included)
        .map(|r| r.page_index)
        .collect();
    checks.push(CheckResult {
        id: "text-removal".into(),
        passed: still.is_empty(),
        detail: if still.is_empty() {
            let skipped = if below_floor > 0 {
                format!(" ({} below MIN_SECRET_LEN skipped)", below_floor)
            } else {
                String::new()
            };
            format!(
                "verified {} of {} redaction(s) across {} page(s) via re-extracted text{}",
                secrets.len() - below_floor,
                secrets.len(),
                pages_touched.len(),
                skipped
            )
        } else {
            // Never embed the plaintext secret: VerificationResult is
            // Serialize and ships inside certificates / logs (C07-m2).
            format!(
                "still extractable after parse/decompress: {}",
                still
                    .iter()
                    .map(|s| format!("textSha256:{}", crate::cert::sha256_hex(s.as_bytes())))
                    .collect::<Vec<_>>()
                    .join(", ")
            )
        },
    });

    // --- 2) metadata-clean ---
    // Checks author/title/subject/keywords Info fields and any XMP/Metadata
    // stream. Producer/Creator are intentionally allowed (tool provenance —
    // `apply` sets them to "redact <ver>"), not PII (C07-minor-1).
    let meta = doc.metadata_snapshot();
    let mut bad_meta = Vec::new();
    for (name, val) in [
        ("title", &meta.title),
        ("author", &meta.author),
        ("subject", &meta.subject),
        ("keywords", &meta.keywords),
    ] {
        if val.as_ref().is_some_and(|s| !s.trim().is_empty()) {
            bad_meta.push(name.to_string());
        }
    }
    // Outside stream bodies (Info/XMP markers often live in dicts; XMP packet may be streamed).
    let mut masked = output.to_vec();
    mask_pdf_stream_bodies_in_place(&mut masked);
    // Note: this scans the *unmasked* `output` so an uncompressed XMP packet
    // is caught. A deflate-compressed XMP packet would not contain the literal
    // `<?xpacket` after compression — the `/Metadata` name-token check on
    // `masked` below is the real backstop in that case. Today `apply` sets
    // `xmp_metadata: false`, so this is a latent gap, not a current bypass
    // (C07-minor-1).
    let has_xmp_packet = contains_bytes(output, b"<?xpacket");
    // /Metadata key in non-stream structure is also a signal. Name-token
    // aware: a URL inside a literal string value must not trip it (C07-n2).
    let has_metadata_key = count_token_occurrences(&masked, b"/Metadata") > 0;
    let meta_ok = bad_meta.is_empty() && !has_xmp_packet && !has_metadata_key;
    checks.push(CheckResult {
        id: "metadata-clean".into(),
        passed: meta_ok,
        detail: if meta_ok {
            "no author/title/subject/keywords info fields, no XMP stream".into()
        } else {
            let mut parts = bad_meta;
            if has_xmp_packet || has_metadata_key {
                parts.push("XMP/Metadata".into());
            }
            format!("remaining metadata: {}", parts.join(", "))
        },
    });

    // --- 3) annotations-removed ---
    let annot_hits = count_token_occurrences(&masked, b"/Annots");
    checks.push(CheckResult {
        id: "annotations-removed".into(),
        passed: annot_hits == 0,
        detail: if annot_hits == 0 {
            "no annotations present".into()
        } else {
            format!("{annot_hits} /Annots reference(s) remain")
        },
    });

    // --- 4) raw-byte-scan (stream bodies masked) ---
    let mut raw_hits = Vec::new();
    let mut raw_below_floor = 0usize;
    for s in &secrets {
        if s.len() < MIN_SECRET_LEN {
            raw_below_floor += 1;
            continue;
        }
        if contains_str_bytes(&masked, s) {
            raw_hits.push(s.clone());
        }
    }
    checks.push(CheckResult {
        id: "raw-byte-scan".into(),
        passed: raw_hits.is_empty(),
        detail: if raw_hits.is_empty() {
            let skipped = if raw_below_floor > 0 {
                format!(" ({} below MIN_SECRET_LEN skipped)", raw_below_floor)
            } else {
                String::new()
            };
            format!(
                "no redacted string appears outside stream bodies (compressed streams masked){}",
                skipped
            )
        } else {
            format!(
                "{} redacted string(s) found in raw non-stream bytes",
                raw_hits.len()
            )
        },
    });

    // --- 5) full-save (not incremental update) ---
    // PDF 32000 §7.5.6: incremental saves append with /Prev and leave old objects.
    let is_incremental = count_token_occurrences(&masked, b"/Prev") > 0;
    checks.push(CheckResult {
        id: "full-save".into(),
        passed: !is_incremental,
        detail: if is_incremental {
            "trailer contains /Prev — looks like an incremental save; original objects may remain"
                .into()
        } else {
            "no /Prev chain in non-stream bytes (byte-level full-save probe)".into()
        },
    });

    // --- 6) pixel-removal (re-render the OUTPUT, assert black per region rect) ---
    // The rebuild rasterizes every page: output pages carry no text layer, so
    // text-removal is vacuous, and raw-byte-scan masks stream bodies, so it
    // cannot see secrets inside the embedded image streams. Re-rendering the
    // output and checking each region rect's interior is black is the only
    // pixel-level proof the ink was actually covered (M1) — and it re-opens the
    // output only, upholding the verify invariant. String-only regions
    // (`cmd_verify --string`) carry empty rects and are skipped.
    //
    // The pixel check is a 2×-fidelity best-effort: for solid-fill black
    // rectangles (all `apply` produces) the 2× render faithfully confirms the
    // ink was covered, but thin-ink shapes painted by `apply` at a higher
    // scale could round to a different pixel at this lower re-render scale
    // (C07-minor-3). This matches the verify invariant ("best-effort, never
    // a guarantee"). For pipeline runs apply's own post-paint M1 check
    // already sampled the same pixels at opts.scale; this pass is the
    // independent re-open for standalone `cmd_verify` on arbitrary outputs,
    // so the second render is deliberate (C07-m4).
    const PIXEL_CHECK_SCALE: f32 = 2.0;
    let mut pixel_failures = Vec::new();
    let mut pixel_rect_count = 0usize;
    {
        let mut rects_by_page: std::collections::BTreeMap<usize, Vec<Rect>> =
            std::collections::BTreeMap::new();
        for r in regions.iter().filter(|r| r.included && !r.rects.is_empty()) {
            rects_by_page
                .entry(r.page_index)
                .or_default()
                .extend(r.rects.iter().copied());
        }
        for (page_index, rects) in rects_by_page {
            let img = doc.render_page(page_index, PIXEL_CHECK_SCALE)?;
            let scaled: Vec<Rect> = rects.iter().map(|r| r.scale(PIXEL_CHECK_SCALE)).collect();
            pixel_rect_count += scaled.len();
            if let Err(e) = assert_rects_black(&img, &scaled) {
                pixel_failures.push(format!("page {}: {e}", page_index + 1));
            }
        }
    }
    checks.push(CheckResult {
        id: "pixel-removal".into(),
        passed: pixel_failures.is_empty(),
        detail: if pixel_failures.is_empty() {
            if pixel_rect_count == 0 {
                "no region rects to check (string-only verification)".into()
            } else {
                format!(
                    "re-rendered output at {PIXEL_CHECK_SCALE}×; \
                     {pixel_rect_count} redaction rect(s) are black"
                )
            }
        } else {
            format!(
                "redaction rect(s) not black in re-rendered output: {}",
                pixel_failures.join("; ")
            )
        },
    });

    let passed = checks.iter().all(|c| c.passed);
    Ok((VerificationResult { passed, checks }, doc.page_count()))
}

/// Replace PDF `stream`…`endstream` bodies with spaces for raw scanning.
///
/// Stream dictionaries and keywords stay intact so structure tokens remain
/// visible; binary payload cannot produce coincidental secret matches.
pub fn mask_pdf_stream_bodies(pdf: &[u8]) -> Vec<u8> {
    let mut out = pdf.to_vec();
    mask_pdf_stream_bodies_in_place(&mut out);
    out
}

/// In-place variant of [`mask_pdf_stream_bodies`] — avoids a second buffer
/// copy for callers that already own a mutable copy (C07-m4).
fn mask_pdf_stream_bodies_in_place(out: &mut [u8]) {
    let mut i = 0;
    while i < out.len() {
        // Comments must be skipped so `% stream` inside a comment is not
        // mistaken for a real stream start (C07-major-1(b)). (This is the
        // *outside*-body scan; `find_keyword_from` intentionally does NOT
        // skip comments/strings — it hunts `endstream` in raw binary body
        // bytes, requiring an EOL immediately before the keyword.)
        if let Some(next) = skip_comment(out, i) {
            i = next;
            continue;
        }
        // Keywords inside literal strings / hex strings / names must never
        // match: `<< /Title (stream) … >>` or a content stream containing
        // `(endstream) Tj` would otherwise start/stop the mask at the wrong
        // place — hiding a leak in dict structure or leaving one unmasked
        // (C07-M1).
        if let Some(next) = skip_string_name_or_hex(out, i) {
            i = next;
            continue;
        }
        if is_keyword_at(out, i, b"stream") && has_stream_eol(out, i + b"stream".len()) {
            let mut body_start = i + b"stream".len();
            // PDF mandates an EOL after `stream` (CRLF, LF, or CR). Consume
            // both bytes of a CRLF pair, or a single LF/CR, in one explicit
            // match so the EOL consumption is self-documenting (C07-minor-3).
            match out.get(body_start) {
                Some(b'\r') => {
                    body_start += 1;
                    if out.get(body_start) == Some(&b'\n') {
                        body_start += 1;
                    }
                }
                Some(b'\n') => body_start += 1,
                _ => {}
            }
            if let Some(end) = find_keyword_from(out, body_start, b"endstream") {
                for b in &mut out[body_start..end] {
                    *b = b' ';
                }
                i = end + b"endstream".len();
                continue;
            }
        }
        i += 1;
    }
}

/// True if `needle` appears as a PDF keyword at `idx` (not mid-token).
fn is_keyword_at(hay: &[u8], idx: usize, needle: &[u8]) -> bool {
    if idx + needle.len() > hay.len() {
        return false;
    }
    if &hay[idx..idx + needle.len()] != needle {
        return false;
    }
    let before_ok = idx == 0 || !is_name_char(hay[idx - 1]);
    let after = idx + needle.len();
    let after_ok = after >= hay.len() || !is_name_char(hay[after]);
    before_ok && after_ok
}

/// PDF 32000 §7.3.8.1: the `stream` keyword must be followed by an EOL
/// (CRLF, LF, or CR). Requiring it here (instead of any non-name char) stops
/// `stream` mid-token — e.g. `(stream)` in a literal string or `/stream` in a
/// name — from starting a bogus body (C07-M1).
///
/// **Caller contract:** the caller must first confirm a token boundary via
/// [`is_keyword_at`] before calling this function. `has_stream_eol` only
/// checks the byte *after* the keyword; it does not verify the byte *before*
/// it, so without `is_keyword_at`, `xstream\n…` (no separator before the
/// keyword) would be treated as a valid stream start (C07-minor-2).
fn has_stream_eol(hay: &[u8], after: usize) -> bool {
    matches!(hay.get(after), Some(b'\r') | Some(b'\n'))
}

/// Find a bare PDF keyword (`endstream`) at or after `from`, requiring it to
/// be immediately preceded by an EOL (PDF 32000 §7.3.8.1: `endstream` shall
/// be preceded by an EOL).
///
/// Unlike the outside-body token scan in [`mask_pdf_stream_bodies_in_place`],
/// this does **not** skip comments or strings: it scans raw stream-body bytes.
/// A body is arbitrary binary data, so a stray `(`/`%`/`<` byte whose "token"
/// closes *after* the true `endstream` must not be interpreted as a literal
/// string/comment that skips past the real end — that would extend masking to
/// the *next* `endstream` and blank real non-stream structure (dicts,
/// trailer, `/Prev`, `/Annots`, leaked strings) from the masked buffer, so
/// raw-byte-scan / full-save / annotations-removed would go blind. The EOL
/// requirement keeps `(endstream)` inside a literal string from matching (its
/// preceding byte is `(`), so the `(endstream) Tj` case still stops the mask
/// at the real keyword.
fn find_keyword_from(hay: &[u8], from: usize, needle: &[u8]) -> Option<usize> {
    let mut i = from;
    while i + needle.len() <= hay.len() {
        if is_keyword_at(hay, i, needle) && (i == from || matches!(hay[i - 1], b'\r' | b'\n')) {
            return Some(i);
        }
        i += 1;
    }
    None
}

fn is_name_char(b: u8) -> bool {
    b.is_ascii_alphanumeric() || b == b'_' || b == b'-' || b == b'.' || b == b'+'
}

/// Skip a PDF comment (`%` to end-of-line) starting at `i` (PDF 32000 §7.2.3).
/// Returns the index just past the trailing newline, or `None` if `hay[i]`
/// is not `%`. Comments must be skipped in token-counting and keyword-finding
/// loops so a `/Prev` inside a `% /Prev` comment is not mistaken for a real
/// token (false alarm on `cmd_verify` for arbitrary third-party outputs).
fn skip_comment(hay: &[u8], i: usize) -> Option<usize> {
    if hay.get(i) != Some(&b'%') {
        return None;
    }
    // Advance to just past the next CR, LF, or CRLF (or end of buffer).
    let mut j = i + 1;
    while j < hay.len() {
        match hay[j] {
            b'\r' => return Some(j + 1 + (j + 1 < hay.len() && hay[j + 1] == b'\n') as usize),
            b'\n' => return Some(j + 1),
            _ => j += 1,
        }
    }
    Some(j)
}

/// Skip a PDF literal string `(...)`, hex string `<...>` or name `/foo`
/// starting at `i`, returning the index just past the token (or `None`).
///
/// `<<` is a dictionary delimiter, not a hex string; a `<` only starts a hex
/// string when the content up to `>` is hex digits/whitespace. This keeps
/// keywords inside dicts findable while skipping string values wholesale.
fn skip_string_name_or_hex(hay: &[u8], i: usize) -> Option<usize> {
    match hay[i] {
        b'(' => skip_literal_string(hay, i),
        b'<' => skip_hex_string(hay, i),
        b'/' => skip_name(hay, i),
        _ => None,
    }
}

/// Skip literal/hex strings only (names are matched explicitly by
/// [`count_token_occurrences`]).
///
/// DO NOT unify with [`skip_string_name_or_hex`]: `count_token_occurrences`
/// searches for `/`-prefixed name tokens and must therefore *not* skip names
/// (skipping them would skip its own target). The masker searches for bare
/// keywords (`stream`/`endstream`) and *must* skip names. The asymmetry is
/// intentional and correct (C07-nit-3).
fn skip_literal_or_hex(hay: &[u8], i: usize) -> Option<usize> {
    match hay[i] {
        b'(' => skip_literal_string(hay, i),
        b'<' => skip_hex_string(hay, i),
        _ => None,
    }
}

/// Skip a PDF literal string `( … )` with nested parens and `\` escapes
/// (PDF 32000 §7.3.4.2).
fn skip_literal_string(hay: &[u8], start: usize) -> Option<usize> {
    let mut depth = 1usize;
    let mut i = start + 1;
    while i < hay.len() {
        match hay[i] {
            b'\\' => {
                i += 1;
                if i < hay.len() {
                    // Octal escapes are up to three digits (max 377).
                    if (b'0'..=b'7').contains(&hay[i]) {
                        let mut digits = 1;
                        while digits < 3 && i + 1 < hay.len() && (b'0'..=b'7').contains(&hay[i + 1])
                        {
                            i += 1;
                            digits += 1;
                        }
                    }
                    i += 1;
                }
            }
            b'(' => {
                depth += 1;
                i += 1;
            }
            b')' => {
                depth -= 1;
                if depth == 0 {
                    return Some(i + 1);
                }
                i += 1;
            }
            _ => i += 1,
        }
    }
    None // unterminated — not treated as a string
}

/// Skip a PDF hex string `<hex>`; only when the content up to `>` consists
/// of hex digits / whitespace (so `<<` dicts and other `<`-prefixed tokens
/// are left for keyword matching).
fn skip_hex_string(hay: &[u8], i: usize) -> Option<usize> {
    if i + 1 < hay.len() && hay[i + 1] == b'<' {
        return None;
    }
    let mut j = i + 1;
    while j < hay.len() {
        match hay[j] {
            b'>' => return Some(j + 1),
            b if b.is_ascii_hexdigit() || b.is_ascii_whitespace() => j += 1,
            _ => return None,
        }
    }
    None
}

/// Skip a PDF name `/foo` (incl. `#xx` escapes; PDF 32000 §7.3.5).
fn skip_name(hay: &[u8], i: usize) -> Option<usize> {
    let mut j = i + 1;
    while j < hay.len() {
        let b = hay[j];
        if b.is_ascii_whitespace() || is_delimiter(b) {
            break;
        }
        if b == b'#' {
            // `#` must be followed by two hex digits.
            j += 1;
            if j < hay.len() && hay[j].is_ascii_hexdigit() {
                j += 1;
            }
            if j < hay.len() && hay[j].is_ascii_hexdigit() {
                j += 1;
            }
        } else {
            j += 1;
        }
    }
    Some(j)
}

/// PDF delimiters (PDF 32000 §7.2.2): terminate a name token.
fn is_delimiter(b: u8) -> bool {
    matches!(
        b,
        b'(' | b')' | b'<' | b'>' | b'[' | b']' | b'{' | b'}' | b'/' | b'%'
    )
}

fn contains_bytes(hay: &[u8], needle: &[u8]) -> bool {
    if needle.is_empty() {
        return false;
    }
    hay.windows(needle.len()).any(|w| w == needle)
}

/// Search for `s` and a whitespace-compacted form (for card numbers etc.).
pub fn contains_str_bytes(hay: &[u8], s: &str) -> bool {
    let n = s.as_bytes();
    if n.is_empty() {
        return false;
    }
    if contains_bytes(hay, n) {
        return true;
    }
    // Strip *Unicode* whitespace (NBSP included) to mirror normalize_text:
    // the parsed-text and raw-byte checks must agree on what a "gap" is
    // (C07-n5).
    //
    // The compact form is built from a `String` (char-level filtering) then
    // converted to bytes via `into_bytes`, so it is valid UTF-8 — the raw
    // byte-window scan in `contains_bytes` is therefore sound for multi-byte
    // secrets (C07-minor-5).
    let compact: Vec<u8> = s
        .chars()
        .filter(|c| !c.is_whitespace())
        .collect::<String>()
        .into_bytes();
    if compact.len() >= MIN_SECRET_LEN && compact.as_slice() != n {
        return contains_bytes(hay, &compact);
    }
    false
}

/// Count occurrences of a `/`-prefixed name token (`/Annots`, `/Metadata`,
/// `/Prev`) outside literal/hex strings.
///
/// Unlike a raw substring scan, this does not flag dict *values* that merely
/// contain the token text (e.g. a URL `(…/Annots)` inside a string, C07-n2).
/// A name token is delimited by its leading `/` and a non-name char after the
/// token (`/Annots` vs `/AnnotsX`); the char before the `/` is irrelevant —
/// `…1 0 R/Metadata 11…` is a real name boundary.
fn count_token_occurrences(pdf: &[u8], token: &[u8]) -> usize {
    debug_assert!(token.starts_with(b"/"));
    let mut count = 0;
    let mut i = 0;
    while i < pdf.len() {
        if let Some(next) = skip_comment(pdf, i) {
            i = next;
            continue;
        }
        if let Some(next) = skip_literal_or_hex(pdf, i) {
            i = next;
            continue;
        }
        if i + token.len() <= pdf.len()
            && &pdf[i..i + token.len()] == token
            && (i + token.len() == pdf.len() || !is_name_char(pdf[i + token.len()]))
        {
            count += 1;
            i += token.len();
            continue;
        }
        i += 1;
    }
    count
}

/// Assert secrets are gone — shared by e2e and product.
pub fn assert_redacted(output: &[u8], secrets: &[&str]) -> Result<VerificationResult> {
    // String-only verification: no rects, so pixel-removal is skipped and
    // page_index only feeds the `pages_touched` detail count (0 is correct
    // for the caller's single-page assumption, C07-n1).
    let regions: Vec<Region> = secrets
        .iter()
        .map(|s| Region {
            page_index: 0,
            rects: vec![],
            source_text: (*s).to_string(),
            category: crate::types::Category::Custom,
            confidence: 1.0,
            included: true,
            source: crate::types::MatchSource::Manual,
        })
        .collect();
    verify_output(output, &regions)
}

/// Whether the PDF trailer appears to be an incremental update (`/Prev` present
/// outside stream bodies).
pub fn looks_like_incremental_save(pdf: &[u8]) -> bool {
    count_token_occurrences(&mask_pdf_stream_bodies(pdf), b"/Prev") > 0
}

#[cfg(test)]
mod tests {
    use super::*;

    fn pii_basic_input() -> Vec<u8> {
        std::fs::read(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../../testdata/fixtures/synthetic/pii_basic.pdf"
        ))
        .unwrap()
    }

    fn string_region(s: &str) -> Region {
        Region {
            page_index: 0,
            rects: vec![],
            source_text: s.into(),
            category: crate::types::Category::Custom,
            confidence: 1.0,
            included: true,
            source: crate::types::MatchSource::Manual,
        }
    }

    /// Build a minimal single-page PDF (empty content stream, blank render)
    /// whose object 5 is the given Info dict body.
    fn minimal_pdf(info_obj: &[u8]) -> Vec<u8> {
        let objects: Vec<Vec<u8>> = vec![
            b"<< /Type /Catalog /Pages 2 0 R >>".to_vec(),
            b"<< /Type /Pages /Kids [3 0 R] /Count 1 >>".to_vec(),
            b"<< /Type /Page /Parent 2 0 R /MediaBox [0 0 200 200] /Resources << >> /Contents 4 0 R >>"
                .to_vec(),
            b"<< /Length 0 >>\nstream\nendstream".to_vec(),
            info_obj.to_vec(),
        ];
        let mut out = Vec::new();
        out.extend_from_slice(b"%PDF-1.4\n");
        let mut offsets = Vec::new();
        for (i, obj) in objects.iter().enumerate() {
            offsets.push(out.len());
            out.extend_from_slice(format!("{} 0 obj\n", i + 1).as_bytes());
            out.extend_from_slice(obj);
            out.extend_from_slice(b"\nendobj\n");
        }
        let xref_pos = out.len();
        out.extend_from_slice(format!("xref\n0 {}\n", objects.len() + 1).as_bytes());
        out.extend_from_slice(b"0000000000 65535 f \n");
        for off in &offsets {
            out.extend_from_slice(format!("{off:010} 00000 n \n").as_bytes());
        }
        out.extend_from_slice(
            format!(
                "trailer\n<< /Size {} /Root 1 0 R /Info 5 0 R >>\nstartxref\n{xref_pos}\n%%EOF\n",
                objects.len() + 1
            )
            .as_bytes(),
        );
        out
    }

    #[test]
    fn count_annot_tokens() {
        let pdf = b"1 0 obj\n<< /Annots [5 0 R] >>\nendobj\n2 0 obj\n<< /Annots 6 0 R >>\nendobj\n";
        assert_eq!(count_token_occurrences(pdf, b"/Annots"), 2);
    }

    #[test]
    fn count_token_ignores_strings_and_longer_names() {
        // The literal-string URL must not count; `/AnnotsX` is a different
        // name (name chars after the token). Note `/` is a delimiter
        // (PDF 32000 §7.2.2), so `/Foo/Annots` is *two* names and the second
        // one is a real `/Annots` token.
        let pdf = b"<< /Annots (see https://x.example/Annots) /AnnotsX 1 /Foo/Annots 2 >>";
        assert_eq!(count_token_occurrences(pdf, b"/Annots"), 2);
        assert_eq!(count_token_occurrences(b"/Annots", b"/Annots"), 1);
    }

    #[test]
    fn verify_dedupes_secret_list() {
        let regions = vec![
            Region {
                page_index: 0,
                rects: vec![],
                source_text: "jane.doe@example.com".into(),
                category: crate::types::Category::Custom,
                confidence: 1.0,
                included: true,
                source: crate::types::MatchSource::Manual,
            },
            Region {
                page_index: 0,
                rects: vec![],
                source_text: "jane.doe@example.com".into(),
                category: crate::types::Category::Custom,
                confidence: 1.0,
                included: true,
                source: crate::types::MatchSource::Manual,
            },
        ];
        let input = pii_basic_input();
        // Verify a real redacted output (metadata stripped by apply).
        let out = crate::apply::apply_regions(&input, &[], &crate::types::ApplyOptions::default())
            .unwrap();
        let res = verify_output(&out, &regions).unwrap();
        let tr = res.checks.iter().find(|c| c.id == "text-removal").unwrap();
        assert!(tr.passed, "checks: {:?}", res.checks);
        // The two duplicate regions must collapse to one unique secret: the
        // detail count proves the secrets list was deduped.
        assert!(
            tr.detail.contains("verified 1 of 1 redaction"),
            "detail: {}",
            tr.detail
        );
    }

    #[test]
    fn mask_stream_hides_body_keeps_keyword() {
        let pdf = b"%PDF-1.4\n1 0 obj\n<< /Length 11 >>\nstream\nSECRET-SSN\nendstream\nendobj\n";
        let masked = mask_pdf_stream_bodies(pdf);
        assert!(
            !contains_bytes(&masked, b"SECRET-SSN"),
            "stream body should be masked"
        );
        assert!(contains_bytes(&masked, b"stream"));
        assert!(contains_bytes(&masked, b"endstream"));
        // Original unchanged.
        assert!(contains_bytes(pdf, b"SECRET-SSN"));
    }

    #[test]
    fn raw_scan_ignores_secret_only_in_stream() {
        // Minimal fake PDF with secret only inside a stream body.
        let pdf = b"%PDF-1.4\n1 0 obj\n<<>>\nstream\njane.doe@example.com\nendstream\nendobj\ntrailer\n<< /Size 1 >>\nstartxref\n0\n%%EOF\n";
        let masked = mask_pdf_stream_bodies(pdf);
        assert!(!contains_str_bytes(&masked, "jane.doe@example.com"));
    }

    #[test]
    fn raw_scan_catches_secret_outside_stream() {
        let pdf =
            b"%PDF-1.4\n% jane.doe@example.com\n1 0 obj\n<<>>\nstream\nxxx\nendstream\nendobj\n";
        let masked = mask_pdf_stream_bodies(pdf);
        assert!(contains_str_bytes(&masked, "jane.doe@example.com"));
    }

    #[test]
    fn masker_ignores_stream_keyword_inside_comment() {
        // A `% stream` comment must not be mistaken for a real stream start
        // (C07-major-1(b)): without skip_comment in the masker's main loop,
        // the word `stream` in the comment would falsely start body masking,
        // desyncing the scanner and leaving subsequent bytes unmasked.
        let pdf = b"%PDF-1.4\n% this is a stream object\n1 0 obj\n<< /Length 5 >>\nstream\nLEAK1\nendstream\nendobj\n";
        let masked = mask_pdf_stream_bodies(pdf);
        assert!(
            !contains_str_bytes(&masked, "LEAK1"),
            "real stream body after a %%comment containing 'stream' must be masked"
        );
    }

    #[test]
    fn masker_ignores_keywords_inside_literal_strings() {
        // `(stream)` / `(endstream)` inside literal strings must not start or
        // stop body masking (C07-M1): a leak sitting in dict structure must
        // stay visible to the raw scan.
        let pdf = b"%PDF-1.4\n1 0 obj\n<< /Title (stream) /Subject (SECRET-LEAK) >>\nendobj\n2 0 obj\n<< /Length 3 >>\nstream\nabc\nendstream\nendobj\n";
        let masked = mask_pdf_stream_bodies(pdf);
        assert!(
            contains_str_bytes(&masked, "SECRET-LEAK"),
            "dict structure must stay unmasked"
        );
        assert!(contains_bytes(&masked, b"(stream)"));
        assert!(
            !contains_bytes(&masked, b"abc"),
            "the real stream body must still be masked"
        );
    }

    #[test]
    fn masker_masks_through_endstream_inside_literal_string() {
        // `(endstream)` inside an uncompressed content stream must not stop
        // the mask early and leave the leak visible (C07-M1).
        let pdf = b"%PDF-1.4\n1 0 obj\n<< /Length 40 >>\nstream\n(endstream) Tj (SECRET-LEAK) Tj\nendstream\nendobj\n";
        let masked = mask_pdf_stream_bodies(pdf);
        assert!(
            !contains_str_bytes(&masked, "SECRET-LEAK"),
            "leak after a literal (endstream) must be masked"
        );
        assert!(contains_bytes(&masked, b"endstream"));
    }

    #[test]
    fn masker_stray_paren_in_body_does_not_desync_endstream_scan() {
        // A `(` byte in a stream body whose matching `)` lands *after* the
        // true endstream must not make the scan skip the true endstream and
        // extend masking to the *next* endstream — that would blank real
        // non-stream structure (trailer /Prev, /Annots, endobj) from the
        // masked buffer, so raw-byte-scan / full-save / annotations-removed
        // would go blind. The fix: `endstream` must be immediately
        // EOL-preceded and body bytes are scanned raw (no string/comment
        // interpretation).
        let pdf = b"%PDF-1.4\n1 0 obj\n<< /Length 40 >>\nstream\n(binary (junk\nendstream\n) still ) trailing\nendobj\ntrailer\n<< /Prev 42 /Annots [5 0 R] >>\nstartxref\n0\n%%EOF\n2 0 obj\n<< /Length 3 >>\nstream\nSECRET2\nendstream\nendobj\n";
        let masked = mask_pdf_stream_bodies(pdf);
        // Trailer structure between the two endstream tokens must stay visible.
        assert!(
            contains_bytes(&masked, b"/Prev"),
            "trailer /Prev must survive"
        );
        assert!(
            contains_bytes(&masked, b"/Annots"),
            "trailer /Annots must survive"
        );
        assert!(contains_bytes(&masked, b"endobj"));
        // Both real stream bodies are still masked.
        assert!(!contains_bytes(&masked, b"binary (junk"));
        assert!(!contains_bytes(&masked, b"SECRET2"));
    }

    #[test]
    fn stream_keyword_requires_eol() {
        // `stream` followed by a space (not an EOL) is not a body start per
        // PDF 32000 §7.3.8.1 — the masker must not treat it as one.
        let pdf = b"%PDF-1.4\n1 0 obj\n<< /Length 5 >>\nstream abc\nendstream\nendobj\n";
        let masked = mask_pdf_stream_bodies(pdf);
        assert!(contains_bytes(&masked, b"abc"));
    }

    #[test]
    fn stream_eol_crlf_lf_and_cr_forms() {
        for eol in [b"\r\n".as_slice(), b"\n".as_slice(), b"\r".as_slice()] {
            let mut pdf = Vec::new();
            pdf.extend_from_slice(b"%PDF-1.4\n1 0 obj\n<< /Length 3 >>\nstream");
            pdf.extend_from_slice(eol);
            pdf.extend_from_slice(b"SECRET-SSN\nendstream\nendobj\n");
            let masked = mask_pdf_stream_bodies(&pdf);
            assert!(
                !contains_str_bytes(&masked, "SECRET-SSN"),
                "body must be masked for EOL {eol:?}"
            );
        }
    }

    #[test]
    fn compact_card_number_match() {
        let hay = b"prefix 4111111111111111 suffix";
        assert!(contains_str_bytes(hay, "4111 1111 1111 1111"));
    }

    #[test]
    fn contains_str_bytes_strips_unicode_whitespace() {
        // NBSP (U+00A0) in the *secret* must count as a gap exactly like
        // normalize_text does (C07-n5): the compact form is what gets searched.
        let hay = b"4111111111111111";
        assert!(contains_str_bytes(
            hay,
            "4111\u{00a0}1111\u{00a0}1111\u{00a0}1111"
        ));
        assert!(contains_str_bytes(hay, "4111 1111 1111 1111"));
    }

    #[test]
    fn normalize_collapses_whitespace() {
        assert_eq!(normalize_text("  Foo \n Bar  "), "foo bar");
    }

    #[test]
    fn extracted_probe_respects_floor_per_form() {
        // "1 2 3": norm "1 2 3" (5 chars, clears the floor) but compact "123"
        // (3 chars, below the floor). The compact probe must be skipped, so an
        // extracted text containing "123" (e.g. an SSN "123-45-6789") must not
        // spuriously fail text-removal.
        assert!(!extracted_still_contains(
            "the ssn 123-45-6789 sits here",
            "the ssn 123-45-6789 sits here",
            "1 2 3",
            "123",
        ));
        // The normalized probe still applies when it clears the floor.
        assert!(extracted_still_contains(
            "prefix 1 2 3 suffix",
            "prefix 1 2 3 suffix",
            "1 2 3",
            "123",
        ));
        // A compact form that clears the floor is still probed (line-break /
        // word-gap splits, C07-M2).
        assert!(extracted_still_contains(
            "jane.doe@example .com",
            "jane.doe@example.com",
            "jane.doe@example.com",
            "jane.doe@example.com",
        ));
        // Below-floor secrets are not probed at all.
        assert!(!extracted_still_contains("ab", "ab", "a b", "ab"));
    }

    #[test]
    fn incremental_prev_detected() {
        let inc = b"%PDF-1.4\ntrailer\n<< /Size 2 /Prev 42 >>\nstartxref\n0\n%%EOF\n";
        assert!(looks_like_incremental_save(inc));
        let full = b"%PDF-1.4\ntrailer\n<< /Size 2 >>\nstartxref\n0\n%%EOF\n";
        assert!(!looks_like_incremental_save(full));
    }

    #[test]
    fn text_removal_fails_when_secret_still_in_text_layer() {
        // Negative path for the *only* content check that runs for --string
        // verification: the unredacted fixture still carries "example.com" in
        // its text layer. Its spaced extraction splits it ("exam ple.com"),
        // so this also proves the compact-form match catches line-break /
        // word-gap splits (C07-M2).
        let v = verify_output(&pii_basic_input(), &[string_region("example.com")]).unwrap();
        let tr = v.checks.iter().find(|c| c.id == "text-removal").unwrap();
        assert!(
            !tr.passed,
            "text-removal must fail on the unredacted input: {}",
            tr.detail
        );
    }

    #[test]
    fn failing_text_removal_detail_hashes_secret() {
        // C07-m2: failing details must never embed the plaintext secret —
        // VerificationResult is serialized into certificates and logs.
        let v = verify_output(&pii_basic_input(), &[string_region("example.com")]).unwrap();
        let tr = v.checks.iter().find(|c| c.id == "text-removal").unwrap();
        assert!(!tr.passed);
        assert!(tr.detail.contains("textSha256:"), "detail: {}", tr.detail);
        assert!(
            !tr.detail.contains("example.com"),
            "detail must not contain the plaintext secret: {}",
            tr.detail
        );
    }

    #[test]
    fn metadata_clean_fails_on_xmp_metadata() {
        // The synthetic fixture ships an XMP packet + a /Metadata reference in
        // its catalog — a failing metadata-clean negative path.
        let v = verify_output(&pii_basic_input(), &[string_region("example.com")]).unwrap();
        let mc = v.checks.iter().find(|c| c.id == "metadata-clean").unwrap();
        assert!(
            !mc.passed,
            "metadata-clean must fail on the fixture's XMP/Metadata: {}",
            mc.detail
        );
    }

    #[test]
    fn metadata_clean_fails_on_info_title() {
        let pdf = minimal_pdf(b"<< /Title (Leaked Title) >>");
        let v = verify_output(&pdf, &[string_region("irrelevant-string-xyz")]).unwrap();
        let mc = v.checks.iter().find(|c| c.id == "metadata-clean").unwrap();
        assert!(
            !mc.passed,
            "Info /Title must fail metadata-clean: {}",
            mc.detail
        );
    }

    #[test]
    fn metadata_clean_fails_on_utf16be_info_title() {
        // UTF-16BE (with BOM) Info values must not be dropped from the
        // snapshot — a secret-bearing /Title would silently pass otherwise
        // (C07-m1).
        let mut title = vec![0xFE, 0xFF];
        for u in "Leaked Title".encode_utf16() {
            title.extend_from_slice(&u.to_be_bytes());
        }
        let mut raw = b"<< /Title <".to_vec();
        for b in &title {
            raw.extend_from_slice(format!("{b:02X}").as_bytes());
        }
        raw.extend_from_slice(b"> >>");
        let pdf = minimal_pdf(&raw);
        let v = verify_output(&pdf, &[string_region("irrelevant-string-xyz")]).unwrap();
        let mc = v.checks.iter().find(|c| c.id == "metadata-clean").unwrap();
        assert!(
            !mc.passed,
            "UTF-16BE Info /Title must fail metadata-clean: {}",
            mc.detail
        );
    }

    #[test]
    fn pixel_removal_fails_on_unpainted_rect() {
        // Blank page renders white: a rect with no black ink must fail the
        // verify-level pixel check (negative path for pixel-removal).
        let pdf = minimal_pdf(b"<< >>");
        let v = verify_output(
            &pdf,
            &[Region {
                page_index: 0,
                rects: vec![Rect::new(50.0, 50.0, 40.0, 20.0)],
                source_text: "redacted-secret-123".into(),
                category: crate::types::Category::Custom,
                confidence: 1.0,
                included: true,
                source: crate::types::MatchSource::Manual,
            }],
        )
        .unwrap();
        let pr = v.checks.iter().find(|c| c.id == "pixel-removal").unwrap();
        assert!(
            !pr.passed,
            "pixel-removal must fail on a white rect: {}",
            pr.detail
        );
    }

    #[test]
    fn pixel_removal_sub_pixel_rect_fails_when_not_black() {
        // A 0.5 pt rect at the 2× check scale is a single 1 px cell; the 2 px
        // sampling margin leaves an empty interior. Without the full-region
        // fallback this silently passed without sampling a single pixel
        // (C07-m5).
        let pdf = minimal_pdf(b"<< >>");
        let v = verify_output(
            &pdf,
            &[Region {
                page_index: 0,
                rects: vec![Rect::new(100.0, 100.0, 0.5, 0.5)],
                source_text: "redacted-secret-123".into(),
                category: crate::types::Category::Custom,
                confidence: 1.0,
                included: true,
                source: crate::types::MatchSource::Manual,
            }],
        )
        .unwrap();
        let pr = v.checks.iter().find(|c| c.id == "pixel-removal").unwrap();
        assert!(
            !pr.passed,
            "sub-2px rect on white must fail pixel-removal: {}",
            pr.detail
        );
    }

    #[test]
    fn pixel_removal_passes_on_painted_sub_pixel_rect() {
        // Apply paints the same tiny rect black; verify must then sample the
        // 1 px cell (full-region fallback) and pass (C07-m5 positive path).
        let pdf = minimal_pdf(b"<< >>");
        let rect = Rect::new(100.0, 100.0, 0.5, 0.5);
        let region = Region {
            page_index: 0,
            rects: vec![rect],
            source_text: "redacted-secret-123".into(),
            category: crate::types::Category::Custom,
            confidence: 1.0,
            included: true,
            source: crate::types::MatchSource::Manual,
        };
        let out = crate::apply::apply_regions(
            &pdf,
            std::slice::from_ref(&region),
            &crate::types::ApplyOptions::default(),
        )
        .unwrap();
        let v = verify_output(&out, &[region]).unwrap();
        let pr = v.checks.iter().find(|c| c.id == "pixel-removal").unwrap();
        assert!(pr.passed, "painted 1px rect must pass: {}", pr.detail);
    }
}
