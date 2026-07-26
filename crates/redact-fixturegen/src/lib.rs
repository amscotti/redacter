//! Synthetic PDF fixture generation shared by the CLI and tests.
//!
//! Every fixture's ground-truth [`Meta`] is derived from the same data
//! structures that are drawn, so the committed `.meta.json` files cannot
//! silently drift from page content (C14-m1). The same helpers also power the
//! `--check` mode (byte-drift + meta-contract validation, C14-m3) and the
//! image-only "scanned" fixture for OCR coverage (C14-m2).
//!
//! Krilla page surfaces use a **top-left origin with y growing downward**
//! (via an internal flip of PDF's y-up space). Layout helpers below follow that.

use std::path::{Path, PathBuf};
use std::sync::Arc;

use anyhow::{Context, Result};
use krilla::Document;
use krilla::geom::{Point, Size};
use krilla::image::Image;
use krilla::page::PageSettings;
pub use krilla::text::Font;
use krilla::text::TextDirection;
use serde::Serialize;

// --- Shared synthetic PII (reserved/synthetic; not real people) ---

pub const EMAIL: &str = "jane.doe@example.com";
pub const SSN: &str = "123-45-6789";
/// Spaced so the detector must accept digit groups with separators.
pub const CARD: &str = "4111 1111 1111 1111";
pub const PHONE: &str = "+1 415-555-0132";
pub const IBAN: &str = "GB82 WEST 1234 5698 7654 32";
pub const EIN: &str = "12-3456789";
pub const ADDRESS: &str = "742 Evergreen Terrace, Springfield, IL 62704";
/// Checksum-valid but fictional ABA routing number (C14-n4): derived with the
/// ABA check-digit formula and not assigned to any real bank.
pub const ROUTING: &str = "123456780";

// --- Layout parameters shared by every writer (C14-n3) ---

pub const PAGE_W: f32 = 612.0;
pub const PAGE_H: f32 = 792.0;
pub const PAGE_MARGIN: f32 = 72.0;
pub const LINE_GAP: f32 = 22.0;
pub const BODY_SIZE: f32 = 12.0;
/// Bottom margin below which a writer refuses further lines, keeping synthetic
/// pages inside the MediaBox even if a fixture grows.
pub const OVERFLOW_MARGIN: f32 = 100.0;
/// Raster scale for the image-only (scanned) fixture: 3.0 ≈ 216 dpi.
pub const SCAN_SCALE: f32 = 3.0;

/// Ground truth for one fixture: what the page must and must not contain.
#[derive(Serialize)]
pub struct Meta {
    pub must_detect: Vec<MetaItem>,
    pub must_not_false_positive: Vec<String>,
}

#[derive(Serialize)]
pub struct MetaItem {
    pub text: String,
    pub category: String,
}

pub fn item(text: &str, category: &str) -> MetaItem {
    MetaItem {
        text: text.into(),
        category: category.into(),
    }
}

/// A fixture written by [`generate_all`] / [`generate_ocr_scanned`].
pub struct GeneratedFixture {
    /// Stable fixture name (matches the committed file base name).
    pub name: &'static str,
    /// Path the PDF was written to.
    pub pdf_path: PathBuf,
    /// Path the meta JSON was written to.
    pub meta_path: PathBuf,
    /// The ground truth derived from the same data that was drawn.
    pub meta: Meta,
}

impl GeneratedFixture {
    fn new(dir: &Path, name: &'static str, meta: Meta) -> Self {
        Self {
            name,
            pdf_path: dir.join(format!("{name}.pdf")),
            meta_path: dir.join(format!("{name}.meta.json")),
            meta,
        }
    }
}

fn write_meta(path: &Path, meta: &Meta) -> Result<()> {
    std::fs::write(path, serde_json::to_string_pretty(meta)?)
        .with_context(|| format!("write {}", path.display()))?;
    Ok(())
}

/// Emit the page-overflow warning for fields a form writer had to drop.
fn warn_dropped_fields(path: &Path, dropped: &[String]) {
    if !dropped.is_empty() {
        eprintln!(
            "warning: page overflow in {} — fields dropped: {}",
            path.display(),
            dropped.join(", ")
        );
    }
}

// --- Font loading (C14-n2) ---

/// Font candidate list tried when no `--font` / `REDACT_FONT` override is given.
const FONT_CANDIDATES: &[&str] = &[
    "/System/Library/Fonts/Supplemental/Arial.ttf",
    "/System/Library/Fonts/Supplemental/Times New Roman.ttf",
    "/Library/Fonts/Arial.ttf",
    "/usr/share/fonts/truetype/dejavu/DejaVuSans.ttf",
    "/usr/share/fonts/truetype/liberation/LiberationSans-Regular.ttf",
    "C:\\Windows\\Fonts\\arial.ttf",
    "C:\\Windows\\Fonts\\consola.ttf",
];

/// Load the fixture font, honoring an explicit `--font <path>` / `REDACT_FONT`
/// override before the built-in candidate list.
pub fn load_font(explicit: Option<&Path>) -> Result<Font> {
    if let Some(path) = explicit {
        return load_font_from(path)
            .with_context(|| format!("cannot load font from {}", path.display()));
    }
    for candidate in FONT_CANDIDATES {
        if let Ok(font) = load_font_from(Path::new(candidate)) {
            return Ok(font);
        }
    }
    anyhow::bail!(
        "no system TTF font found for fixture generation; install DejaVu or Arial, \
         or pass --font <path> (or set REDACT_FONT) to point at a TTF"
    )
}

fn load_font_from(path: &Path) -> Result<Font> {
    let data = std::fs::read(path)?;
    Font::new(Arc::new(data).into(), 0).context("krilla rejected the font data")
}

// --- Layout writers ---

/// Draw lines top-down. `start_y` is distance from the **top** of the page.
#[allow(clippy::too_many_arguments)]
pub fn write_text_pdf(
    path: &Path,
    font: &Font,
    lines: &[&str],
    w: f32,
    h: f32,
    start_y: f32,
    line_gap: f32,
    font_size: f32,
) -> Result<()> {
    let mut document = Document::new();
    let mut page = document.start_page_with(PageSettings::from_wh(w, h).context("page size")?);
    let mut surface = page.surface();
    // Krilla surface: y increases downward from the top.
    let mut y = start_y;
    for (idx, line) in lines.iter().enumerate() {
        // Pre-draw guard (unlike write_multipage/write_form_like, which check
        // post-draw): this writer has no caller-facing "dropped" list, so the
        // dropped count (lines.len() - idx) reflects lines never drawn.
        if y > h - OVERFLOW_MARGIN {
            eprintln!(
                "warning: page overflow in {} — lines dropped: {}",
                path.display(),
                lines.len() - idx
            );
            break;
        }
        surface.draw_text(
            Point::from_xy(PAGE_MARGIN, y),
            font.clone(),
            font_size,
            line,
            false,
            TextDirection::Auto,
        );
        y += line_gap;
    }
    surface.finish();
    page.finish();
    let pdf = document.finish().map_err(|e| anyhow::anyhow!("{e}"))?;
    std::fs::write(path, pdf).with_context(|| format!("write {}", path.display()))?;
    Ok(())
}

/// Multi-page variant of [`write_text_pdf`] sharing the same layout parameters,
/// write context, and page-overflow guard (C14-n3).
#[allow(clippy::too_many_arguments)]
pub fn write_multipage(
    path: &Path,
    font: &Font,
    pages: &[Vec<String>],
    w: f32,
    h: f32,
    start_y: f32,
    line_gap: f32,
    font_size: f32,
) -> Result<()> {
    let mut document = Document::new();
    for (pi, lines) in pages.iter().enumerate() {
        let mut page = document.start_page_with(PageSettings::from_wh(w, h).context("page size")?);
        let mut surface = page.surface();
        let mut y = start_y;
        for (idx, line) in lines.iter().enumerate() {
            surface.draw_text(
                Point::from_xy(PAGE_MARGIN, y),
                font.clone(),
                font_size,
                line,
                false,
                TextDirection::Auto,
            );
            y += line_gap;
            if y > h - OVERFLOW_MARGIN {
                // `idx` was already drawn: only lines after it were dropped.
                eprintln!(
                    "warning: page overflow in {} page {pi} — lines dropped: {}",
                    path.display(),
                    lines[idx + 1..].join(", ")
                );
                break;
            }
        }
        surface.finish();
        page.finish();
    }
    let pdf = document.finish().map_err(|e| anyhow::anyhow!("{e}"))?;
    std::fs::write(path, pdf).with_context(|| format!("write {}", path.display()))?;
    Ok(())
}

/// Two-column-ish form: label left, value right. Returns the labels of any
/// fields the page-overflow guard had to drop (empty when nothing was dropped)
/// so callers can warn about exactly the fields that were **not** drawn
/// (C14-n1: the just-drawn field must not appear in the list).
#[allow(clippy::too_many_arguments)]
pub fn write_form_like(
    path: &Path,
    font: &Font,
    title_font: &Font,
    title: &str,
    fields: &[(&str, &str)],
    footnotes: &[&str],
) -> Result<Vec<String>> {
    let w = PAGE_W;
    let h = PAGE_H;
    let mut document = Document::new();
    let mut page = document.start_page_with(PageSettings::from_wh(w, h).context("page size")?);
    let mut surface = page.surface();

    let mut y = 56.0;
    surface.draw_text(
        Point::from_xy(48.0, y),
        title_font.clone(),
        13.0,
        title,
        false,
        TextDirection::Auto,
    );
    y += 28.0;
    surface.draw_text(
        Point::from_xy(48.0, y),
        font.clone(),
        9.0,
        "Department of the Treasury — Internal Revenue Service (test fixture)",
        false,
        TextDirection::Auto,
    );
    y += 32.0;

    let mut dropped = Vec::new();
    for (idx, (label, value)) in fields.iter().enumerate() {
        surface.draw_text(
            Point::from_xy(48.0, y),
            font.clone(),
            10.0,
            label,
            false,
            TextDirection::Auto,
        );
        if !value.is_empty() {
            surface.draw_text(
                Point::from_xy(300.0, y),
                font.clone(),
                11.0,
                value,
                false,
                TextDirection::Auto,
            );
        }
        y += 20.0;
        if y > h - OVERFLOW_MARGIN {
            // `idx` was already drawn: only fields after it were dropped.
            dropped = fields[idx + 1..]
                .iter()
                .map(|(l, _)| (*l).to_string())
                .collect();
            break;
        }
    }

    y += 24.0;
    for note in footnotes {
        if y > h - OVERFLOW_MARGIN {
            // Pre-draw guard: `note` itself was not drawn, so it must appear
            // in the dropped list (no `.skip(1)` — it would under-report the
            // first dropped footnote, e.g. an overflow starting at the last
            // footnote would list nothing).
            eprintln!(
                "warning: page overflow in {} — footnotes dropped: {}",
                path.display(),
                footnotes
                    .iter()
                    .skip_while(|n| *n != note)
                    .copied()
                    .collect::<Vec<_>>()
                    .join(", ")
            );
            break;
        }
        surface.draw_text(
            Point::from_xy(48.0, y),
            font.clone(),
            9.0,
            note,
            false,
            TextDirection::Auto,
        );
        y += 14.0;
    }

    surface.finish();
    page.finish();
    let pdf = document.finish().map_err(|e| anyhow::anyhow!("{e}"))?;
    std::fs::write(path, pdf).with_context(|| format!("write {}", path.display()))?;
    Ok(dropped)
}

/// Image-only ("scanned") fixture: the text is rasterized and embedded as a
/// bitmap, so the page has **no text layer** — OCR is the only way to read it
/// back (C14-m2). Renders `lines` with the same layout as [`write_text_pdf`],
/// rasterizes through the hayro backend, and embeds the PNG via krilla's
/// `raster-images` support.
#[allow(clippy::too_many_arguments)]
pub fn write_scanned_pdf(
    path: &Path,
    font: &Font,
    lines: &[&str],
    w: f32,
    h: f32,
    start_y: f32,
    line_gap: f32,
    font_size: f32,
) -> Result<()> {
    // 1. Draw the text into an in-memory krilla document…
    let mut text_doc = Document::new();
    let mut page = text_doc.start_page_with(PageSettings::from_wh(w, h).context("page size")?);
    let mut surface = page.surface();
    let mut y = start_y;
    for (idx, line) in lines.iter().enumerate() {
        // Pre-draw guard mirroring write_text_pdf: rasterization silently
        // clips lines below the page bottom, so refuse and warn instead of
        // truncating the scanned fixture without notice as it grows.
        if y > h - OVERFLOW_MARGIN {
            eprintln!(
                "warning: page overflow in {} — lines dropped: {}",
                path.display(),
                lines.len() - idx
            );
            break;
        }
        surface.draw_text(
            Point::from_xy(PAGE_MARGIN, y),
            font.clone(),
            font_size,
            line,
            false,
            TextDirection::Auto,
        );
        y += line_gap;
    }
    surface.finish();
    page.finish();
    let text_pdf = text_doc.finish().map_err(|e| anyhow::anyhow!("{e}"))?;

    // 2. …rasterize it to RGBA (the text layer does not survive rasterization)…
    let doc = redact_core::HayroDocument::open(text_pdf)
        .with_context(|| format!("open scanned fixture source {}", path.display()))?;
    let rgba = doc
        .render_page(0, SCAN_SCALE)
        .with_context(|| format!("rasterize scanned fixture {}", path.display()))?;

    // 3. …and embed the PNG into a fresh document as the only content.
    let mut png = std::io::Cursor::new(Vec::new());
    image::DynamicImage::ImageRgba8(rgba)
        .write_to(&mut png, image::ImageFormat::Png)
        .map_err(|e| anyhow::anyhow!("encode scanned page as PNG: {e}"))?;
    let img = Image::from_png(png.into_inner().into(), true)
        .map_err(|e| anyhow::anyhow!("krilla rejected scanned PNG: {e}"))?;

    let mut out_doc = Document::new();
    let mut page = out_doc.start_page_with(PageSettings::from_wh(w, h).context("page size")?);
    let mut surface = page.surface();
    surface.draw_image(
        img,
        Size::from_wh(w, h).context("invalid embedded image size")?,
    );
    surface.finish();
    page.finish();
    let pdf = out_doc.finish().map_err(|e| anyhow::anyhow!("{e}"))?;
    std::fs::write(path, pdf).with_context(|| format!("write {}", path.display()))?;
    Ok(())
}

// --- Fixture definitions (single source of truth for content + meta) ---

/// Default synthetic fixture set (the four PDFs + metas committed under
/// `testdata/fixtures/synthetic/`).
pub fn generate_all(dir: &Path, font: &Font, title_font: &Font) -> Result<Vec<GeneratedFixture>> {
    Ok(vec![
        generate_pii_basic(dir, font)?,
        generate_multipage_mixed(dir, font)?,
        generate_clean_lorem(dir, font)?,
        generate_fake_w2(dir, font, title_font)?,
        generate_fake_1040(dir, font, title_font)?,
    ])
}

/// `pii_basic.pdf`: simple list, top-aligned.
pub fn generate_pii_basic(dir: &Path, font: &Font) -> Result<GeneratedFixture> {
    let lines: Vec<String> = vec![
        "CONFIDENTIAL - synthetic test document (not real PII)".to_string(),
        format!("Email: {EMAIL}"),
        format!("SSN: {SSN}"),
        format!("Credit card: {CARD}"),
        format!("Phone: {PHONE}"),
        format!("IBAN: {IBAN}"),
        "Notes: invoice total $42.00 - should not be redacted as PII by default.".to_string(),
    ];
    let lines_ref: Vec<&str> = lines.iter().map(String::as_str).collect();
    write_text_pdf(
        &dir.join("pii_basic.pdf"),
        font,
        &lines_ref,
        PAGE_W,
        PAGE_H,
        PAGE_MARGIN,
        LINE_GAP,
        BODY_SIZE,
    )?;
    let meta = Meta {
        // C14-n5: the page contains the phone and the e2e asserts its
        // redaction, so the ground truth must require it too.
        must_detect: vec![
            item(EMAIL, "email"),
            item(SSN, "ssn"),
            item("4111111111111111", "credit-card"),
            item(PHONE, "phone"),
            item(IBAN, "iban"),
        ],
        must_not_false_positive: vec!["CONFIDENTIAL".into(), "invoice".into()],
    };
    let fixture = GeneratedFixture::new(dir, "pii_basic", meta);
    write_meta(&fixture.meta_path, &fixture.meta)?;
    Ok(fixture)
}

/// `multipage_mixed.pdf`: three pages, one clean control page.
pub fn generate_multipage_mixed(dir: &Path, font: &Font) -> Result<GeneratedFixture> {
    let pages = vec![
        vec![
            "Page 1 - has email".to_string(),
            format!("Contact: {EMAIL}"),
        ],
        vec![
            "Page 2 - clean control page".to_string(),
            "Lorem ipsum dolor sit amet.".to_string(),
        ],
        vec![
            "Page 3 - has SSN".to_string(),
            format!("Taxpayer ID: {SSN}"),
        ],
    ];
    write_multipage(
        &dir.join("multipage_mixed.pdf"),
        font,
        &pages,
        PAGE_W,
        PAGE_H,
        PAGE_MARGIN,
        LINE_GAP,
        BODY_SIZE,
    )?;
    let meta = Meta {
        must_detect: vec![item(EMAIL, "email"), item(SSN, "ssn")],
        must_not_false_positive: vec!["Lorem ipsum".into(), "clean control page".into()],
    };
    let fixture = GeneratedFixture::new(dir, "multipage_mixed", meta);
    write_meta(&fixture.meta_path, &fixture.meta)?;
    Ok(fixture)
}

/// `clean_lorem.pdf`: control page with no identifiers at all.
pub fn generate_clean_lorem(dir: &Path, font: &Font) -> Result<GeneratedFixture> {
    let lines = [
        "Clean document",
        "Lorem ipsum dolor sit amet, consectetur adipiscing elit.",
        "No synthetic identifiers are present on this page.",
    ];
    write_text_pdf(
        &dir.join("clean_lorem.pdf"),
        font,
        &lines,
        PAGE_W,
        PAGE_H,
        PAGE_MARGIN,
        LINE_GAP,
        BODY_SIZE,
    )?;
    let meta = Meta {
        must_detect: vec![],
        must_not_false_positive: vec![],
    };
    let fixture = GeneratedFixture::new(dir, "clean_lorem", meta);
    write_meta(&fixture.meta_path, &fixture.meta)?;
    Ok(fixture)
}

/// `fake_w2.pdf`: looks more like a tax wage statement.
pub fn generate_fake_w2(dir: &Path, font: &Font, title_font: &Font) -> Result<GeneratedFixture> {
    let dropped = write_form_like(
        &dir.join("fake_w2.pdf"),
        font,
        title_font,
        "Form W-2 Wage and Tax Statement (SYNTHETIC — NOT A REAL FORM)",
        &[
            ("a Employee's SSN", SSN),
            ("c Employer name", "ACME PAYROLL LLC"),
            ("e Employee name", "JANE Q DOE"),
            ("f Employee address", ADDRESS),
            ("1 Wages, tips", "58420.00"),
            ("2 Federal income tax withheld", "7421.15"),
            ("4 Social security tax withheld", "3622.04"),
            ("Employee email (HR copy)", EMAIL),
            ("Daytime phone", PHONE),
            ("Direct deposit account", CARD),
        ],
        &[
            "This document is entirely fictional and for software testing only.",
            "Do not use these numbers for any real filing or identification.",
        ],
    )?;
    warn_dropped_fields(&dir.join("fake_w2.pdf"), &dropped);
    let meta = Meta {
        must_detect: vec![
            item(SSN, "ssn"),
            item(EMAIL, "email"),
            item(PHONE, "phone"),
            item("4111111111111111", "credit-card"),
        ],
        must_not_false_positive: vec!["58420.00".into(), "Wages".into()],
    };
    let fixture = GeneratedFixture::new(dir, "fake_w2", meta);
    write_meta(&fixture.meta_path, &fixture.meta)?;
    Ok(fixture)
}

/// `fake_1040_snippet.pdf`: return-style layout.
pub fn generate_fake_1040(dir: &Path, font: &Font, title_font: &Font) -> Result<GeneratedFixture> {
    let dropped = write_form_like(
        &dir.join("fake_1040_snippet.pdf"),
        font,
        title_font,
        "U.S. Individual Income Tax Return — 2024 (SYNTHETIC SAMPLE)",
        &[
            ("Your first name and middle initial", "JANE Q"),
            ("Last name", "DOE"),
            ("Your social security number", SSN),
            ("Home address", ADDRESS),
            ("Presidential Election Campaign", ""),
            ("Filing status: Single", ""),
            ("1z Total income", "61200"),
            // C14-n4: fictional (checksum-valid, unassigned) routing number;
            // the real Chase ABA would be a compliance smell in a "synthetic"
            // fixture and its detection was unasserted in the meta.
            ("Bank routing number (refund)", ROUTING),
            ("Account number", "4111111111111111"),
            ("Third party designee phone", PHONE),
            ("Email for e-file confirmation", EMAIL),
        ],
        &[
            "Synthetic IRS-like layout for redaction testing. All figures are fake.",
            &format!("IBAN (foreign account worksheet): {IBAN}"),
        ],
    )?;
    warn_dropped_fields(&dir.join("fake_1040_snippet.pdf"), &dropped);
    let meta = Meta {
        must_detect: vec![
            item(SSN, "ssn"),
            item(EMAIL, "email"),
            item(PHONE, "phone"),
            item("4111111111111111", "credit-card"),
            item(IBAN, "iban"),
            item(ROUTING, "routing-number"),
        ],
        must_not_false_positive: vec!["61200".into(), "Total income".into()],
    };
    let fixture = GeneratedFixture::new(dir, "fake_1040_snippet", meta);
    write_meta(&fixture.meta_path, &fixture.meta)?;
    Ok(fixture)
}

/// `ocr_scanned.pdf`: image-only fixture for OCR e2e coverage (C14-m2). Only
/// written on request (`--scanned`) so the committed fixture set stays the
/// default one.
pub fn generate_ocr_scanned(dir: &Path, font: &Font) -> Result<GeneratedFixture> {
    let lines: Vec<String> = vec![
        "SCANNED COPY - SYNTHETIC image-only fixture (no text layer)".to_string(),
        format!("Email: {EMAIL}"),
        format!("SSN: {SSN}"),
        format!("Phone: {PHONE}"),
    ];
    let lines_ref: Vec<&str> = lines.iter().map(String::as_str).collect();
    write_scanned_pdf(
        &dir.join("ocr_scanned.pdf"),
        font,
        &lines_ref,
        PAGE_W,
        PAGE_H,
        PAGE_MARGIN,
        LINE_GAP,
        BODY_SIZE,
    )?;
    let meta = Meta {
        must_detect: vec![item(EMAIL, "email"), item(SSN, "ssn"), item(PHONE, "phone")],
        must_not_false_positive: vec!["SCANNED COPY".into()],
    };
    let fixture = GeneratedFixture::new(dir, "ocr_scanned", meta);
    write_meta(&fixture.meta_path, &fixture.meta)?;
    Ok(fixture)
}

// --- Verification machinery (C14-m1/m3) ---

/// Normalize for comparison: strip every whitespace char so spaced values
/// ("4111 1111 1111 1111") compare equal to their unspaced needles
/// ("4111111111111111").
fn normalize(text: &str) -> String {
    text.chars().filter(|c| !c.is_whitespace()).collect()
}

/// Verify each fixture's ground truth against what redact-core actually
/// detects in the generated PDF (C14-m1): every `must_detect` item must be
/// found with its category, and no `must_not_false_positive` string may
/// appear inside any detection. Returns human-readable problems (empty = all
/// fixtures truthful).
pub fn meta_contract_problems(fixtures: &[GeneratedFixture]) -> Vec<String> {
    let opts = redact_core::DetectOptions::default();
    let mut problems = Vec::new();
    for fixture in fixtures {
        let bytes = match std::fs::read(&fixture.pdf_path) {
            Ok(b) => b,
            Err(e) => {
                problems.push(format!(
                    "{}: cannot read generated PDF: {e}",
                    fixture.pdf_path.display()
                ));
                continue;
            }
        };
        let doc = match redact_core::HayroDocument::open(bytes) {
            Ok(d) => d,
            Err(e) => {
                problems.push(format!(
                    "{}: cannot open generated PDF: {e}",
                    fixture.pdf_path.display()
                ));
                continue;
            }
        };
        let mut hits: Vec<(String, String)> = Vec::new();
        for page in 0..doc.page_count() {
            match doc.page_text(page) {
                Ok(text) => {
                    // Mirror the pipeline: detection runs over spaced text
                    // (line breaks become spaces), and unmapped hits still
                    // count as detections (they surface in the findings).
                    let (regions, unmapped) = redact_core::detect_page_regions(&text, &opts);
                    hits.extend(
                        regions
                            .iter()
                            .map(|r| (r.category.as_str().to_string(), r.source_text.clone())),
                    );
                    hits.extend(
                        unmapped
                            .into_iter()
                            .map(|m| (m.category.as_str().to_string(), m.text)),
                    );
                }
                Err(e) => problems.push(format!(
                    "{}: page {page} text extraction failed: {e}",
                    fixture.pdf_path.display()
                )),
            }
        }
        for want in &fixture.meta.must_detect {
            let needle = normalize(&want.text);
            let hit = hits.iter().any(|(category, text)| {
                category.as_str() == want.category && normalize(text).contains(&needle)
            });
            if !hit {
                problems.push(format!(
                    "{}: must_detect {}({}) not detected",
                    fixture.name, want.text, want.category
                ));
            }
        }
        for banned in &fixture.meta.must_not_false_positive {
            // A "must not false positive" entry is a string that the detector
            // must NOT flag as a detection. Mirror `must_detect` (which uses
            // `contains`) so a partial or over-long hit whose normalized text
            // merely contains the banned string is also caught.
            let needle = normalize(banned);
            if hits
                .iter()
                .any(|(_, text)| normalize(text).contains(&needle))
            {
                problems.push(format!(
                    "{}: false positive detected: {}",
                    fixture.name, banned
                ));
            }
        }
    }
    problems
}

/// Byte-compare freshly generated fixtures against the files already present
/// in `out_dir` (krilla output is deterministic: `Document::new()` never
/// attaches a `Metadata`, whose `creation_date` defaults to `None`, and krilla
/// calls no clock — so a byte diff is meaningful, C14-m3). Generated files
/// missing from `out_dir` are reported too. Additionally flags any committed
/// `.pdf` / `.meta.json` in `out_dir` that the generator did not produce
/// (orphan detection, C14-m4). Returns problems (empty = in sync).
pub fn byte_drift_problems(fixtures: &[GeneratedFixture], out_dir: &Path) -> Vec<String> {
    let mut problems = Vec::new();
    // Base names the generator produced (so we can detect orphans below).
    let produced: std::collections::HashSet<String> = fixtures
        .iter()
        .flat_map(|f| {
            [
                f.pdf_path
                    .file_name()
                    .map(|n| n.to_string_lossy().into_owned()),
                f.meta_path
                    .file_name()
                    .map(|n| n.to_string_lossy().into_owned()),
            ]
        })
        .flatten()
        .collect();
    for fixture in fixtures {
        for generated in [&fixture.pdf_path, &fixture.meta_path] {
            let file_name = generated
                .file_name()
                .map(|n| n.to_string_lossy().into_owned())
                .unwrap_or_default();
            let committed = out_dir.join(&file_name);
            if !committed.is_file() {
                problems.push(format!(
                    "{file_name}: generated but missing from {}",
                    out_dir.display()
                ));
                continue;
            }
            let fresh = match std::fs::read(generated) {
                Ok(b) => b,
                Err(e) => {
                    problems.push(format!("{file_name}: cannot read fresh output: {e}"));
                    continue;
                }
            };
            match std::fs::read(&committed) {
                Ok(existing) if existing != fresh => problems.push(format!(
                    "{file_name}: committed file differs from current generator output"
                )),
                Ok(_) => {}
                Err(e) => problems.push(format!("{file_name}: cannot read committed file: {e}")),
            }
        }
    }
    // C14-m4: flag committed `.pdf` / `.meta.json` files the generator no
    // longer emits (orphans that would silently rot in the committed tree).
    if let Ok(entries) = std::fs::read_dir(out_dir) {
        for entry in entries.flatten() {
            let path = entry.path();
            let is_managed = matches!(
                path.extension().and_then(|e| e.to_str()),
                Some("pdf") | Some("json")
            ) && path
                .file_name()
                .and_then(|n| n.to_str())
                .is_some_and(|n| n.ends_with(".pdf") || n.ends_with(".meta.json"));
            if !is_managed {
                continue;
            }
            let name = match path.file_name().map(|n| n.to_string_lossy().into_owned()) {
                Some(n) => n,
                None => continue,
            };
            if !produced.contains(&name) {
                problems.push(format!(
                    "{name}: committed file in {} is not produced by the generator (orphan)",
                    out_dir.display()
                ));
            }
        }
    }
    problems
}

#[cfg(test)]
mod tests {
    use super::*;
    use redact_core::HayroDocument;

    /// Try to load the fixture font; returns `None` when no candidate is
    /// available so font-dependent tests skip gracefully instead of failing
    /// on a minimal CI runner (C14-f6).
    fn fixture_font() -> Option<Font> {
        load_font(None).ok()
    }

    fn generate_into(dir: &Path) -> Option<Vec<GeneratedFixture>> {
        let font = fixture_font()?;
        let title_font = font.clone();
        Some(generate_all(dir, &font, &title_font).expect("generate fixtures"))
    }

    fn page_texts(bytes: &[u8]) -> Vec<String> {
        let doc = HayroDocument::open(bytes.to_vec()).expect("open generated PDF");
        (0..doc.page_count())
            .map(|p| doc.page_text(p).expect("page text").text)
            .collect()
    }

    #[test]
    fn pii_basic_has_one_page_with_all_secrets() {
        let dir = tempfile::tempdir().unwrap();
        let Some(fixtures) = generate_into(dir.path()) else {
            return;
        };
        let fixture = fixtures.iter().find(|f| f.name == "pii_basic").unwrap();
        let texts = page_texts(&std::fs::read(&fixture.pdf_path).unwrap());
        assert_eq!(texts.len(), 1);
        for needle in [EMAIL, SSN, CARD, PHONE, IBAN] {
            assert!(
                texts[0].contains(needle),
                "pii_basic missing {needle:?}: {:?}",
                texts[0]
            );
        }
    }

    #[test]
    fn multipage_has_three_pages_with_per_page_content() {
        let dir = tempfile::tempdir().unwrap();
        let Some(fixtures) = generate_into(dir.path()) else {
            return;
        };
        let fixture = fixtures
            .iter()
            .find(|f| f.name == "multipage_mixed")
            .unwrap();
        let texts = page_texts(&std::fs::read(&fixture.pdf_path).unwrap());
        assert_eq!(texts.len(), 3, "multipage fixture must have 3 pages");
        assert!(texts[0].contains(EMAIL), "page 1 must carry the email");
        assert!(!texts[0].contains(SSN), "page 1 must not carry the SSN");
        assert!(
            texts[1].contains("Lorem ipsum"),
            "page 2 is the clean control page"
        );
        assert!(texts[2].contains(SSN), "page 3 must carry the SSN");
    }

    #[test]
    fn form_fixtures_are_single_page_and_contain_secrets() {
        let dir = tempfile::tempdir().unwrap();
        let Some(fixtures) = generate_into(dir.path()) else {
            return;
        };
        for name in ["fake_w2", "fake_1040_snippet"] {
            let fixture = fixtures.iter().find(|f| f.name == name).unwrap();
            let texts = page_texts(&std::fs::read(&fixture.pdf_path).unwrap());
            assert_eq!(texts.len(), 1, "{name} must be a single page");
            for needle in [SSN, EMAIL, PHONE] {
                assert!(texts[0].contains(needle), "{name} missing {needle:?}");
            }
        }
        let w2 = fixtures.iter().find(|f| f.name == "fake_w2").unwrap();
        let w2_text = page_texts(&std::fs::read(&w2.pdf_path).unwrap());
        assert!(w2_text[0].contains("ACME PAYROLL LLC"));
        let t1040 = fixtures
            .iter()
            .find(|f| f.name == "fake_1040_snippet")
            .unwrap();
        let t1040_text = page_texts(&std::fs::read(&t1040.pdf_path).unwrap());
        assert!(
            t1040_text[0].contains(ROUTING),
            "routing number must be drawn"
        );
        assert!(t1040_text[0].contains(IBAN), "IBAN footnote must be drawn");
    }

    #[test]
    fn clean_lorem_has_no_detections() {
        let dir = tempfile::tempdir().unwrap();
        let Some(fixtures) = generate_into(dir.path()) else {
            return;
        };
        let fixture = fixtures.iter().find(|f| f.name == "clean_lorem").unwrap();
        let texts = page_texts(&std::fs::read(&fixture.pdf_path).unwrap());
        assert_eq!(texts.len(), 1);
        let opts = redact_core::DetectOptions::default();
        let hits = redact_core::detect(&texts[0], &opts);
        assert!(
            hits.is_empty(),
            "clean_lorem must produce no detections: {hits:?}"
        );
    }

    /// C14-m1: every meta contract must hold against real detection output.
    #[test]
    fn meta_contracts_hold_for_generated_fixtures() {
        let dir = tempfile::tempdir().unwrap();
        let Some(fixtures) = generate_into(dir.path()) else {
            return;
        };
        let problems = meta_contract_problems(&fixtures);
        assert!(
            problems.is_empty(),
            "meta contract violations:\n{}",
            problems.join("\n")
        );
    }

    /// C14-m3: regeneration is byte-deterministic (two temp dirs, same bytes).
    #[test]
    fn generation_is_deterministic() {
        let Some(font) = fixture_font() else {
            return;
        };
        let title_font = font.clone();
        let dir_a = tempfile::tempdir().unwrap();
        let dir_b = tempfile::tempdir().unwrap();
        let a = generate_all(dir_a.path(), &font, &title_font).unwrap();
        let b = generate_all(dir_b.path(), &font, &title_font).unwrap();
        assert_eq!(a.len(), b.len());
        for (fa, fb) in a.iter().zip(&b) {
            assert_eq!(fa.name, fb.name);
            assert_eq!(
                std::fs::read(&fa.pdf_path).unwrap(),
                std::fs::read(&fb.pdf_path).unwrap(),
                "{} PDF bytes differ between runs",
                fa.name
            );
            assert_eq!(
                std::fs::read(&fa.meta_path).unwrap(),
                std::fs::read(&fb.meta_path).unwrap(),
                "{} meta bytes differ between runs",
                fa.name
            );
        }
    }

    /// C14-m3: the drift checker passes on freshly generated output.
    #[test]
    fn byte_drift_check_passes_on_fresh_output() {
        let dir = tempfile::tempdir().unwrap();
        let Some(fixtures) = generate_into(dir.path()) else {
            return;
        };
        assert!(
            byte_drift_problems(&fixtures, dir.path()).is_empty(),
            "fresh output must not drift from itself"
        );
    }

    /// C14-n1: the overflow guard's dropped list must start at the first
    /// field that was never drawn, not at the just-drawn one.
    #[test]
    fn overflow_dropped_list_excludes_the_last_drawn_field() {
        let dir = tempfile::tempdir().unwrap();
        let Some(font) = fixture_font() else {
            return;
        };
        let title_font = font.clone();
        let path = dir.path().join("overflow.pdf");
        let labels: Vec<String> = (0..60).map(|i| format!("Field {i}")).collect();
        let fields: Vec<(&str, &str)> = labels.iter().map(|l| (l.as_str(), "value")).collect();
        let dropped =
            write_form_like(&path, &font, &title_font, "Overflow test", &fields, &[]).unwrap();

        // Fields start at y=56+28+32=116 and advance 20 pt each; the guard
        // fires after drawing field 28 (next y = 696 > 692 = 792 − 100), so
        // fields 29..=59 (31 fields) are dropped.
        assert_eq!(
            dropped.len(),
            31,
            "expected fields 29..59 dropped, got {dropped:?}"
        );
        assert_eq!(dropped.first().map(String::as_str), Some("Field 29"));
        assert_eq!(dropped.last().map(String::as_str), Some("Field 59"));
        assert!(
            !dropped.iter().any(|l| l == "Field 28"),
            "already-drawn field must not be listed as dropped: {dropped:?}"
        );
    }

    /// C14-m2: the scanned fixture is image-only (no text layer) and the
    /// embedded raster actually carries ink.
    #[test]
    fn scanned_fixture_is_image_only_with_ink() {
        let dir = tempfile::tempdir().unwrap();
        let Some(font) = fixture_font() else {
            return;
        };
        generate_ocr_scanned(dir.path(), &font).unwrap();
        let bytes = std::fs::read(dir.path().join("ocr_scanned.pdf")).unwrap();
        let doc = HayroDocument::open(bytes).expect("open scanned fixture");
        assert_eq!(doc.page_count(), 1);
        assert!(
            doc.page_text(0).map(|t| t.text.is_empty()).unwrap_or(true),
            "scanned fixture must have no text layer"
        );
        let img = doc.render_page(0, 1.0).expect("render scanned page");
        assert!(img.width() > 0 && img.height() > 0);
        let non_white = img
            .pixels()
            .filter(|p| p.0.iter().any(|c| *c < 200))
            .count();
        assert!(non_white > 100, "scanned raster looks blank");
    }

    /// C14-n2: `write_multipage` uses a post-draw overflow guard (like
    /// `write_form_like`); confirm a page that overflows keeps the just-drawn
    /// line and drops only the subsequent ones (parallel to the form test).
    #[test]
    fn multipage_overflow_keeps_drawn_lines() {
        let dir = tempfile::tempdir().unwrap();
        let Some(font) = fixture_font() else {
            return;
        };
        let path = dir.path().join("overflow_mp.pdf");
        // One page with enough lines to overflow, plus a second page to ensure
        // pagination still works after the guard breaks out of the first page.
        let big_page: Vec<String> = (0..60).map(|i| format!("Line {i}")).collect();
        let pages = vec![big_page, vec!["Second page".to_string()]];
        write_multipage(
            &path,
            &font,
            &pages,
            PAGE_W,
            PAGE_H,
            PAGE_MARGIN,
            LINE_GAP,
            BODY_SIZE,
        )
        .unwrap();
        let texts = page_texts(&std::fs::read(&path).unwrap());
        assert_eq!(texts.len(), 2, "must still emit both pages");
        // Line 0 starts at PAGE_MARGIN=72 and advances LINE_GAP=22 each; the
        // guard fires after the line whose next y exceeds 792−100=692, i.e.
        // after y=72+28*22=688 → next 710 > 692, so Line 28 is the last drawn.
        assert!(
            texts[0].contains("Line 28"),
            "last-drawn line must survive: {:?}",
            texts[0]
        );
        assert!(
            !texts[0].contains("Line 29"),
            "first dropped line must not appear: {:?}",
            texts[0]
        );
    }
}
