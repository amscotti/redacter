//! Hayro-backed PDF open / text extract / render.

use std::sync::Arc;

use hayro::hayro_interpret::util::TransformExt;
use hayro::hayro_interpret::{
    Context, InterpreterCache, InterpreterSettings, InterpreterWarning, interpret_page,
};
use hayro::hayro_syntax::Pdf;
use hayro::vello_cpu::color::palette::css::WHITE;
use hayro::{RenderCache, RenderSettings, render};
use image::RgbaImage;

#[cfg(test)]
use image::Rgba;
use kurbo::Rect as KurboRect;

use super::RasterOps;
use super::text_device::TextCollector;
use crate::error::{RedactError, Result};
use crate::types::PageText;

/// Opened PDF document with hayro.
///
/// The parsed [`Pdf`] is owned (no `Box::leak`): hayro's [`InterpreterCache`]
/// / [`RenderCache`] borrow from the xref, so keeping them per-document would
/// require a self-referential struct; instead they are constructed per call
/// (page_text / render_page). That costs one font parse per call — negligible
/// against rasterization — and keeps `redact-core` leak-free for long-running
/// processes (server, batch daemon, test harness). The input bytes stay shared
/// via `data` (hayro-syntax `PdfData: From<Arc<T>>`).
pub struct HayroDocument {
    data: Arc<Vec<u8>>,
    pdf: Pdf,
}

impl HayroDocument {
    pub fn open(bytes: impl Into<Vec<u8>>) -> Result<Self> {
        let data = Arc::new(bytes.into());
        // PdfData supports From<Arc<T>> (hayro-syntax data.rs), so hayro shares
        // the buffer with us instead of copying the whole document.
        let pdf = Pdf::new(data.clone()).map_err(|e| match e {
            hayro::hayro_syntax::LoadPdfError::Decryption(_) => RedactError::OpenPdf(
                "PDF is encrypted/password-protected; encrypted PDFs are not supported \
                 (the document would be exported without proper redaction, leaking plaintext)"
                    .into(),
            ),
            other => RedactError::OpenPdf(format!("{other:?}")),
        })?;
        Ok(Self { data, pdf })
    }

    pub fn page_count(&self) -> usize {
        self.pdf.pages().len()
    }

    pub fn bytes(&self) -> &[u8] {
        self.data.as_ref()
    }

    /// Unscaled render viewport (width, height) in points for a page.
    pub fn render_dimensions(&self, page_index: usize) -> Result<(f32, f32)> {
        let pages = self.pdf.pages();
        let page = pages
            .get(page_index)
            .ok_or(RedactError::PageOutOfRange(page_index, pages.len()))?;
        let (width, height) = page.render_dimensions();
        if width <= 0.0 || height <= 0.0 {
            return Err(RedactError::Other(format!(
                "page {page_index} has zero render dimensions ({width}x{height}); \
                 malformed/empty MediaBox"
            )));
        }
        Ok((width, height))
    }

    pub fn page_text(&self, page_index: usize) -> Result<PageText> {
        let pages = self.pdf.pages();
        let page = pages
            .get(page_index)
            .ok_or(RedactError::PageOutOfRange(page_index, pages.len()))?;
        let (width, height) = page.render_dimensions();
        if width <= 0.0 || height <= 0.0 {
            return Err(RedactError::Other(format!(
                "page {page_index} has zero render dimensions ({width}x{height}); \
                 malformed/empty MediaBox"
            )));
        }

        let settings = interpreter_settings();
        // Per-call cache: it borrows from the xref, so a per-document cache
        // would need a self-referential struct (see struct docs). One font
        // parse per call is negligible against rasterization.
        let interpreter_cache = InterpreterCache::new();
        let mut context = Context::new(
            // Same viewport transform hayro's own `render()` uses: y-flip,
            // `/Rotate` and crop-box origin all encoded, so glyph boxes land in
            // the same coordinate space as the rendered pixmap (not raw
            // unrotated page space).
            page.initial_transform(true).to_kurbo(),
            KurboRect::new(0.0, 0.0, width as f64, height as f64),
            &interpreter_cache,
            page.xref(),
            settings,
        );

        let mut collector = TextCollector::new(page_index, width, height);
        interpret_page(page, &mut context, &mut collector);
        Ok(collector.into_page_text())
    }

    /// Render page to RGBA at the given scale. Background is white.
    pub fn render_page(&self, page_index: usize, scale: f32) -> Result<RgbaImage> {
        if !scale.is_finite() || scale <= 0.0 {
            return Err(RedactError::Render(
                page_index,
                format!("scale must be finite and positive, got {scale}"),
            ));
        }
        let (width, height) = self.render_dimensions(page_index)?;
        let pages = self.pdf.pages();
        let page = &pages[page_index];

        // hayro's viewport is `Option<u16>`; a scale that would overflow the
        // `as u16` cast silently wraps to a corrupt tiny pixmap. Reject it.
        let max_scale = u16::MAX as f64 / (width as f64).max(height as f64);
        if scale as f64 > max_scale {
            return Err(RedactError::Render(
                page_index,
                format!(
                    "scale {scale} too large for {width}x{height} pt page \
                     (hayro viewport is u16; max scale ≈ {max_scale:.1})"
                ),
            ));
        }

        // Cap total pixels: the per-dimension u16 guard alone still admits
        // ~65535×65535×4 B ≈ 16 GiB of RGBA (e.g. scale 300 on a 200 pt page),
        // enough to OOM the process instead of erroring (DoS surface for
        // server/batch callers). Reject before hayro allocates the pixmap.
        const MAX_RENDER_PIXELS: f64 = 100_000_000.0; // ~100 MP ≈ 400 MB RGBA
        let pixels = width as f64 * height as f64 * scale as f64 * scale as f64;
        if pixels > MAX_RENDER_PIXELS {
            let mp = pixels / 1e6;
            let cap_mp = MAX_RENDER_PIXELS / 1e6;
            return Err(RedactError::Render(
                page_index,
                format!(
                    "scale {scale} too large for {width}x{height} pt page: \
                     would produce ~{mp:.0} MP ({pixels:.0} px; cap {cap_mp:.0} MP)"
                ),
            ));
        }

        let interpreter_settings = interpreter_settings();
        let render_settings = RenderSettings {
            x_scale: scale,
            y_scale: scale,
            bg_color: WHITE,
            ..Default::default()
        };

        // Per-call cache: it borrows from the xref (see struct docs).
        let render_cache = RenderCache::new();
        let pixmap = render(page, &render_cache, &interpreter_settings, &render_settings);
        let (pixmap_w, pixmap_h) = (pixmap.width() as u32, pixmap.height() as u32);

        // hayro paints the opaque background color first, so every pixel is
        // opaque and the premultiplied buffer equals straight RGBA. We
        // defensively un-premultiply any non-opaque pixel (alpha < 255) to
        // guard against future hayro compositing changes (soft masks,
        // transparency groups, anti-aliased edges) that could produce
        // premultiplied values — under-rendered RGB in the redaction render
        // path could affect OCR-based re-extraction.
        let mut buf = vec![0u8; pixmap_w as usize * pixmap_h as usize * 4];
        for (chunk, px) in buf.chunks_exact_mut(4).zip(pixmap.data()) {
            if px.a == 255 {
                chunk.copy_from_slice(&[px.r, px.g, px.b, px.a]);
            } else if px.a == 0 {
                chunk.copy_from_slice(&[255, 255, 255, 0]);
            } else {
                // Un-premultiply: divide RGB by alpha to recover straight alpha.
                let a = px.a as u32;
                chunk.copy_from_slice(&[
                    ((px.r as u32 * 255 + a / 2) / a).min(255) as u8,
                    ((px.g as u32 * 255 + a / 2) / a).min(255) as u8,
                    ((px.b as u32 * 255 + a / 2) / a).min(255) as u8,
                    px.a,
                ]);
            }
        }
        RgbaImage::from_raw(pixmap_w, pixmap_h, buf)
            .ok_or_else(|| RedactError::Render(page_index, "invalid pixmap dimensions".into()))
    }

    pub fn metadata_snapshot(&self) -> MetadataSnapshot {
        let m = self.pdf.metadata();
        // Info values may be PDFDocEncoding or UTF-16 (PDF 32000 §14.3.3).
        // Never drop a non-UTF-8 value: verification must still see the field
        // as non-empty, or a secret-bearing /Title in UTF-16BE would silently
        // pass metadata-clean (C07-m1).
        let decode = |field: &str, b: &Option<Vec<u8>>| match b {
            Some(bytes) => {
                let s = decode_info_string(bytes);
                if s.trim().is_empty() && !bytes.is_empty() {
                    tracing::debug!(
                        field,
                        len = bytes.len(),
                        "PDF metadata value is non-text; flagged as present"
                    );
                    Some("\u{FFFD} (non-text metadata value)".into())
                } else {
                    Some(s)
                }
            }
            None => None,
        };
        MetadataSnapshot {
            title: decode("title", &m.title),
            author: decode("author", &m.author),
            subject: decode("subject", &m.subject),
            keywords: decode("keywords", &m.keywords),
            creator: decode("creator", &m.creator),
            producer: decode("producer", &m.producer),
        }
    }
}

/// `InterpreterSettings` with a warning sink that surfaces hayro's
/// interpretation warnings via `tracing`.
///
/// The default sink is a no-op, which silently swallows
/// [`InterpreterWarning::UnsupportedFont`] (CID fonts with non-identity
/// encoding — text in such fonts is neither extracted nor rendered, so
/// detection misses it and it disappears from the rebuilt page) and
/// [`InterpreterWarning::ImageDecodeFailure`] (the image vanishes from the
/// rebuilt page). Neither failure is recoverable here, but both must be
/// observable in logs instead of vanishing without a trace.
fn interpreter_settings() -> InterpreterSettings {
    InterpreterSettings {
        warning_sink: Arc::new(|warning| match warning {
            InterpreterWarning::UnsupportedFont => {
                tracing::warn!(
                    "hayro: unsupported font (CID font with non-identity encoding); \
                     text in this font will not be extracted or rendered"
                );
            }
            InterpreterWarning::ImageDecodeFailure => {
                tracing::warn!("hayro: image decode failure; image will not be rendered");
            }
        }),
        ..Default::default()
    }
}

/// Decode a PDF Info string value (best-effort).
///
/// Handles UTF-16 (BOM'd, or BOM-less UTF-16BE with ASCII content — common in
/// the wild), falls back to UTF-8, and finally to a lossy representation so a
/// non-empty value is never silently dropped from verification snapshots.
fn decode_info_string(bytes: &[u8]) -> String {
    if let Some(s) = decode_utf16(bytes) {
        return s;
    }
    match std::str::from_utf8(bytes) {
        Ok(s) => s.to_string(),
        Err(_) => String::from_utf8_lossy(bytes).into_owned(),
    }
}

fn decode_utf16(bytes: &[u8]) -> Option<String> {
    // Explicit BOM → decode per endianness.
    if bytes.starts_with(&[0xFE, 0xFF]) {
        return decode_utf16_units(bytes, 2, true);
    }
    if bytes.starts_with(&[0xFF, 0xFE]) {
        return decode_utf16_units(bytes, 2, false);
    }
    // BOM-less UTF-16BE with ASCII content (NUL-interleaved high bytes).
    // Require min length ≥ 6 to reduce false positives on short sequences,
    // and an even length so every chunk is a full code unit. Note there is
    // deliberately no "UTF-8 decode failed" requirement: a NUL-interleaved
    // ASCII byte string is always valid UTF-8 (all bytes are 0x00-0x7F), so
    // such a guard would be dead code and real BOM-less UTF-16BE titles
    // would fall through to the lossy path as NUL-interleaved garbage. The
    // interleaved-NUL pattern is unambiguous for real titles — ordinary
    // PDFDocEncoding/UTF-8 strings never contain NUL high bytes.
    if bytes.len() >= 6
        && bytes.len().is_multiple_of(2)
        && bytes.chunks(2).all(|c| c[0] == 0 && c[1].is_ascii())
    {
        return Some(bytes.chunks(2).map(|c| c[1] as char).collect());
    }
    None
}

fn decode_utf16_units(bytes: &[u8], start: usize, big_endian: bool) -> Option<String> {
    let units: Vec<u16> = bytes[start..]
        .chunks_exact(2)
        .map(|c| {
            if big_endian {
                u16::from_be_bytes([c[0], c[1]])
            } else {
                u16::from_le_bytes([c[0], c[1]])
            }
        })
        .collect();
    String::from_utf16(&units).ok()
}

#[derive(Debug, Clone, Default)]
pub struct MetadataSnapshot {
    pub title: Option<String>,
    pub author: Option<String>,
    pub subject: Option<String>,
    pub keywords: Option<String>,
    pub creator: Option<String>,
    pub producer: Option<String>,
}

/// Paint black rectangles onto an image. Rects are in **pixel** coordinates.
///
/// Fails loudly on a non-finite or non-positive rect: a redactor must never
/// silently skip a rect — `NaN as i32` maps to 0 and negative dimensions yield
/// an empty loop, both leaving the secret fully visible while every verify
/// check passes. Callers (findings/pipeline/cli) validate rects up front; this
/// is the always-on backstop for the public `apply_regions` API.
pub fn paint_black_rects(img: &mut RgbaImage, rects: &[crate::types::Rect]) -> Result<()> {
    let (iw, ih) = (img.width() as i32, img.height() as i32);
    let black: [u8; 4] = [0, 0, 0, 255];
    for r in rects {
        if !r.is_valid() {
            return Err(RedactError::Other(format!(
                "paint_black_rects got invalid rect {r:?}"
            )));
        }
        let (x0, y0, x1, y1) = crate::types::rect_pixel_range(*r, iw, ih);
        for y in y0..y1 {
            for x in x0..x1 {
                img.get_pixel_mut(x as u32, y as u32).0 = black;
            }
        }
    }
    Ok(())
}

/// Engine-trait entry point: `apply` paints through `RasterOps` so a second
/// backend can provide its own painter without rewriting the rebuild step.
impl RasterOps for HayroDocument {
    fn paint_black_rects(img: &mut RgbaImage, rects: &[crate::types::Rect]) -> Result<()> {
        paint_black_rects(img, rects)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::Rect;

    fn white_img(w: u32, h: u32) -> RgbaImage {
        RgbaImage::from_pixel(w, h, Rgba([255, 255, 255, 255]))
    }

    #[test]
    fn paint_black_rects_paints_interior_only() {
        let mut img = white_img(10, 10);
        paint_black_rects(&mut img, &[Rect::new(2.0, 3.0, 4.0, 5.0)]).expect("valid rect");
        assert_eq!(img.get_pixel(3, 4), &Rgba([0, 0, 0, 255]));
        assert_eq!(img.get_pixel(2, 3), &Rgba([0, 0, 0, 255]));
        assert_eq!(img.get_pixel(5, 7), &Rgba([0, 0, 0, 255]));
        // Just outside the rect stays white.
        assert_eq!(img.get_pixel(1, 3), &Rgba([255, 255, 255, 255]));
        assert_eq!(img.get_pixel(3, 2), &Rgba([255, 255, 255, 255]));
        assert_eq!(img.get_pixel(6, 4), &Rgba([255, 255, 255, 255]));
        assert_eq!(img.get_pixel(3, 8), &Rgba([255, 255, 255, 255]));
    }

    #[test]
    fn paint_black_rects_clips_at_image_edges() {
        let mut img = white_img(4, 4);
        // Rect extends beyond every edge; must not panic and must blacken all pixels.
        paint_black_rects(&mut img, &[Rect::new(-3.0, -3.0, 10.0, 10.0)]).expect("valid rect");
        for y in 0..4 {
            for x in 0..4 {
                assert_eq!(img.get_pixel(x, y), &Rgba([0, 0, 0, 255]));
            }
        }
    }

    #[test]
    fn paint_black_rects_fully_offscreen_is_noop() {
        let mut img = white_img(4, 4);
        paint_black_rects(&mut img, &[Rect::new(100.0, 100.0, 10.0, 10.0)]).expect("valid rect");
        assert_eq!(img.get_pixel(0, 0), &Rgba([255, 255, 255, 255]));
        assert_eq!(img.get_pixel(3, 3), &Rgba([255, 255, 255, 255]));
    }

    #[test]
    fn paint_black_rects_rejects_invalid_rects() {
        // A non-finite / non-positive rect must fail loudly (m2): silently
        // skipping it would leave the secret visible while verify passes.
        let mut img = white_img(4, 4);
        for bad in [
            Rect::new(f32::NAN, 0.0, 5.0, 5.0),
            Rect::new(0.0, 0.0, f32::INFINITY, 5.0),
            Rect::new(0.0, 0.0, -1.0, 5.0),
            Rect::new(0.0, 0.0, 5.0, 0.0),
        ] {
            let err = paint_black_rects(&mut img, &[bad]).unwrap_err();
            assert!(
                matches!(&err, RedactError::Other(msg) if msg.contains("invalid rect")),
                "unexpected error: {err:?}"
            );
        }
        // Nothing may have been painted by the failed calls.
        for y in 0..4 {
            for x in 0..4 {
                assert_eq!(img.get_pixel(x, y), &Rgba([255, 255, 255, 255]));
            }
        }
    }

    #[test]
    fn paint_black_rects_rejects_saturating_coordinates() {
        // A finite rect with coordinates ~1e9 passes `is_finite` but makes
        // the floor/ceil `as i32` casts in `rect_pixel_range` saturate to an
        // empty clamped pixel range — it would silently paint nothing while
        // the secret stays visible (violating the never-skip backstop).
        let mut img = white_img(4, 4);
        for bad in [
            Rect::new(2e9, 0.0, 5.0, 5.0),
            Rect::new(0.0, -2e9, 5.0, 5.0),
            Rect::new(-3e9, -3e9, 6e9, 6e9),
            Rect::new(0.0, 0.0, 5.0, 5e9),
        ] {
            let err = paint_black_rects(&mut img, &[bad]).unwrap_err();
            assert!(
                matches!(&err, RedactError::Other(msg) if msg.contains("invalid rect")),
                "unexpected error: {err:?}"
            );
        }
        for y in 0..4 {
            for x in 0..4 {
                assert_eq!(img.get_pixel(x, y), &Rgba([255, 255, 255, 255]));
            }
        }
    }

    #[test]
    fn decode_info_string_bomless_utf16be() {
        // BOM-less UTF-16BE with ASCII content (NUL-interleaved high bytes)
        // must decode as "Hello" — not fall through to the lossy UTF-8 path
        // and surface as "\0H\0e\0l\0l\0o" (which verify would treat as a
        // present title and detection would mis-map).
        assert_eq!(
            decode_info_string(&[0x00, 0x48, 0x00, 0x65, 0x00, 0x6C, 0x00, 0x6C, 0x00, 0x6F]),
            "Hello"
        );
        // A normal UTF-8/PDFDocEncoding string must NOT be misidentified:
        // its high bytes are non-zero, so the NUL-interleaved pattern fails.
        assert_eq!(decode_info_string(b"Hello"), "Hello");
        assert_eq!(decode_info_string("Café".as_bytes()), "Café");
        // Explicit BOMs still win (LE here).
        assert_eq!(
            decode_info_string(&[0xFF, 0xFE, 0x48, 0x00, 0x69, 0x00]),
            "Hi"
        );
        // Short (< 6 byte) NUL-interleaved sequences stay on the UTF-8 path
        // (the length guard limits false positives).
        assert_eq!(decode_info_string(&[0x00, 0x41]), "\0A");
    }

    /// Load a system TrueType font for the embedded-font tests (same
    /// candidates as `redact-fixturegen`). Returns `None` on machines without
    /// any of them. The krilla `Font` is parsed purely as a sanity check that
    /// the bytes are a readable TrueType font before we embed them.
    fn test_font() -> Option<(Vec<u8>, krilla::text::Font)> {
        let candidates = [
            "/System/Library/Fonts/Supplemental/Arial.ttf",
            "/System/Library/Fonts/Supplemental/Times New Roman.ttf",
            "/Library/Fonts/Arial.ttf",
            "/usr/share/fonts/truetype/dejavu/DejaVuSans.ttf",
            "/usr/share/fonts/truetype/liberation/LiberationSans-Regular.ttf",
        ];
        for path in candidates {
            if let Ok(data) = std::fs::read(path)
                && let Some(font) = krilla::text::Font::new(Arc::new(data.clone()).into(), 0)
            {
                return Some((data, font));
            }
        }
        None
    }

    /// Build a minimal single-page PDF with an **embedded TrueType** text run
    /// "AB" at PDF coordinates (20, 30), with the given `/Rotate` value. Built
    /// at runtime so the engine tests need no fixture files.
    ///
    /// The font is a system TTF embedded via `/FontFile2` — not a non-embedded
    /// standard font — so the rendered ink matches the glyph outlines (see
    /// `fallback_font_render_quirk_documented` for why the fallback font cannot
    /// be used for box↔ink tests). The `/Widths` array feeds both the render
    /// and the extractor identically, so approximate widths are fine here.
    fn rotated_text_pdf(rotate: i64) -> Option<Vec<u8>> {
        let (font_bytes, _) = test_font()?;
        let content = b"BT /F1 12 Tf 20 30 Td (AB) Tj ET\n";
        // FirstChar 32 .. LastChar 90 inclusive → 59 widths.
        let widths = std::iter::repeat_n("500", 59).collect::<Vec<_>>().join(" ");
        let objects: Vec<Vec<u8>> = vec![
            b"<< /Type /Catalog /Pages 2 0 R >>".to_vec(),
            b"<< /Type /Pages /Kids [3 0 R] /Count 1 >>".to_vec(),
            format!(
                "<< /Type /Page /Parent 2 0 R /MediaBox [0 0 200 200] /Rotate {rotate} \
                 /Resources << /Font << /F1 4 0 R >> >> /Contents 5 0 R >>"
            )
            .into_bytes(),
            format!(
                "<< /Type /Font /Subtype /TrueType /BaseFont /ArialMT \
                 /FirstChar 32 /LastChar 90 /Widths [ {widths} ] \
                 /FontDescriptor << /Type /FontDescriptor /FontName /ArialMT /Flags 32 \
                 /FontBBox [-665 -325 2000 1006] /ItalicAngle 0 /Ascent 905 /Descent -212 \
                 /CapHeight 716 /StemV 80 /FontFile2 6 0 R >> >>"
            )
            .into_bytes(),
            {
                let mut obj = format!("<< /Length {} >>\nstream\n", content.len()).into_bytes();
                obj.extend_from_slice(content);
                obj.extend_from_slice(b"endstream");
                obj
            },
            {
                let mut obj = format!("<< /Length {} >>\nstream\n", font_bytes.len()).into_bytes();
                obj.extend_from_slice(&font_bytes);
                obj.extend_from_slice(b"endstream");
                obj
            },
        ];
        Some(assemble_pdf(objects))
    }

    /// Same layout as `rotated_text_pdf` but with a non-embedded `/Helvetica`
    /// standard font — hayro's fallback substitution path. Used only by
    /// `fallback_font_render_quirk_documented`.
    fn fallback_text_pdf(rotate: i64) -> Vec<u8> {
        let content = b"BT /F1 12 Tf 20 30 Td (AB) Tj ET\n";
        let objects: Vec<Vec<u8>> = vec![
            b"<< /Type /Catalog /Pages 2 0 R >>".to_vec(),
            b"<< /Type /Pages /Kids [3 0 R] /Count 1 >>".to_vec(),
            format!(
                "<< /Type /Page /Parent 2 0 R /MediaBox [0 0 200 200] /Rotate {rotate} \
                 /Resources << /Font << /F1 4 0 R >> >> /Contents 5 0 R >>"
            )
            .into_bytes(),
            b"<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica >>".to_vec(),
            {
                let mut obj = format!("<< /Length {} >>\nstream\n", content.len()).into_bytes();
                obj.extend_from_slice(content);
                obj.extend_from_slice(b"endstream");
                obj
            },
        ];
        assemble_pdf(objects)
    }

    /// A one-page PDF whose MediaBox collapses to zero area (malformed input).
    fn degenerate_page_pdf() -> Vec<u8> {
        let objects: Vec<Vec<u8>> = vec![
            b"<< /Type /Catalog /Pages 2 0 R >>".to_vec(),
            b"<< /Type /Pages /Kids [3 0 R] /Count 1 >>".to_vec(),
            b"<< /Type /Page /Parent 2 0 R /MediaBox [0 0 0 0] /Contents 4 0 R >>".to_vec(),
            b"<< /Length 0 >>\nstream\nendstream".to_vec(),
        ];
        assemble_pdf(objects)
    }

    /// Serialize numbered objects with a correct xref table into a PDF byte
    /// string (shared by the test PDF builders above).
    fn assemble_pdf(objects: Vec<Vec<u8>>) -> Vec<u8> {
        let mut out = Vec::new();
        out.extend_from_slice(b"%PDF-1.4\n%\xE2\xE3\xCF\xD3\n");
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
        for off in offsets {
            out.extend_from_slice(format!("{off:010} 00000 n \n").as_bytes());
        }
        out.extend_from_slice(
            format!(
                "trailer\n<< /Size {} /Root 1 0 R >>\nstartxref\n{xref_pos}\n%%EOF\n",
                objects.len() + 1
            )
            .as_bytes(),
        );
        out
    }

    fn intersect_area(a: &Rect, b: &Rect) -> f32 {
        let ix = (a.x + a.w).min(b.x + b.w) - a.x.max(b.x);
        let iy = (a.y + a.h).min(b.y + b.h) - a.y.max(b.y);
        ix.max(0.0) * iy.max(0.0)
    }

    /// Assert that the extracted glyph box (scaled to pixels) lines up with
    /// where the ink actually landed in the rendered image — the property the
    /// C1 rotation/crop-box bug broke.
    fn assert_glyph_box_matches_render(doc: &HayroDocument, rotate: i64) {
        let pt = doc.page_text(0).expect("page_text");
        assert_eq!(pt.text, "AB", "rotate={rotate}: text must be extracted");
        assert_eq!(pt.spans.len(), 2, "rotate={rotate}: two glyphs");
        let box_rect = pt.spans[0].rect.union(pt.spans[1].rect);

        let scale = 2.0;
        let img = doc.render_page(0, scale).expect("render");
        let (iw, ih) = (img.width(), img.height());
        assert_eq!((iw, ih), (400, 400), "rotate={rotate}: 200pt page @2x");

        // Tight bbox of non-white pixels = where the ink really is. Track the
        // min/max corners directly: seeding a `Rect` at the page corner and
        // unioning into it would pin the far corner at the page edge (union
        // never shrinks), inflating the measured ink to ~the whole page and
        // making every box↔ink comparison fail regardless of geometry.
        let mut min_x = iw as f32;
        let mut min_y = ih as f32;
        let mut max_x = 0.0_f32;
        let mut max_y = 0.0_f32;
        for y in 0..ih {
            for x in 0..iw {
                let p = img.get_pixel(x, y);
                if p[0] < 128 || p[1] < 128 || p[2] < 128 {
                    min_x = min_x.min(x as f32);
                    min_y = min_y.min(y as f32);
                    max_x = max_x.max((x + 1) as f32);
                    max_y = max_y.max((y + 1) as f32);
                }
            }
        }
        let ink = Rect::new(min_x, min_y, max_x - min_x, max_y - min_y);
        assert!(ink.w > 1.0, "rotate={rotate}: expected ink on the page");

        let scaled = box_rect.scale(scale);
        let ink_area = ink.w * ink.h;
        let inter = intersect_area(&scaled, &ink);
        let glyph_area = scaled.w * scaled.h;
        // The boxes should nearly coincide; a rotation bug leaves them disjoint.
        assert!(
            inter / ink_area > 0.6 && inter / glyph_area > 0.3,
            "rotate={rotate}: glyph box {scaled:?} vs ink {ink:?} (inter {inter})"
        );
    }

    #[test]
    fn page_text_matches_render_unrotated() {
        let doc =
            HayroDocument::open(rotated_text_pdf(0).expect("embedded test font")).expect("open");
        assert_glyph_box_matches_render(&doc, 0);
    }

    #[test]
    fn page_text_matches_render_rotated_90() {
        let doc =
            HayroDocument::open(rotated_text_pdf(90).expect("embedded test font")).expect("open");
        assert_glyph_box_matches_render(&doc, 90);
    }

    #[test]
    fn page_text_matches_render_rotated_180() {
        let doc =
            HayroDocument::open(rotated_text_pdf(180).expect("embedded test font")).expect("open");
        assert_glyph_box_matches_render(&doc, 180);
    }

    #[test]
    fn page_text_matches_render_rotated_270() {
        let doc =
            HayroDocument::open(rotated_text_pdf(270).expect("embedded test font")).expect("open");
        assert_glyph_box_matches_render(&doc, 270);
    }

    #[test]
    fn render_page_rejects_overflowing_scale() {
        // 200pt page → max scale ≈ 65535/200 ≈ 327; 400 would wrap the u16
        // viewport and produce a corrupt tiny pixmap.
        let doc =
            HayroDocument::open(rotated_text_pdf(0).expect("embedded test font")).expect("open");
        let err = doc.render_page(0, 400.0).unwrap_err();
        assert!(matches!(err, RedactError::Render(0, _)));
        assert!(doc.render_page(0, 2.0).is_ok(), "in-range scale must work");
    }

    #[test]
    fn render_page_rejects_oversized_pixmap() {
        // 200pt page at scale 200 → 40000×40000 ≈ 1.6e9 px ≈ 6.4 GB RGBA:
        // within the u16 viewport limit (max scale ≈ 327) but far beyond a
        // sane allocation. Must error out instead of OOMing the process.
        let doc =
            HayroDocument::open(rotated_text_pdf(0).expect("embedded test font")).expect("open");
        let err = doc.render_page(0, 200.0).unwrap_err();
        assert!(
            matches!(err, RedactError::Render(0, ref msg) if msg.contains("MP")),
            "expected pixel-cap error, got {err:?}"
        );
        // A moderately large-but-sane render (200pt page @ scale 10 →
        // 2000×2000 = 4 MP) still works under the cap.
        assert!(doc.render_page(0, 10.0).is_ok(), "4 MP render must work");
    }

    #[test]
    fn zero_area_media_box_is_handled_without_panic() {
        // A page whose MediaBox collapses to zero area is malformed input
        // (m3). hayro falls back to A4 render dimensions, and we must not
        // divide by zero in the u16 scale guard or hand hayro a 0-width
        // viewport — both `page_text` and `render_page` must stay sane.
        let doc = HayroDocument::open(degenerate_page_pdf()).expect("open");
        let pt = doc.page_text(0).expect("page_text");
        assert!(pt.width > 0.0 && pt.height > 0.0, "A4 fallback dims");
        let img = doc.render_page(0, 2.0).expect("render");
        assert!(img.width() > 0 && img.height() > 0, "A4 fallback pixmap");
    }

    #[test]
    fn open_rejects_garbage_bytes() {
        let err = HayroDocument::open(b"this is definitely not a pdf".to_vec()).err();
        assert!(matches!(err, Some(RedactError::OpenPdf(_))));
    }

    /// Fallback-substitution sanity: a non-embedded standard font (`/Helvetica`,
    /// no embedded program) must extract and render at the correct scale too.
    ///
    /// An earlier review believed hayro's fallback drew "AB" at a wildly wrong
    /// scale (~180×39 pt for 12 pt text) and the rotation tests were therefore
    /// pinned to an embedded TrueType font. That conclusion came from this
    /// suite's old ink measurement, which seeded the ink bbox at the page
    /// corner and (since `Rect::union` never shrinks) always reported ink
    /// reaching the page edges. With the measurement fixed, the fallback font's
    /// boxes and render line up like the embedded font's; the rotation tests
    /// could migrate back to `fallback_text_pdf` if desired.
    #[test]
    fn fallback_font_boxes_match_render() {
        let doc = HayroDocument::open(fallback_text_pdf(0)).expect("open");
        assert_glyph_box_matches_render(&doc, 0);
    }

    #[test]
    #[ignore]
    fn debug_dump_rotated_render() {
        let bytes = rotated_text_pdf(0).expect("embedded test font");
        std::fs::write("/tmp/rot.pdf", &bytes).unwrap();
        let doc = HayroDocument::open(bytes).unwrap();
        let pt = doc.page_text(0).unwrap();
        eprintln!("text={:?} spans={:?}", pt.text, pt.spans);
        let img = doc.render_page(0, 2.0).unwrap();
        img.save("/tmp/rot.png").unwrap();
    }

    #[test]
    #[ignore]
    fn debug_rot_transforms() {
        use hayro::hayro_interpret::font::Glyph;
        use hayro::hayro_interpret::{
            BlendMode, ClipPath, Device, GlyphDrawMode, Image, Paint, PathDrawMode, SoftMask,
        };
        use hayro::hayro_interpret::{
            Context, InterpreterCache, InterpreterSettings, interpret_page,
        };
        use kurbo::Affine;

        for rotate in [0i64, 90, 180, 270] {
            let doc =
                HayroDocument::open(rotated_text_pdf(rotate).expect("embedded test font")).unwrap();
            let page = &doc.pdf.pages()[0];
            let (w, h) = page.render_dimensions();
            let settings = InterpreterSettings::default();
            let interpreter_cache = InterpreterCache::new();
            let mut context = Context::new(
                page.initial_transform(true).to_kurbo(),
                kurbo::Rect::new(0.0, 0.0, w as f64, h as f64),
                &interpreter_cache,
                page.xref(),
                settings,
            );
            struct Probe {
                n: usize,
            }
            impl Device<'_> for Probe {
                fn set_soft_mask(&mut self, _: Option<SoftMask<'_>>) {}
                fn set_blend_mode(&mut self, _: BlendMode) {}
                fn draw_path(
                    &mut self,
                    _: &kurbo::BezPath,
                    _: Affine,
                    _: &Paint<'_>,
                    _: &PathDrawMode,
                ) {
                }
                fn push_clip_path(&mut self, _: &ClipPath) {}
                fn push_transparency_group(
                    &mut self,
                    _: f32,
                    _: Option<SoftMask<'_>>,
                    _: BlendMode,
                ) {
                }
                fn pop_clip_path(&mut self) {}
                fn pop_transparency_group(&mut self) {}
                fn draw_image(&mut self, _: Image<'_, '_>, _: Affine) {}
                fn draw_glyph(
                    &mut self,
                    _glyph: &Glyph<'_>,
                    transform: Affine,
                    glyph_transform: Affine,
                    _: &Paint<'_>,
                    _: &GlyphDrawMode,
                ) {
                    let o = transform * glyph_transform * kurbo::Point::new(0.0, 0.0);
                    let r = transform * glyph_transform * kurbo::Point::new(1.0, 0.0);
                    let u = transform * glyph_transform * kurbo::Point::new(0.0, 1.0);
                    eprintln!(
                        "glyph n={} origin=({:.3},{:.3}) adv=({:.3},{:.3}) len={:.3} up=({:.3},{:.3}) len={:.3}",
                        self.n,
                        o.x,
                        o.y,
                        r.x - o.x,
                        r.y - o.y,
                        ((r.x - o.x).powi(2) + (r.y - o.y).powi(2)).sqrt(),
                        u.x - o.x,
                        u.y - o.y,
                        ((u.x - o.x).powi(2) + (u.y - o.y).powi(2)).sqrt()
                    );
                    self.n += 1;
                }
            }
            let mut probe = Probe { n: 0 };
            eprintln!(
                "--- rotate={rotate} dims=({w},{h}) init={:?}",
                page.initial_transform(true)
            );
            interpret_page(page, &mut context, &mut probe);
        }
    }
}
