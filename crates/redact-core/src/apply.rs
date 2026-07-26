//! Rasterize pages, paint redactions, rebuild PDF with krilla.
//!
//! **Always a full save:** we create a brand-new `Document` and serialize once.
//! There is no incremental update (`/Prev`), no copy of original content streams
//! for redacted pages, and no superseded objects left in the file (PDF 32000
//! §7.5.6). Pages are image-only rebuilds so original text objects never re-enter.

use std::sync::Arc;

use krilla::Document;
use krilla::SerializeSettings;
use krilla::geom::Size;
use krilla::image::Image as KrillaImage;
use krilla::metadata::Metadata;
use krilla::page::PageSettings;

use crate::engine::{HayroDocument, RasterOps};
use crate::error::{RedactError, Result};
use crate::types::{ApplyOptions, Rect, Region};

const TOOL_NAME: &str = "redact";
const TOOL_VERSION: &str = env!("CARGO_PKG_VERSION");

/// A painted pixel must be below this threshold in every RGB channel to count
/// as black (matches the integration coverage test in `tests/visual_coverage.rs`).
pub const NEAR_BLACK: u8 = 40;

/// Apply included regions: rasterize every page, paint black boxes on hit pages, rebuild PDF.
pub fn apply_regions(input: &[u8], regions: &[Region], opts: &ApplyOptions) -> Result<Vec<u8>> {
    let doc = HayroDocument::open(input.to_vec())?;
    apply_regions_in(&doc, regions, opts)
}

/// [`apply_regions`] against an already-open document, so pipeline entry
/// points that already parsed the input (C10-m1) don't re-open it for the
/// apply stage (C12-m2).
pub(crate) fn apply_regions_in(
    doc: &HayroDocument,
    regions: &[Region],
    opts: &ApplyOptions,
) -> Result<Vec<u8>> {
    // Validate scale up front: `f32::max` clamping would silently discard user
    // intent (`--scale nan` / `-5` / `0` would all quietly render at 0.5), which
    // is inconsistent with the explicit NaN handling elsewhere in the codebase.
    if !opts.scale.is_finite() || opts.scale <= 0.0 {
        return Err(RedactError::InvalidInput(format!(
            "apply: scale must be finite and positive, got {}",
            opts.scale
        )));
    }
    // Validate pad up front: `padded_rect` is called for every region rect, and
    // a non-finite `pad` (`--pad nan` / `--pad inf`) must surface as a usage
    // error (exit 2), not an `assert!` panic (process abort, exit via signal).
    // Negative `pad` shrinks the rect (via `Rect::pad`'s `max(0.0)` clamp) and
    // could under-cover ink: reject it so the CLI parser's `pad >= 0` contract
    // also holds for library callers (C06-m2).
    if !opts.pad.is_finite() || opts.pad < 0.0 {
        return Err(RedactError::InvalidInput(format!(
            "apply: pad must be finite and non-negative, got {}",
            opts.pad
        )));
    }
    // Front-load the upper-bound check here too (not just in the backend's
    // render_page): keeps the validation contract in one place so a future
    // backend that doesn't enforce the same bound gets a clear error instead
    // of a corrupt pixmap. hayro's viewport is u16, so the practical limit
    // is u16::MAX / max_page_dimension (render_page additionally caps total
    // pixels at ~100 MP to bound allocation, which this check cannot express
    // without knowing every page's area — that one lives in the backend).
    // Use the **maximum** page dimension across all pages (not just page 0):
    // mixed page sizes are valid (PDF §7.7.3.3 allows per-page MediaBox), so
    // a scale that passes page 0's guard could still overflow a larger later
    // page.
    let page_count = doc.page_count();
    if page_count == 0 {
        return Err(RedactError::InvalidInput(
            "apply: input document has no pages; refusing to export an empty PDF".into(),
        ));
    }
    let mut max_dim = 0.0_f32;
    let mut max_dim_label = String::from("612x792");
    for pi in 0..page_count {
        match doc.render_dimensions(pi) {
            Ok((w, h)) => {
                let dim = w.max(h);
                if dim > max_dim {
                    max_dim = dim;
                    max_dim_label = format!("{w}x{h}");
                }
            }
            Err(e) => {
                return Err(RedactError::Other(format!(
                    "apply: failed to read dimensions for page {pi}: {e}"
                )));
            }
        }
    }
    if max_dim == 0.0 {
        max_dim = 612.0; // fallback if no page reported valid dimensions
    }
    let max_scale = u16::MAX as f32 / max_dim;
    if opts.scale > max_scale {
        return Err(RedactError::Other(format!(
            "apply: scale {} too large (max ≈ {:.1} for {} pt max page dimension {})",
            opts.scale, max_scale, max_dim, max_dim_label
        )));
    }
    let scale = opts.scale;

    // Group rects by page (included only).
    let mut by_page: Vec<Vec<Rect>> = (0..page_count).map(|_| Vec::new()).collect();
    for r in regions.iter().filter(|r| r.included) {
        if r.page_index >= page_count {
            return Err(RedactError::PageOutOfRange(r.page_index, page_count));
        }
        for rect in &r.rects {
            // Fail fast with attribution: the paint backstop below would
            // reject this too, but here we can name the page and region.
            if !rect.is_valid() {
                return Err(RedactError::InvalidInput(format!(
                    "apply: invalid rect {rect:?} for page {} (x/y/w/h must be finite, \
                     width and height > 0, magnitudes ≤ {})",
                    r.page_index,
                    crate::types::MAX_RECT_MAGNITUDE
                )));
            }
            by_page[r.page_index].push(padded_rect(*rect, opts.pad).scale(scale));
        }
    }

    let settings = SerializeSettings {
        xmp_metadata: false,
        enable_tagging: false,
        compress_content_streams: true,
        ..SerializeSettings::default()
    };

    let mut out_doc = Document::new_with(settings);
    out_doc.set_metadata(
        Metadata::new()
            .producer(format!("{TOOL_NAME} {TOOL_VERSION}"))
            .creator(TOOL_NAME.to_string()),
    );

    for (page_index, page_rects) in by_page.iter().enumerate() {
        let mut img = doc.render_page(page_index, scale)?;
        <HayroDocument as RasterOps>::paint_black_rects(&mut img, page_rects)?;
        // Deterministic post-paint self-check (M1): the output has no text layer
        // and the secrets live inside embedded image streams, so every verify
        // content check is vacuous for it. If a coordinate/scale bug makes a
        // rect miss its ink — or a rect is fully off-page and silently clipped —
        // the secret stays visible while verification would still pass. Sampling
        // each rect's interior here catches that at runtime.
        assert_rects_black(&img, page_rects)?;

        // Skip the PNG encode/decode round trip (m2): krilla's `from_custom`
        // takes the raw RGB buffer and deflates it once at serialize time. The
        // trade-off is memory — the raw 3 B/px buffer (no alpha, see n3) is held
        // in krilla's deferred cache until `finish()`, larger than compressed
        // PNG — but it removes one full PNG encode + deferred decode per page.
        let (rgb, w, h) = opaque_rgba_to_rgb(&img)?;
        // Defensive check: krilla's Deferred closure asserts dimensions match
        // at finish() time (a panic, not a Result). Catch a mismatch here so
        // any future code path gets a catchable error instead of an abort.
        let expected_len = w as usize * h as usize * 3;
        if rgb.len() != expected_len {
            return Err(RedactError::Rebuild(format!(
                "RGB buffer size mismatch: got {} bytes, expected {} ({}x{}x3)",
                rgb.len(),
                expected_len,
                w,
                h
            )));
        }
        let krilla_img = KrillaImage::from_custom(
            OpaqueRgb {
                data: rgb,
                width: w,
                height: h,
            },
            false,
        )
        .map_err(RedactError::Rebuild)?;

        // Page size in PDF points = the original unscaled render dimensions.
        // Deriving it as `img / scale` would round-trip hayro's floored pixel
        // count and silently change the MediaBox of fractional-pt pages (e.g.
        // 595.44 pt → 595.0 pt).
        let (page_w, page_h) = doc.render_dimensions(page_index)?;
        let page_settings = PageSettings::from_wh(page_w, page_h)
            .ok_or_else(|| RedactError::Rebuild("invalid page size".into()))?;

        let mut page = out_doc.start_page_with(page_settings);
        let mut surface = page.surface();
        let size = Size::from_wh(page_w, page_h)
            .ok_or_else(|| RedactError::Rebuild("invalid image size".into()))?;
        surface.draw_image(krilla_img, size);
        surface.finish();
        page.finish();
    }

    out_doc
        .finish()
        .map_err(|e| RedactError::Rebuild(format!("{e}")))
}

/// Expand a rect before painting (n2).
///
/// Derivation of the asymmetric slack:
/// - `pad` (default 1.5 pt) applies to all four sides — baseline coverage for
///   boxes that are tight against the ink.
/// - `v_extra` = 25% of the box height, clamped to 1–4 pt, extends top and
///   bottom symmetrically: ascender/descender overshoot and the anti-aliased
///   fringe of adjacent lines. Box height is a proxy for font size.
/// - `h_extra` = 75% of the box height, clamped to 4–12 pt, extends the right
///   edge only: the extractor's advance-width sum underestimates the last
///   glyph's ink (no advance is reported after it), so the tight box can stop
///   mid-glyph; height-as-font-size is the same proxy.
/// - The left edge gets half the right slack: first-glyph ink with a negative
///   left bearing (italic/serif overhang) is typically far smaller than a full
///   advance width, so a full `h_extra` there would double the horizontal
///   expansion for no benefit.
///
/// The asymmetric split is implemented as `x -= h_extra * 0.5` (left edge
/// grows by `h_extra / 2`) plus `w += h_extra * 1.5` (total width growth
/// `1.5 * h_extra`, so the right edge — the coverage-critical side, which can
/// stop mid-glyph — grows by the full `h_extra`).
///
/// No `debug_assert` here: a NaN / infinite input rect (coordinates or
/// dimensions) produces an invalid padded rect, and `paint_black_rects`
/// validates every rect it paints and returns [`RedactError::Other`] — the
/// same loud error in debug and release builds. A `debug_assert` would instead
/// abort the process on public-API misuse, inconsistent with the codebase's
/// error-not-panic policy. (Negative dimensions are rescued by `Rect::pad`'s
/// `max(0.0)` clamp plus the slack added here, so they always produce a valid
/// over-sized box — safe over-coverage, never a panic.)
fn padded_rect(rect: Rect, pad: f32) -> Rect {
    let mut padded = rect.pad(pad);
    let v_extra = (rect.h * 0.25).clamp(1.0, 4.0);
    let h_extra = (rect.h * 0.75).clamp(4.0, 12.0);
    padded.x -= h_extra * 0.5;
    padded.y -= v_extra * 0.5;
    padded.h += v_extra;
    padded.w += h_extra * 1.5;
    padded
}

/// Convert a fully-opaque RGBA raster to an RGB buffer (n3).
///
/// hayro paints an opaque white background before rendering, so every pixel's
/// alpha is 255 and the premultiplied buffer equals straight RGBA (see
/// `HayroDocument::render_page`). Dropping the redundant alpha channel shrinks
/// the embedded image by ~25-33%; the check below turns a violation of that
/// assumption into a loud error instead of a corrupted export.
fn opaque_rgba_to_rgb(img: &image::RgbaImage) -> Result<(Arc<Vec<u8>>, u32, u32)> {
    let (w, h) = (img.width(), img.height());
    let mut rgb = Vec::with_capacity(w as usize * h as usize * 3);
    for px in img.as_raw().chunks_exact(4) {
        if px[3] != 255 {
            return Err(RedactError::Other(format!(
                "render produced a non-opaque pixel (alpha {}); expected an opaque white background",
                px[3]
            )));
        }
        rgb.extend_from_slice(&px[..3]);
    }
    Ok((Arc::new(rgb), w, h))
}

/// Raw opaque RGB8 buffer implementing krilla's [`CustomImage`].
///
/// hayro's renders are fully opaque (see `opaque_rgba_to_rgb`), so the image
/// carries no alpha channel at all: krilla embeds a plain `/DeviceRGB` XObject
/// without an `/SMask`, and no PNG header/codec is involved anywhere in the
/// rebuild path (m2, n3).
#[derive(Clone, Hash)]
struct OpaqueRgb {
    data: Arc<Vec<u8>>,
    width: u32,
    height: u32,
}

impl krilla::image::CustomImage for OpaqueRgb {
    fn color_channel(&self) -> &[u8] {
        &self.data
    }

    fn alpha_channel(&self) -> Option<&[u8]> {
        None
    }

    fn bits_per_component(&self) -> krilla::image::BitsPerComponent {
        krilla::image::BitsPerComponent::Eight
    }

    fn size(&self) -> (u32, u32) {
        (self.width, self.height)
    }

    fn icc_profile(&self) -> Option<&[u8]> {
        None
    }

    fn color_space(&self) -> krilla::image::ImageColorspace {
        krilla::image::ImageColorspace::Rgb
    }
}

/// Deterministic post-paint self-check (M1).
///
/// The rebuild rasterizes every page, so the output has no text layer and the
/// secrets live inside embedded image streams — both verify content checks
/// (`text-removal`, `raw-byte-scan`) are vacuous for it. If a geometry/scale
/// bug makes a rect miss its ink — or a rect is fully off-page and silently
/// clipped — the secret stays visible while every other check passes. Sampling
/// each rect's interior closes that hole at runtime; `verify` mirrors it on the
/// re-rendered output (its `pixel-removal` check).
///
/// Rects are in **pixel** coordinates of `img`. A rect with no visible area on
/// the page (fully off-page) is an error. Interior pixels are sampled with a
/// small inset so anti-aliased rect edges don't fail the check; when the
/// visible region is narrower than the inset, it is checked in full.
pub(crate) fn assert_rects_black(img: &image::RgbaImage, rects: &[Rect]) -> Result<()> {
    let (iw, ih) = (img.width() as i32, img.height() as i32);
    for (i, r) in rects.iter().enumerate() {
        if !r.is_valid() {
            return Err(RedactError::Other(format!(
                "assert_rects_black got invalid rect {r:?}"
            )));
        }
        let (vx0, vy0, vx1, vy1) = crate::types::rect_pixel_range(*r, iw, ih);
        if vx1 <= vx0 || vy1 <= vy0 {
            return Err(RedactError::Other(format!(
                "redaction rect {i} {r:?} lies fully outside the {}x{} px page image; \
                 the secret would remain visible",
                img.width(),
                img.height()
            )));
        }
        const MARGIN: i32 = 2;
        let sx0 = (vx0 + MARGIN).min(vx1);
        let sy0 = (vy0 + MARGIN).min(vy1);
        let sx1 = (vx1 - MARGIN).max(sx0);
        let sy1 = (vy1 - MARGIN).max(sy0);
        // A rect narrower/taller than 2·MARGIN px leaves an empty interior
        // (sx0 == sx1 or sy0 == sy1) — sampling nothing would silently pass
        // sub-2px rects (e.g. a 0.5 pt rect at 2× is 1 px). Fall back to a
        // 1-px inset on each side so the visible region is still checked but
        // the outermost anti-aliased fringe pixel is skipped per the contract.
        // When even a 1-px inset collapses to an empty range (sub-2px rect),
        // use the full visible range so the rect is actually sampled.
        let (sx0, sx1) = if sx1 > sx0 {
            (sx0, sx1)
        } else {
            let a = (vx0 + 1).min(vx1);
            let b = (vx1 - 1).max(vx0);
            if b > a { (a, b) } else { (vx0, vx1) }
        };
        let (sy0, sy1) = if sy1 > sy0 {
            (sy0, sy1)
        } else {
            let a = (vy0 + 1).min(vy1);
            let b = (vy1 - 1).max(vy0);
            if b > a { (a, b) } else { (vy0, vy1) }
        };
        // Full-scan sampling: every interior pixel is checked. An earlier
        // version strided along X (every 4th column once the region exceeded a
        // width threshold) to cut iteration counts on large regions, but that
        // left a blind spot: a 1–3 px unpainted vertical gap between adjacent
        // rects (e.g. two rects in one region separated by a rounding gap)
        // slipped through whenever it contained no sampled column — the C06-m5
        // gap test only passed because its gap happened to align with the
        // stride phase. The Y axis is already iterated without a stride for
        // the same reason; the X stride saved at most 4× on a check that is
        // cheap relative to the painting pass it validates
        // (`paint_black_rects` already touches every painted pixel), so it was
        // removed rather than documented as a hole in the coverage guarantee.
        let mut y = sy0;
        while y < sy1 {
            let mut x = sx0;
            while x < sx1 {
                let p = img.get_pixel(x as u32, y as u32);
                if p[0] >= NEAR_BLACK || p[1] >= NEAR_BLACK || p[2] >= NEAR_BLACK {
                    return Err(RedactError::Other(format!(
                        "redaction rect {i} {r:?} is not black at pixel ({x},{y}) (rgba {:?}); \
                         the rect misses its ink (geometry/scale bug)",
                        [p[0], p[1], p[2], p[3]]
                    )));
                }
                x += 1;
            }
            y += 1;
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::{ApplyOptions, Category, Rect, Region};

    /// A `page_count`-page PDF of blank 200×200 pt pages (no fonts needed).
    fn blank_pages_pdf(page_count: usize) -> Vec<u8> {
        let mut objects: Vec<Vec<u8>> = Vec::new();
        objects.push(b"<< /Type /Catalog /Pages 2 0 R >>".to_vec());
        let kids: Vec<String> = (0..page_count).map(|i| format!("{} 0 R", 3 + i)).collect();
        objects.push(
            format!(
                "<< /Type /Pages /Kids [{}] /Count {page_count} >>",
                kids.join(" ")
            )
            .into_bytes(),
        );
        for i in 0..page_count {
            let content_ref = 3 + page_count + i;
            objects.push(
                format!(
                    "<< /Type /Page /Parent 2 0 R /MediaBox [0 0 200 200] \
                     /Contents {content_ref} 0 R >>"
                )
                .into_bytes(),
            );
        }
        for _ in 0..page_count {
            objects.push(b"<< /Length 0 >>\nstream\nendstream".to_vec());
        }
        assemble_pdf(objects)
    }

    /// Serialize numbered objects with a correct xref table into a PDF byte
    /// string (same helper as the hayro engine tests).
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

    fn region(page_index: usize, rects: Vec<Rect>, text: &str) -> Region {
        Region {
            page_index,
            rects,
            source_text: text.into(),
            category: Category::Custom,
            confidence: 1.0,
            included: true,
            source: crate::types::MatchSource::Regex,
        }
    }

    #[test]
    fn out_of_range_region_is_an_error_not_a_silent_skip() {
        // A one-page document; a region on page 5 must fail loudly.
        let input = std::fs::read(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../../testdata/fixtures/synthetic/pii_basic.pdf"
        ))
        .unwrap();
        let region = region(5, vec![Rect::new(0.0, 0.0, 10.0, 10.0)], "typo");
        let err = apply_regions(&input, &[region], &ApplyOptions::default()).unwrap_err();
        assert!(matches!(err, RedactError::PageOutOfRange(5, 1)), "{err:?}");
    }

    #[test]
    fn apply_known_rect_paints_black_and_preserves_page_count() {
        // Applies a known rect to a synthetic page, re-opens the REBUILT output
        // and asserts the corresponding pixels are black (n1).
        let input = blank_pages_pdf(1);
        let out = apply_regions(
            &input,
            &[region(0, vec![Rect::new(20.0, 20.0, 40.0, 12.0)], "secret")],
            &ApplyOptions::default(),
        )
        .unwrap();

        // Full save: no /Prev anywhere in the emitted bytes.
        assert!(!out.windows(5).any(|w| w == b"/Prev"), "no /Prev in output");

        let out_doc = HayroDocument::open(out).unwrap();
        assert_eq!(out_doc.page_count(), 1, "page count preserved");
        let img = out_doc.render_page(0, 2.0).unwrap();
        // Region rect × render scale: must be black in the rebuilt raster.
        assert_rects_black(&img, &[Rect::new(40.0, 40.0, 80.0, 24.0)]).unwrap();
        // A spot far from the rect stays white (image was actually drawn).
        assert_eq!(img.get_pixel(10, 10), &image::Rgba([255, 255, 255, 255]));
    }

    #[test]
    fn multipage_rects_land_on_the_right_page() {
        let input = blank_pages_pdf(2);
        let out = apply_regions(
            &input,
            &[
                region(0, vec![Rect::new(20.0, 20.0, 40.0, 12.0)], "page one"),
                region(1, vec![Rect::new(120.0, 120.0, 30.0, 10.0)], "page two"),
            ],
            &ApplyOptions::default(),
        )
        .unwrap();

        let out_doc = HayroDocument::open(out).unwrap();
        assert_eq!(out_doc.page_count(), 2, "page count preserved");
        let p0 = out_doc.render_page(0, 2.0).unwrap();
        assert_rects_black(&p0, &[Rect::new(40.0, 40.0, 80.0, 24.0)]).unwrap();
        // Page 1 must stay white where page 0's rect was painted…
        let p1 = out_doc.render_page(1, 2.0).unwrap();
        assert_eq!(p1.get_pixel(60, 52), &image::Rgba([255, 255, 255, 255]));
        // …and black at its own rect's location.
        assert_rects_black(&p1, &[Rect::new(240.0, 240.0, 60.0, 20.0)]).unwrap();
    }

    #[test]
    fn empty_rects_region_and_zero_regions_rebuild_cleanly() {
        let input = blank_pages_pdf(2);
        // An included region with no rects (cmd_verify --string style) paints nothing.
        let out = apply_regions(
            &input,
            &[region(1, Vec::new(), "secret")],
            &ApplyOptions::default(),
        )
        .unwrap();
        assert!(!out.windows(5).any(|w| w == b"/Prev"));
        let out_doc = HayroDocument::open(out).unwrap();
        assert_eq!(out_doc.page_count(), 2);
        let p1 = out_doc.render_page(1, 2.0).unwrap();
        assert_eq!(p1.get_pixel(10, 10), &image::Rgba([255, 255, 255, 255]));

        // Zero regions: still a full rebuild (metadata strip), page count preserved.
        let out = apply_regions(&input, &[], &ApplyOptions::default()).unwrap();
        let out_doc = HayroDocument::open(out).unwrap();
        assert_eq!(out_doc.page_count(), 2);
    }

    #[test]
    fn scale_must_be_finite_and_positive() {
        let input = blank_pages_pdf(1);
        for scale in [f32::NAN, 0.0, -5.0] {
            let err = apply_regions(
                &input,
                &[],
                &ApplyOptions {
                    scale,
                    ..Default::default()
                },
            )
            .unwrap_err();
            assert!(
                matches!(&err, RedactError::InvalidInput(msg) if msg.contains("scale")),
                "scale={scale} gave {err:?}"
            );
        }
        // A sane non-default scale still works.
        apply_regions(
            &input,
            &[],
            &ApplyOptions {
                scale: 3.0,
                ..Default::default()
            },
        )
        .unwrap();
    }

    #[test]
    fn fully_offscreen_rect_is_an_error_not_a_silent_skip() {
        // A rect fully outside the 200 pt page must fail loudly: painting it is
        // a no-op and the secret would stay visible while verify passes (M1).
        let input = blank_pages_pdf(1);
        let err = apply_regions(
            &input,
            &[region(
                0,
                vec![Rect::new(500.0, 500.0, 10.0, 10.0)],
                "secret",
            )],
            &ApplyOptions::default(),
        )
        .unwrap_err();
        assert!(
            matches!(&err, RedactError::Other(msg) if msg.contains("fully outside")),
            "{err:?}"
        );
    }

    #[test]
    fn assert_rects_black_detects_unpainted_interior() {
        let mut img = image::RgbaImage::from_pixel(20, 20, image::Rgba([255, 255, 255, 255]));
        let rect = Rect::new(2.0, 2.0, 10.0, 10.0);
        // An unpainted rect must fail the check…
        let err = assert_rects_black(&img, &[rect]).unwrap_err();
        assert!(
            matches!(&err, RedactError::Other(msg) if msg.contains("not black")),
            "{err:?}"
        );
        // …and painting makes it pass.
        HayroDocument::paint_black_rects(&mut img, &[rect]).unwrap();
        assert_rects_black(&img, &[rect]).unwrap();
    }

    #[test]
    fn opaque_rgba_to_rgb_drops_alpha_and_rejects_translucent() {
        let mut img = image::RgbaImage::from_pixel(2, 1, image::Rgba([10, 20, 30, 255]));
        img.put_pixel(1, 0, image::Rgba([0, 0, 0, 255]));
        let (rgb, w, h) = opaque_rgba_to_rgb(&img).unwrap();
        assert_eq!((w, h), (2, 1));
        assert_eq!(rgb.as_ref(), &[10, 20, 30, 0, 0, 0]);
        // A translucent pixel is a violated invariant — loud error, not corrupt export.
        let img = image::RgbaImage::from_pixel(1, 1, image::Rgba([1, 2, 3, 128]));
        let err = opaque_rgba_to_rgb(&img).unwrap_err();
        assert!(
            matches!(&err, RedactError::Other(msg) if msg.contains("non-opaque")),
            "{err:?}"
        );
    }

    #[test]
    fn padded_rect_small_font_clamps_vertical() {
        // Box height < 5 → v_extra = h*0.25 clamped to min 1.0
        let r = Rect::new(10.0, 10.0, 20.0, 4.0);
        let p = padded_rect(r, 1.5);
        // pad(1.5) adds 2*1.5=3.0 to w,h; then v_extra=1.0, h_extra=4.0
        // h growth = 3.0 + v_extra(1.0) = 4.0; w growth = 3.0 + 1.5*h_extra(4.0) = 9.0
        assert!((p.h - r.h - 4.0).abs() < 0.01, "h: {}", p.h);
        assert!((p.w - r.w - 9.0).abs() < 0.01, "w: {}", p.w);
    }

    #[test]
    fn padded_rect_large_font_clamps_vertical() {
        // Box height > 16 → v_extra = h*0.25 clamped to max 4.0
        let r = Rect::new(10.0, 10.0, 20.0, 20.0);
        let p = padded_rect(r, 1.5);
        // v_extra=4.0 (clamped max), h_extra=12.0 (clamped max)
        // h growth = 3.0 + 4.0 = 7.0; w growth = 3.0 + 1.5*12.0 = 21.0
        assert!((p.h - r.h - 7.0).abs() < 0.01, "h: {}", p.h);
        assert!((p.w - r.w - 21.0).abs() < 0.01, "w: {}", p.w);
    }

    #[test]
    fn padded_rect_medium_font_uses_proportional() {
        // Box height = 10 → v_extra = 2.5, h_extra = 7.5 (no clamping)
        let r = Rect::new(10.0, 10.0, 20.0, 10.0);
        let p = padded_rect(r, 1.5);
        // h growth = 3.0 + 2.5 = 5.5; w growth = 3.0 + 1.5*7.5 = 14.25
        assert!((p.h - r.h - 5.5).abs() < 0.01, "h: {}", p.h);
        assert!((p.w - r.w - 14.25).abs() < 0.01, "w: {}", p.w);
    }

    #[test]
    fn apply_regions_with_garbage_input_returns_openpdf_error() {
        let garbage = b"this is not a PDF at all".to_vec();
        let err = apply_regions(&garbage, &[], &ApplyOptions::default()).unwrap_err();
        assert!(
            matches!(err, RedactError::OpenPdf(_)),
            "garbage input should surface as OpenPdf, got {err:?}"
        );
    }

    /// C06-m5: a region with two rects separated by a 1–3 px unpainted column
    /// must be caught by `assert_rects_black` even when the rects exceed the
    /// old stride threshold. The gap is deliberately placed at a column phase
    /// the old 4-column X stride never sampled (x ∈ [82, 84) — residues 2/3 of
    /// the stride), so this test fails against the strided sampler and passes
    /// only because every interior pixel is now checked (C06-M1).
    #[test]
    fn assert_rects_black_detects_gap_between_two_rects() {
        // Two black rects wider than the old STRIDE_THRESHOLD (64 px),
        // separated by a 2 px white column at x ∈ [82, 84): with the old
        // stride-4 sampling starting at sx0 = 12, the sampled columns were
        // 12, 16, …, 80, 84, … — neither 82 nor 83 was ever sampled, so the
        // gap would have slipped through even though it spans every Y row.
        let mut img = image::RgbaImage::from_pixel(200, 200, image::Rgba([255, 255, 255, 255]));
        let left = Rect::new(10.0, 10.0, 72.0, 100.0);
        let right = Rect::new(84.0, 10.0, 68.0, 100.0);
        HayroDocument::paint_black_rects(&mut img, &[left, right]).unwrap();
        // The unpainted 2 px gap (x ∈ [82, 84)) is on every Y row — the check
        // must fail.
        let gap = Rect::new(10.0, 10.0, 142.0, 100.0);
        let err = assert_rects_black(&img, &[gap]).unwrap_err();
        assert!(
            matches!(&err, RedactError::Other(msg) if msg.contains("not black")),
            "{err:?}"
        );
    }

    /// C06-n3: a painted black rect must produce interior pixels with every RGB
    /// channel ≤ `NEAR_BLACK`, and the surrounding white must stay well above it.
    #[test]
    fn near_black_threshold_covers_paint_and_white() {
        let mut img = image::RgbaImage::from_pixel(50, 50, image::Rgba([255, 255, 255, 255]));
        let rect = Rect::new(5.0, 5.0, 40.0, 40.0);
        HayroDocument::paint_black_rects(&mut img, &[rect]).unwrap();
        // Every interior pixel of the painted rect is at most `NEAR_BLACK`.
        for y in 10..40 {
            for x in 10..40 {
                let p = img.get_pixel(x, y);
                assert!(
                    p[0] <= NEAR_BLACK && p[1] <= NEAR_BLACK && p[2] <= NEAR_BLACK,
                    "painted pixel ({x},{y}) rgba {:?} exceeds NEAR_BLACK ({})",
                    [p[0], p[1], p[2], p[3]],
                    NEAR_BLACK,
                );
            }
        }
        // The white exterior stays well above `NEAR_BLACK`.
        let corner = img.get_pixel(2, 2);
        assert!(corner[0] > NEAR_BLACK && corner[1] > NEAR_BLACK && corner[2] > NEAR_BLACK);
    }

    /// C06-m2: an invalid rect (NaN / infinite coordinates or dimensions)
    /// passed to `apply_regions` must surface as a `RedactError`, not abort
    /// the process: `padded_rect`'s old `debug_assert!` panicked on exactly
    /// this public-API misuse in debug builds while release builds correctly
    /// reported the error from the `paint_black_rects` backstop. Both profiles
    /// must now return the same loud error.
    ///
    /// (Negative dimensions are not covered: `Rect::pad` clamps them to 0 and
    /// `padded_rect` then adds positive slack, so they always produce a valid
    /// over-sized painted box — safe over-coverage, no panic even before.)
    #[test]
    fn invalid_rect_is_an_error_not_a_panic() {
        let input = blank_pages_pdf(1);
        for bad in [
            Rect::new(f32::NAN, 0.0, 10.0, 10.0),
            Rect::new(0.0, f32::NAN, 10.0, 10.0),
            Rect::new(f32::INFINITY, 0.0, 10.0, 10.0),
            Rect::new(0.0, 0.0, f32::INFINITY, 10.0),
            Rect::new(0.0, 0.0, 10.0, f32::INFINITY),
            Rect::new(0.0, 0.0, 10.0, f32::NAN),
        ] {
            let err = apply_regions(
                &input,
                &[region(0, vec![bad], "secret")],
                &ApplyOptions::default(),
            )
            .unwrap_err();
            assert!(
                matches!(&err, RedactError::InvalidInput(msg) if msg.contains("invalid rect")),
                "{bad:?} gave {err:?}"
            );
        }
    }

    /// C06-m2: a negative `pad` must be rejected by the library API, mirroring
    /// the CLI parser's `--pad >= 0` contract.
    #[test]
    fn negative_pad_is_rejected() {
        let input = blank_pages_pdf(1);
        let err = apply_regions(
            &input,
            &[region(0, vec![Rect::new(20.0, 20.0, 40.0, 12.0)], "secret")],
            &ApplyOptions {
                pad: -0.5,
                ..Default::default()
            },
        )
        .unwrap_err();
        assert!(
            matches!(&err, RedactError::InvalidInput(msg) if msg.contains("non-negative")),
            "{err:?}"
        );
    }
}
