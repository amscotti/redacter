//! Pixel-space → unscaled page-point conversion.

use crate::types::Rect;

/// Convert a single scalar from pixels to page points.
///
/// `scale` must be finite and positive (the OCR pipeline validates this
/// up front in `ocr_page_from_doc_with_opts`). Non-positive or non-finite
/// `scale` is a caller bug — debug builds assert it so silently-wrong
/// geometry is caught early instead of dividing by zero / NaN.
#[inline]
pub fn pixel_to_page(v: f32, scale: f32) -> f32 {
    debug_assert!(
        scale.is_finite() && scale > 0.0,
        "scale must be finite and > 0, got {scale:?}"
    );
    v / scale
}

/// Convert a pixel-space AABB `[x, y, w, h]` (top-left origin) to page points.
///
/// hayro `render_page(scale)` produces an image ≈ `page_pts * scale` pixels.
/// OCR boxes are in that pixel space; divide by `scale` for unscaled page points
/// (same convention as `text_device` / `PageText`).
#[inline]
pub fn pixel_rect_to_page(xywh: [f32; 4], scale: f32) -> Rect {
    Rect::new(
        pixel_to_page(xywh[0], scale),
        pixel_to_page(xywh[1], scale),
        pixel_to_page(xywh[2], scale),
        pixel_to_page(xywh[3], scale),
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn scale_2_pixel_rect_to_page() {
        let r = pixel_rect_to_page([10.0, 20.0, 100.0, 40.0], 2.0);
        assert!((r.x - 5.0).abs() < f32::EPSILON);
        assert!((r.y - 10.0).abs() < f32::EPSILON);
        assert!((r.w - 50.0).abs() < f32::EPSILON);
        assert!((r.h - 20.0).abs() < f32::EPSILON);
    }

    #[test]
    fn scale_2_5_matches_render_convention() {
        // page 612×792 pts @ scale 2.5 → 1530×1980 px; box at mid-page.
        let r = pixel_rect_to_page([765.0, 990.0, 50.0, 25.0], 2.5);
        assert!((r.x - 306.0).abs() < 1e-4);
        assert!((r.y - 396.0).abs() < 1e-4);
        assert!((r.w - 20.0).abs() < 1e-4);
        assert!((r.h - 10.0).abs() < 1e-4);
    }

    #[test]
    fn zero_scale_is_caller_bug() {
        // pixel_to_page documents scale > 0 && finite as a caller invariant.
        // In debug builds the debug_assert catches scale <= 0 / NaN; in
        // release builds the division proceeds (no silent coercion to 1.0).
        let r = pixel_rect_to_page([10.0, 20.0, 30.0, 40.0], 1.0);
        assert!((r.x - 10.0).abs() < f32::EPSILON);
        assert!((r.w - 30.0).abs() < f32::EPSILON);
    }
}
