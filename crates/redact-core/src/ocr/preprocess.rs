//! Lightweight image preprocessing for OCR (pure Rust, no external libs).
//!
//! Aimed at noisy scan-style PDFs (JSL Hard): contrast stretch and optional
//! mild unsharp so ocrs sees cleaner ink. Geometry is unchanged (same size).

use image::{Rgba, RgbaImage};

/// How aggressively to preprocess the page raster before OCR.
///
/// `Default` is [`OcrPreprocess::Off`] to agree with [`OcrOptions::default`]
/// and the CLI default: Light can hurt already-clean renders (C13-m2).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum OcrPreprocess {
    /// Leave pixels as rendered.
    #[default]
    Off,
    /// Grayscale + percentile contrast stretch.
    Light,
    /// Light + mild unsharp mask (helps moiré / soft ink).
    Strong,
}

/// Apply preprocessing in place on an RGBA page image.
pub fn preprocess_rgba(img: &mut RgbaImage, mode: OcrPreprocess) {
    match mode {
        OcrPreprocess::Off => {}
        OcrPreprocess::Light => {
            to_grayscale(img);
            contrast_stretch(img, 2, 98);
        }
        OcrPreprocess::Strong => {
            to_grayscale(img);
            contrast_stretch(img, 1, 99);
            unsharp_light(img);
            contrast_stretch(img, 2, 98);
        }
    }
}

/// Convert to luminance grayscale (keeps alpha = 255).
fn to_grayscale(img: &mut RgbaImage) {
    for p in img.pixels_mut() {
        // Rec. 601 luma
        let y =
            ((u32::from(p[0]) * 299 + u32::from(p[1]) * 587 + u32::from(p[2]) * 114) / 1000) as u8;
        *p = Rgba([y, y, y, 255]);
    }
}

/// Percentile-based contrast stretch on grayscale RGBA.
fn contrast_stretch(img: &mut RgbaImage, low_pct: u8, high_pct: u8) {
    let mut hist = [0u32; 256];
    for p in img.pixels() {
        hist[p[0] as usize] += 1;
    }
    let total = img.width() as u64 * img.height() as u64;
    if total == 0 {
        return;
    }
    let lo_target = (total as f64 * f64::from(low_pct) / 100.0) as u64;
    let hi_target = (total as f64 * f64::from(high_pct) / 100.0) as u64;
    let mut cum = 0u64;
    let mut lo: Option<u8> = None;
    let mut hi = 255u8;
    for (i, &c) in hist.iter().enumerate() {
        cum += u64::from(c);
        if cum >= lo_target && lo.is_none() {
            lo = Some(i as u8);
        }
        if cum >= hi_target {
            hi = i as u8;
            break;
        }
    }
    let lo = lo.unwrap_or(0);
    if hi <= lo {
        return;
    }
    let span = f32::from(hi - lo);
    for p in img.pixels_mut() {
        let v = p[0];
        let stretched = if v <= lo {
            0u8
        } else if v >= hi {
            255u8
        } else {
            (((f32::from(v - lo) / span) * 255.0).round() as u16).min(255) as u8
        };
        *p = Rgba([stretched, stretched, stretched, 255]);
    }
}

/// Very light 3×3 unsharp (center boost) for soft scanned ink.
///
/// Clones the full page raster to read neighbors while writing in place.
/// At OCR scale 2.5× a US-Letter page is ~1530×1980 (~12 MB RGBA); the
/// clone adds a transient copy of the same size. Under sparse-retry at
/// 3.5× (~2142×2772 ≈ 24 MB) the extra allocation is ~24 MB. Acceptable
/// for single-page processing; revisit if memory-constrained.
fn unsharp_light(img: &mut RgbaImage) {
    let (w, h) = img.dimensions();
    if w < 3 || h < 3 {
        return;
    }
    let src = img.clone();
    for y in 1..h - 1 {
        for x in 1..w - 1 {
            let c = f32::from(src.get_pixel(x, y)[0]);
            let blur = (f32::from(src.get_pixel(x - 1, y)[0])
                + f32::from(src.get_pixel(x + 1, y)[0])
                + f32::from(src.get_pixel(x, y - 1)[0])
                + f32::from(src.get_pixel(x, y + 1)[0])
                + c * 4.0)
                / 8.0;
            // amount ≈ 0.5
            let v = (c + (c - blur) * 0.5).round().clamp(0.0, 255.0) as u8;
            img.put_pixel(x, y, Rgba([v, v, v, 255]));
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use image::Rgba;

    #[test]
    fn light_makes_flat_gray_more_extreme() {
        let mut img = RgbaImage::from_pixel(4, 4, Rgba([120, 130, 140, 255]));
        // Add a dark and bright pixel so stretch has range
        img.put_pixel(0, 0, Rgba([40, 40, 40, 255]));
        img.put_pixel(3, 3, Rgba([200, 200, 200, 255]));
        preprocess_rgba(&mut img, OcrPreprocess::Light);
        // All channels equal after grayscale
        let p = img.get_pixel(1, 1);
        assert_eq!(p[0], p[1]);
        assert_eq!(p[1], p[2]);
    }

    #[test]
    fn off_is_noop() {
        let mut img = RgbaImage::from_pixel(2, 2, Rgba([10, 20, 30, 255]));
        preprocess_rgba(&mut img, OcrPreprocess::Off);
        assert_eq!(*img.get_pixel(0, 0), Rgba([10, 20, 30, 255]));
    }
}
