//! PDF engine abstraction (hayro-backed today).

mod hayro_engine;
mod text_device;

use image::RgbaImage;

use crate::error::Result;
use crate::types::{PageText, Rect};

pub use hayro_engine::{HayroDocument, MetadataSnapshot, paint_black_rects};

/// Extension point for PDF backends: page open, text extraction, render.
///
/// A backend must be able to open a document, enumerate pages, extract
/// per-page text spans with boxes, render a page to RGBA, and snapshot
/// metadata — everything the pipeline needs from a PDF. Implement this
/// trait to swap the hayro backend without touching detect/apply/verify/cli.
pub trait PdfEngine {
    /// Open a PDF document from raw bytes.
    fn open(bytes: impl Into<Vec<u8>>) -> Result<Self>
    where
        Self: Sized;

    /// Number of pages in the document.
    fn page_count(&self) -> usize;

    /// Raw input bytes of the document.
    fn bytes(&self) -> &[u8];

    /// Extract text + glyph boxes for a page (unscaled page coordinates).
    fn page_text(&self, page_index: usize) -> Result<PageText>;

    /// Unscaled render viewport (width, height) in points for a page.
    fn render_dimensions(&self, page_index: usize) -> Result<(f32, f32)>;

    /// Render a page to RGBA at `scale` (pixels per page unit). Background is white.
    fn render_page(&self, page_index: usize, scale: f32) -> Result<RgbaImage>;

    /// Snapshot document metadata (best-effort; values are decoded
    /// UTF-16/PDFDocEncoding or flagged as present — never silently dropped).
    fn metadata_snapshot(&self) -> MetadataSnapshot;
}

impl PdfEngine for HayroDocument {
    fn open(bytes: impl Into<Vec<u8>>) -> Result<Self> {
        HayroDocument::open(bytes)
    }

    fn page_count(&self) -> usize {
        HayroDocument::page_count(self)
    }

    fn bytes(&self) -> &[u8] {
        HayroDocument::bytes(self)
    }

    fn page_text(&self, page_index: usize) -> Result<PageText> {
        HayroDocument::page_text(self, page_index)
    }

    fn render_dimensions(&self, page_index: usize) -> Result<(f32, f32)> {
        HayroDocument::render_dimensions(self, page_index)
    }

    fn render_page(&self, page_index: usize, scale: f32) -> Result<RgbaImage> {
        HayroDocument::render_page(self, page_index, scale)
    }

    fn metadata_snapshot(&self) -> MetadataSnapshot {
        HayroDocument::metadata_snapshot(self)
    }
}

/// Raster operations the rebuild step needs from a backend.
///
/// `apply` paints black boxes over redaction rects in rendered pages; that
/// capability lives behind a trait (not as a hayro free function) so a second
/// backend can be swapped in without rewriting `apply` (the ARCHITECTURE.md
/// swap promise: "swap hayro without touching detect/verify/cli").
pub trait RasterOps {
    /// Paint black rectangles onto a rendered RGBA page. Rects are in **pixel**
    /// coordinates. Must fail loudly on invalid rects — a redactor must never
    /// silently skip a rect (the secret would stay visible while verify passes).
    fn paint_black_rects(img: &mut RgbaImage, rects: &[Rect]) -> Result<()>;
}
