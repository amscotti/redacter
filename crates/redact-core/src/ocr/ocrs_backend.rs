//! Pure-Rust ocrs + rten backend (no System Tesseract).

use std::path::{Path, PathBuf};

use image::RgbaImage;
use ocrs::{ImageSource, OcrEngine, OcrEngineParams, TextItem};
use rten::Model;

use super::OcrBackend;
use super::coords::pixel_rect_to_page;
use super::models::{self, resolve_models_dir};
use super::page_text::{OcrWord, page_text_from_lines};
use crate::error::{RedactError, Result};
use crate::types::PageText;

/// ocrs-backed OCR engine with loaded detection + recognition models.
pub struct OcrsBackend {
    engine: OcrEngine,
    models_dir: PathBuf,
}

impl OcrsBackend {
    /// Load models from `models_dir` (or resolved default search path).
    ///
    /// Expects `text-detection.rten` and `text-recognition.rten`.
    /// On missing models, returns a clear error pointing at
    /// `scripts/download_ocrs_models.sh`.
    pub fn load(models_dir: Option<&Path>) -> Result<Self> {
        let dir = resolve_models_dir(models_dir);
        let (det_path, rec_path) = models::model_paths(&dir);

        if !det_path.is_file() || !rec_path.is_file() {
            return Err(RedactError::Ocr(format!(
                "models not found in {} (need {det} and {rec}). Run: ./scripts/download_ocrs_models.sh",
                dir.display(),
                det = models::DETECTION_MODEL,
                rec = models::RECOGNITION_MODEL,
            )));
        }

        let detection_model = Model::load_file(&det_path)
            .map_err(|e| RedactError::Ocr(format!("load detection {}: {e}", det_path.display())))?;
        let recognition_model = Model::load_file(&rec_path).map_err(|e| {
            RedactError::Ocr(format!("load recognition {}: {e}", rec_path.display()))
        })?;

        let engine = OcrEngine::new(OcrEngineParams {
            detection_model: Some(detection_model),
            recognition_model: Some(recognition_model),
            ..Default::default()
        })
        .map_err(|e| RedactError::Ocr(format!("OcrEngine::new: {e}")))?;

        Ok(Self {
            engine,
            models_dir: dir,
        })
    }

    pub fn models_dir(&self) -> &Path {
        &self.models_dir
    }
}

impl OcrBackend for OcrsBackend {
    fn ocr_page(
        &self,
        rgba: &RgbaImage,
        page_index: usize,
        page_width: f32,
        page_height: f32,
        scale: f32,
    ) -> Result<PageText> {
        let img_source = ImageSource::from_bytes(rgba.as_raw(), rgba.dimensions())
            .map_err(|e| RedactError::Ocr(format!("ImageSource: {e:?}")))?;

        let ocr_input = self
            .engine
            .prepare_input(img_source)
            .map_err(|e| RedactError::Ocr(format!("prepare_input: {e}")))?;
        let word_rects = self
            .engine
            .detect_words(&ocr_input)
            .map_err(|e| RedactError::Ocr(format!("detect_words: {e}")))?;
        let line_rects = self.engine.find_text_lines(&ocr_input, &word_rects);
        let line_texts = self
            .engine
            .recognize_text(&ocr_input, &line_rects)
            .map_err(|e| RedactError::Ocr(format!("recognize_text: {e}")))?;

        let mut lines: Vec<Vec<OcrWord>> = Vec::new();
        for line in line_texts.iter().flatten() {
            let line_s = line.to_string();
            // Drop near-empty noise (same filter as O0 spike).
            if line_s.chars().count() <= 1 {
                continue;
            }
            let words: Vec<_> = line.words().collect();
            let mut line_words = Vec::new();
            if words.is_empty() {
                if let Some(bb) = aabb_from_text_item(line) {
                    line_words.push(OcrWord {
                        // Cloned: `line_s` is still borrowed below by the
                        // drop warning when no word geometry maps.
                        text: line_s.clone(),
                        rect: pixel_rect_to_page(bb, scale),
                    });
                }
            } else {
                for w in words {
                    let t = w.to_string();
                    if t.trim().is_empty() {
                        continue;
                    }
                    if let Some(bb) = aabb_from_text_item(&w) {
                        line_words.push(OcrWord {
                            text: t,
                            rect: pixel_rect_to_page(bb, scale),
                        });
                    }
                }
            }
            if !line_words.is_empty() {
                lines.push(line_words);
            } else {
                // C13-3: a recognized line with no geometry is dropped — surface
                // it so users know OCR found text it could not geolocate.
                tracing::warn!(
                    page = page_index,
                    line = %line_s,
                    "OCR line had no mappable word geometry; dropped"
                );
            }
        }

        Ok(page_text_from_lines(
            page_index,
            page_width,
            page_height,
            &lines,
        ))
    }
}

/// Axis-aligned bounding box `[x, y, w, h]` in pixel space from a `TextItem`.
fn aabb_from_text_item(item: &impl TextItem) -> Option<[f32; 4]> {
    let bounds = item.bounding_rect();
    let x = bounds.left() as f32;
    let y = bounds.top() as f32;
    let w = bounds.width() as f32;
    let h = bounds.height() as f32;
    if w <= 0.0 || h <= 0.0 {
        return None;
    }
    Some([x, y, w, h])
}
