//! Offline PDF redaction: detect, rasterize, verify, certify.

pub mod apply;
pub mod cert;
pub mod detect;
pub mod engine;
pub mod error;
pub mod findings;
pub mod geometry;
#[cfg(feature = "ocr")]
pub mod ocr;
pub mod pipeline;
pub mod text_quality;
pub mod types;
pub mod verify;

pub use apply::{NEAR_BLACK, apply_regions};
pub use cert::{
    CERT_FORMAT, Certificate, build_certificate, certificate_from_json, certificate_matches_output,
    certificate_to_json, sha256_hex,
};
pub use detect::{Detector, RegexDetector, detect};
pub use engine::{HayroDocument, PdfEngine};
pub use error::{RedactError, Result};
pub use findings::FindingsFile;
#[cfg(feature = "ocr")]
pub use ocr::{
    OcrBackend, OcrMode, OcrOptions, OcrPreprocess, OcrWord, OcrsBackend, PageOcrDecision,
    has_models, ocr_page_from_doc, ocr_page_from_doc_with_opts, page_text_from_lines,
    pixel_rect_to_page, preprocess_rgba, resolve_models_dir,
};
pub use pipeline::{
    DetectDocumentResult, PipelineResult, RunOptions, detect_document, detect_page_regions,
    rect_iou, redact_with_regions, redact_with_regions_and_options, regions_for_options,
    run_pipeline, text_layer_char_count, union_regions,
};
#[cfg(feature = "ocr")]
pub use pipeline::{detect_document_with, regions_for_options_with};
pub use text_quality::{TextLayerQuality, assess_text_layer};
pub use types::*;
pub use verify::{
    CheckResult, MIN_SECRET_LEN, RAW_SCAN_MIN_LEN, VerificationResult, assert_redacted,
    contains_str_bytes, looks_like_incremental_save, mask_pdf_stream_bodies, normalize_text,
    verify_output,
};
