use thiserror::Error;

/// Errors produced by redact-core.
#[derive(Debug, Error)]
pub enum RedactError {
    #[error("failed to open PDF: {0}")]
    OpenPdf(String),

    #[error("page index {0} is out of range (page count {1})")]
    PageOutOfRange(usize, usize),

    #[error("failed to render page {0}: {1}")]
    Render(usize, String),

    #[error("failed to rebuild PDF: {0}")]
    Rebuild(String),

    #[error("failed to encode image: {0}")]
    Image(String),

    #[error("{count} match(es) could not be mapped to page geometry; refusing unsafe export")]
    UnmappedMatches { count: usize },

    #[error(
        "no included regions to redact (nothing detected and nothing explicitly requested); \
         refusing to export an untouched document"
    )]
    NoIncludedRegions,

    #[error("search text {text:?} was not found on any page; refusing unsafe export")]
    SearchTextNotFound { text: String },

    #[error("verification failed: {0}")]
    VerificationFailed(String),

    #[error("invalid findings file: {0}")]
    Findings(String),

    #[error("invalid certificate: {0}")]
    Certificate(String),

    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),

    #[error("OCR: {0}")]
    Ocr(String),

    /// Invalid user-supplied input (bad CLI flag value, malformed manual rect,
    /// invalid apply scale). Distinct from [`RedactError::Other`] so the CLI
    /// can map it to exit code 2 ("usage") instead of exit code 1 (operational)
    /// without string-matching the message (C10-F7).
    #[error("invalid input: {0}")]
    InvalidInput(String),

    #[error("{0}")]
    Other(String),
}

pub type Result<T> = std::result::Result<T, RedactError>;
