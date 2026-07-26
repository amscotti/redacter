//! Locate ocrs detection + recognition model files on disk.

use std::path::{Path, PathBuf};

pub const DETECTION_MODEL: &str = "text-detection.rten";
pub const RECOGNITION_MODEL: &str = "text-recognition.rten";

/// Resolve the models directory.
///
/// Order:
/// 1. Explicit `models_dir` argument (if provided)
/// 2. `REDACT_OCR_MODELS` env (if set and is a directory)
/// 3. First existing candidate that contains both `.rten` files:
///    `./models/ocr`, `./models`, `$HOME/.cache/ocrs` (only when `$HOME` is set)
/// 4. Fallback: `./models/ocr` (preferred install location)
pub fn resolve_models_dir(explicit: Option<&Path>) -> PathBuf {
    if let Some(p) = explicit {
        if !p.is_dir() {
            tracing::warn!(
                path = %p.display(),
                "explicit models directory does not exist; the path will be used as-is \
                 but model loading will fail if it remains missing"
            );
        }
        return p.to_path_buf();
    }
    if let Ok(p) = std::env::var("REDACT_OCR_MODELS") {
        let p = PathBuf::from(p);
        if p.is_dir() {
            return p;
        }
        // C13-7: surface the misconfiguration so the user knows their env var
        // was ignored, rather than getting an opaque "models not found" later.
        tracing::warn!(
            env = "REDACT_OCR_MODELS",
            path = %p.display(),
            "env var is set but not a directory; ignoring"
        );
    }
    for c in candidate_dirs() {
        if has_models(&c) {
            return c;
        }
    }
    PathBuf::from("models/ocr")
}

/// Whether `dir` contains both required model files.
pub fn has_models(dir: &Path) -> bool {
    dir.join(DETECTION_MODEL).is_file() && dir.join(RECOGNITION_MODEL).is_file()
}

/// Paths to detection and recognition models under `dir`.
pub fn model_paths(dir: &Path) -> (PathBuf, PathBuf) {
    (dir.join(DETECTION_MODEL), dir.join(RECOGNITION_MODEL))
}

fn candidate_dirs() -> Vec<PathBuf> {
    let mut dirs = vec![PathBuf::from("models/ocr"), PathBuf::from("models")];
    // n3: without `$HOME` there is no cache dir — a cwd-relative `.cache/ocrs`
    // guess would silently depend on the working directory and surface a wrong
    // path in the missing-models error. Skip the candidate entirely.
    if let Some(home) = home_cache_ocrs() {
        dirs.push(home);
    }
    dirs
}

fn home_cache_ocrs() -> Option<PathBuf> {
    std::env::var_os("HOME").map(|home| PathBuf::from(home).join(".cache/ocrs"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn explicit_dir_wins() {
        let p = PathBuf::from("/tmp/custom-ocr-models");
        assert_eq!(resolve_models_dir(Some(&p)), p);
    }

    #[test]
    fn has_models_false_for_empty() {
        assert!(!has_models(Path::new("/nonexistent/ocr-models-xyz")));
    }
}
