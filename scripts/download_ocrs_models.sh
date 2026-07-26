#!/usr/bin/env bash
# Download pure-Rust ocrs detection + recognition models into models/ocr/
# (gitignored). Used by the O0 spike and future `ocr` feature.
#
# Integrity: each download is verified against the pinned sha256 below, so a
# corrupted download or a tampered mirror aborts instead of shipping a poisoned
# model into a redaction tool. Update the hashes together with the model files
# they pin (compute with `shasum -a 256 <file>` or `sha256sum <file>`).
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
DEST="${REDACT_OCR_MODELS:-$ROOT/models/ocr}"

# REDACT_OCR_MODELS may point at a regular file — the same misconfiguration
# models.rs warns about and ignores. Fall back to the default location so
# `mkdir -p` cannot hard-fail on a non-directory.
if [ -e "$DEST" ] && [ ! -d "$DEST" ]; then
  echo "warning: $DEST is not a directory; ignoring and using $ROOT/models/ocr" >&2
  DEST="$ROOT/models/ocr"
fi
mkdir -p "$DEST"

DET_URL="https://ocrs-models.s3-accelerate.amazonaws.com/text-detection.rten"
REC_URL="https://ocrs-models.s3-accelerate.amazonaws.com/text-recognition.rten"

# Published sha256 of the model binaries the repo was validated against.
DET_SHA256="f15cfb56bd02c4bf478a20343986504a1f01e1665c2b3a0ad66340f054b1b5ca"
REC_SHA256="e484866d4cce403175bd8d00b128feb08ab42e208de30e42cd9889d8f1735a6e"

# Portable sha256: macOS ships `shasum`, Linux ships `sha256sum`.
if command -v sha256sum >/dev/null 2>&1; then
  sha256_of() { sha256sum "$1" | awk '{print $1}'; }
elif command -v shasum >/dev/null 2>&1; then
  sha256_of() { shasum -a 256 "$1" | awk '{print $1}'; }
else
  echo "error: need sha256sum or shasum to verify model checksums" >&2
  exit 1
fi

# Download with retries, then verify the checksum; a mismatch aborts and
# removes the corrupt file (fail-closed, never a silent partial model).
fetch_verified() {
  local url="$1" out="$2" expected="$3"
  local name actual
  name="$(basename "$out")"
  echo "Downloading ${name} → $out"
  curl -fL --retry 3 -o "$out" "$url"
  actual="$(sha256_of "$out")"
  if [ "$actual" != "$expected" ]; then
    echo "error: sha256 mismatch for ${name}" >&2
    echo "  expected: ${expected}" >&2
    echo "  actual:   ${actual}" >&2
    rm -f "$out"
    exit 1
  fi
  echo "  sha256 ok"
}

echo "Downloading ocrs models → $DEST"
fetch_verified "$DET_URL" "$DEST/text-detection.rten" "$DET_SHA256"
fetch_verified "$REC_URL" "$DEST/text-recognition.rten" "$REC_SHA256"
ls -lh "$DEST"
echo "Done. Run spike:"
echo "  cargo run -p redact-ocr-spike --release -- \\"
echo "    testdata/corpus/jsl-pdf-deid/medium/00_PDF_Deid_Deidentification_Medium_0.pdf"
