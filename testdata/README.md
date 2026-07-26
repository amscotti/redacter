# Test data

## `fixtures/synthetic/`

Committed **real PDF files** produced by `redact-fixturegen` (krilla), containing only **synthetic** PII (test emails, Stripe-style card numbers, fictional SSNs).

| File | Purpose |
|------|---------|
| `pii_basic.pdf` | Email, SSN, card, phone, IBAN on one page (top-aligned) |
| `pii_basic.meta.json` | Expected detections |
| `multipage_mixed.pdf` | PII on pages 1 and 3; clean middle page |
| `multipage_mixed.meta.json` | Expected detections |
| `clean_lorem.pdf` | No PII control |
| `clean_lorem.meta.json` | Expected detections |
| `fake_w2.pdf` | Synthetic W-2-style wage statement |
| `fake_w2.meta.json` | Expected detections |
| `fake_1040_snippet.pdf` | Synthetic 1040-style return snippet |
| `fake_1040_snippet.meta.json` | Expected detections |
| `ocr_scanned.pdf` | Image-only (no text layer) scanned page for OCR e2e; written with `--scanned` |
| `ocr_scanned.meta.json` | Expected detections |

All tax-like fixtures are **entirely fictional** (fake names, SSNs, EINs).

Regenerate (needs a system TTF such as Arial or DejaVu):

```bash
mise run fixtures
# or
cargo run -p redact-fixturegen -- --out-dir testdata/fixtures/synthetic

# include the image-only OCR fixture (needed for `--check` to pass, since the
# committed ocr_scanned files are byte-checked too):
cargo run -p redact-fixturegen -- --scanned --out-dir testdata/fixtures/synthetic
```

## `generated/`

Gitignored runtime outputs from manual runs and debugging.

## `corpus/` (optional, gitignored)

External realism corpus — **not** required for default CI.

John Snow Labs synthetic PDF de-id levels:

| Level | Path | Text layer? | Notes |
|-------|------|-------------|-------|
| **Easy** | `jsl-pdf-deid/easy/` (+ legacy `subset/`) | **Yes** | Clean digital text; primary auto-detect eval |
| **Medium** | `jsl-pdf-deid/medium/` | **No** (image-only) | Visual noise; needs OCR |
| **Hard** | `jsl-pdf-deid/hard/` | **No** (image-only) | Dense layout + noise; needs OCR |

```bash
LEVEL=all ./scripts/fetch_public_corpus.sh
LEVEL=Medium mise run eval:jsl   # expect 0 findings until OCR
LEVEL=Easy mise run eval:jsl
```

### John Snow Labs PDF De-Identification Dataset (primary)

Source: [JohnSnowLabs/pdf-deid-dataset](https://github.com/JohnSnowLabs/pdf-deid-dataset)  
Fully **synthetic** medical-style PDFs (Faker + Gemini); no real patient data. Includes SSNs, names, DOBs, phones, hospital IDs, etc., plus ground-truth JSON.

```bash
# Download Easy level, first 10 PDFs (default)
mise run corpus:fetch
# or: ./scripts/fetch_public_corpus.sh
# or: LEVEL=Medium MAX_PDFS=5 ./scripts/fetch_public_corpus.sh

# Ignored corpus e2e (detect + redact/verify smoke + GT score floor)
mise run test:corpus
# Full Easy-subset eval (writes testdata/generated/jsl_eval/evaluation.json)
mise run eval:jsl
```

Layout after fetch:

```text
testdata/corpus/jsl-pdf-deid/
  easy/                # Easy text PDFs
  medium/              # Medium image-only PDFs (OCR)
  hard/                # Hard image-only PDFs (OCR)
  subset/              # legacy mirror of easy/ (e2e tests)
  ground_truth/        # pdf_deid_gts_{easy,medium,hard}.json
  raw/                 # API listing cache
  MANIFEST.txt
```

These tests assert **robustness** (open/detect/redact/verify, full-save, cert schema), not golden redacted bytes.

**Do not put real personal documents (or any real PII) under `testdata/`.** Use only this public synthetic corpus or files from `redact-fixturegen`.
