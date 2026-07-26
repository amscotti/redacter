# redact

**Offline PDF redaction CLI** — detect PII, permanently remove it by rasterizing pages, re-verify the result, and emit a hash certificate. No uploads. No system PDF tools (Poppler, MuPDF, Tesseract). Pure Rust: hayro + krilla, optional **ocrs** + **rten** for scans.

Binary name: **`redact`**.

## Install

Prebuilt binaries (Linux x86_64/ARM64, macOS Intel/Apple Silicon, Windows x86_64) are attached to [GitHub Releases](https://github.com/amscotti/redacter/releases). Archives include `LICENSE` and `README.md`; checksums are in `SHA256SUMS`.

```bash
# macOS / Linux
tar -xzf redact-0.1.0-<target>.tar.gz
sudo install -m 0755 redact-0.1.0-<target>/redact /usr/local/bin/redact
redact --version
```

Windows: unzip `redact-0.1.0-x86_64-pc-windows-msvc.zip` and put `redact.exe` on your `PATH`.

Release binaries are the **default** build (no OCR). For scanned PDFs, build from source with `--features ocr`.

## Quick start

```bash
mise install                 # Rust pin from mise.toml (dev: 1.97.1)
mise run build               # default binary (no OCR models)

# Full pipeline: detect → redact → verify → cert
cargo run -p redact-cli -- run input.pdf -o out.pdf --cert out.cert.json --yes

# Reviewable detect → edit → redact
cargo run -p redact-cli -- detect input.pdf -o findings.json
# edit findings.json: set "included": false on false positives
cargo run -p redact-cli -- redact input.pdf --findings findings.json -o out.pdf --cert out.cert.json

# Manual strings / rectangles only
cargo run -p redact-cli -- run input.pdf -o out.pdf \
  --text 'secret@example.com' \
  --rect '0:72,640,120,14' \
  --yes --no-detect
```

### Scanned / image-only PDFs (OCR)

```bash
mise run ocr:models          # once: download ocrs models → models/ocr/ (gitignored)
mise run build:ocr           # release CLI with --features ocr

./target/release/redact ocr-info
./target/release/redact run scan.pdf -o out.pdf --ocr auto --yes --cert out.cert.json
```

OCR is **feature-gated** (`redact-cli` / `redact-core` feature `ocr`). Default builds stay small and skip models.

## How it works

1. **Extract** page text + glyph boxes (hayro), or **OCR** rendered pages when enabled (ocrs).
2. **Detect** PII with regex + validators (SSN, Luhn, IBAN, phones, clinical IDs, ages, names/orgs, addresses, …).
3. **Map** every occurrence of each hit on the page to rectangles (multi-hit redaction).
4. **Rasterize** pages, paint black boxes, rebuild a **new** PDF (krilla) as image pages — always a **full save** (no incremental `/Prev`; original content streams are not copied).
5. **Verify** independently on the output (export fails if a check fails):
   - **text-removal** — re-open and re-extract text after parse/decompress
   - **metadata-clean** / **annotations-removed**
   - **raw-byte-scan** — raw file bytes with stream bodies masked (avoids false hits inside compressed image data)
   - **full-save** — reject incremental trailers (`/Prev`)
6. **Certify** with `redact-certificate/v1` (SHA-256 of I/O bytes and of redacted strings only — never plaintext secrets).

```text
input.pdf
   │
   ├─ text layer (hayro) ──┐
   │                       ├─► detect ─► regions (all occurrences)
   └─ OCR if auto/on/force ┘              │
                                          ▼
                              raster + black boxes (krilla full save)
                                          │
                                          ▼
                              verify (5 checks) → certificate.json
```

Docs: [ARCHITECTURE.md](ARCHITECTURE.md)

## Detection

| Area | Examples |
|------|----------|
| Contact / IDs | Email, phone, SSN (dashed/contiguous + validation) |
| Financial | Credit card (Luhn), IBAN, ABA routing |
| Dates / age | `DD/MM/YYYY`, ISO, OCR glued `DDMMYYYY`, `N-year-old`, `Age: N`, `aged N` |
| Clinical | `HOSP…`, `DR…` style IDs |
| People / orgs | Labeled names, `Dr. …`, `…, born on`, corporate suffixes |
| Address-ish | Street lines, ZIP, US states, “United States” |
| Other | IPv4, passport-shaped tokens (weak, context-boosted) |

**Knobs**

| Flag | Effect |
|------|--------|
| `--min-confidence` | Default `0.35` |
| `--aggressive` | Lower floor (~0.12) and slight boost for weak unlabeled hits (more FPs) |
| `--categories` | Filter groups/labels (identity, contact, ssn, …) |
| `--ocr auto` | OCR when text is empty **or** text-layer quality is poor (needs OCR build) |
| `--ocr on` | Detect on native **and** OCR; union regions |
| `--ocr force` | OCR only |
| `--ocr-preprocess` | `off` (default) \| `light` \| `strong` |
| `--ocr-no-retry` | Disable sparse OCR retry (higher scale + strong preprocess) |

Detection is **best-effort**. Verification proves **listed** redactions are gone, not that the file is free of all secrets.

## Commands

| Command | Purpose |
|---------|---------|
| `detect` | Write reviewable findings JSON |
| `redact` | Apply findings and/or `--text` / `--rect` |
| `run` | Detect + redact + verify + cert (`--yes` required) |
| `verify` | Re-check an output PDF |
| `ocr-setup` | Download OCR models (OCR build) |
| `ocr-info` | OCR feature, model paths, readiness |

## OCR (pure Rust)

- **Engine:** [ocrs](https://github.com/robertknight/ocrs) + [rten](https://github.com/robertknight/rten)
- **Not used:** System Tesseract, Poppler, MuPDF, cloud APIs
- **Models:** `./scripts/download_ocrs_models.sh` or `redact ocr-setup` → `models/ocr/` (or `REDACT_OCR_MODELS`)
- **Auto policy:** OCR if native char count is low **or** [text-layer quality](crates/redact-core/src/text_quality.rs) score is poor (garbled / sticky / empty layers)

```bash
# Once
mise run ocr:models

# Build
mise run build:ocr
# equivalent: cargo build -p redact-cli --release --features ocr

# Use
./target/release/redact run scan.pdf -o out.pdf --ocr auto --yes
./target/release/redact detect scan.pdf -o f.json --ocr auto --aggressive
```

Optional spike (O0 go/no-go tooling): `crates/redact-ocr-spike` / `mise run ocr:spike`.

## Public corpus (optional)

[John Snow Labs synthetic PDF de-id](https://github.com/JohnSnowLabs/pdf-deid-dataset) — **no real PII**. Gitignored under `testdata/corpus/`.

| Level | PDFs | Text | Typical use |
|-------|-----:|------|-------------|
| **Easy** | 30 | Digital text layer | GT floor, manual (`test:corpus`) |
| **Medium** | 10 | Image-only | OCR realism |
| **Hard** | 10 | Image-only + heavy noise | OCR stress |

```bash
mise run corpus:fetch                 # Easy (default)
LEVEL=all mise run corpus:fetch       # Easy + Medium + Hard

mise run test:corpus                  # smoke + Easy GT floor (recall ≥ 0.90, precision ≥ 0.95)
LEVEL=Easy mise run eval:jsl          # full Easy score → testdata/generated/jsl_eval_easy/
mise run eval:jsl:medium              # OCR build + Medium score
mise run eval:jsl:hard                # OCR build + Hard score
```

### Recent eval snapshot (local, approximate)

Measured 2026-09-05 with `AGGRESSIVE=1` (recall mode; default mode trades
recall for precision — see `--aggressive` above). Easy also gated by
`mise run test:corpus` (floors: recall ≥ 0.90, precision ≥ 0.95).

| Level | Micro-recall | Micro-precision | Verify |
|-------|-------------:|----------------:|:------:|
| Easy | 100% | ~98% | 30/30 pass |
| Medium (`--ocr auto`) | ~73% | ~85% | 10/10 pass |
| Hard (`--ocr auto`) | ~31% | ~67% | 10/10 pass |

Metrics are **string match vs GT PHI lists**, not bounding-box IoU. Hard is limited mainly by OCR quality on dense/noisy pages.

**Never** put real personal tax or medical docs under `testdata/`. See [testdata/README.md](testdata/README.md).

## Development

```bash
mise run test       # unit + e2e
mise run lint       # clippy + fmt
mise run check      # lint + test

# Coverage (cargo-llvm-cov + llvm-tools-preview)
mise run coverage              # HTML → target/coverage/html/index.html
mise run coverage:summary
mise run coverage:lcov

# Regenerate synthetic PDFs (needs a system TTF, e.g. Arial/DejaVu)
cargo run -p redact-fixturegen -- --out-dir testdata/fixtures/synthetic
```

### Layout

| Path | Role |
|------|------|
| `crates/redact-core` | Library: engine, detect, OCR, apply, verify, cert, text quality |
| `crates/redact-cli` | Thin CLI (`ocr` feature → `redact-core/ocr`) |
| `crates/redact-fixturegen` | Synthetic PDF fixtures |
| `crates/redact-ocr-spike` | Optional OCR smoke binary (not default) |
| `scripts/` | Corpus fetch, JSL eval, OCR model download |
| `testdata/fixtures/synthetic` | Committed sample PDFs + meta |
| `testdata/corpus/` | Optional public corpus (gitignored) |
| `models/ocr/` | OCR weights (gitignored) |
| `mise.toml` | Toolchain + tasks |
| `deny.toml` + `redact-core/tests/architecture.rs` | Supply-chain and layering gates (CI) |

Edition **2024**, MSRV **1.92**, dev pin **1.97.1** (`mise.toml`).

## Limits

- Best-effort detection — not a guarantee that all PII is found.
- Default mode favors precision: bare dates/phones need keyword context; use `--aggressive` for medical-form recall.
- Verification proves **listed** redactions are gone, not global secrecy of the file.
- Multi-occurrence painting covers every mapped string hit; detector must still *find* the string.
- Encrypted / password PDFs are unsupported (hayro).
- OCR accuracy on hard scans is model-limited; preprocess knobs are experimental (default off).
- No System Tesseract and no cloud APIs by design.

## License

MIT — see [LICENSE](LICENSE).
