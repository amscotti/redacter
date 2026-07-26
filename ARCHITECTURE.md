# Architecture

This document describes how the `redact` codebase is laid out so it stays
easy to extend (new detectors, OCR, alternate PDF backends, CLI commands).

## Crate map

```text
crates/
  redact-core/        # library: all product logic (no clap, no main)
  redact-cli/         # thin binary: parse args, call core, print results
  redact-fixturegen/  # dev tool: build synthetic PDFs with known PII
  redact-ocr-spike/   # throwaway go/no-go OCR experiment (publish = false)
```

| Crate | Depends on | Responsibility |
|-------|------------|----------------|
| `redact-core` | hayro, krilla, image, regex, … | detect / apply / verify / cert |
| `redact-cli` | redact-core, clap, anyhow | UX only |
| `redact-fixturegen` | redact-core, krilla | offline test PDFs |
| `redact-ocr-spike` | redact-core, ocrs, rten | throwaway experiment, never a dependency |

**Rule:** business logic never lives in `redact-cli`. If a feature is useful
in tests or another front-end, it belongs in `redact-core`.

**Enforcement:** these rules are executable, not just documented — see
`crates/redact-core/tests/architecture.rs` (module layering, no `clap` in
core, CLI direction) run under `cargo test`, plus `deny.toml` (`cargo deny
check`) for the supply-chain side. CI (`.github/workflows/ci.yml`) runs
fmt, clippy, tests, and deny on every push/PR. Tag `v*` pushes run
`.github/workflows/release.yml`, which builds `redact` for Linux, macOS, and
Windows and publishes the archives on the GitHub Release.

## `redact-core` modules

```text
redact-core/src/
  lib.rs           # public re-exports + pipeline orchestration
  error.rs         # thiserror types shared by all modules
  types.rs         # Region, Match, PageText, Rect, shared DTOs + pure
                   # rect helpers (same_line_rects, rect_pixel_range) so the
                   # engine never depends on geometry (see architecture.rs)
  engine/          # PDF open / text / render (hayro-backed today)
    mod.rs
    hayro_engine.rs
    text_device.rs # hayro Device → glyphs + boxes
  detect/          # PII detectors (pluggable)
    mod.rs
    regex_detect.rs
    validators.rs  # Luhn, IBAN, SSN, …
    catalog.rs     # pattern table
  geometry.rs      # map text spans / matches → page rects
  apply.rs         # rasterize, paint black, rebuild with krilla
  verify.rs        # four independent checks on output bytes
  cert.rs          # redact-certificate/v1
  findings.rs      # findings JSON load/save (review workflow)
  pipeline.rs      # detect → map → apply → verify → cert
```

### Extension points

1. **New detector** — implement logic in `detect/`, register in `detect/mod.rs`
   (`RegexDetector` today; NER later as another struct behind the same
   `Detector` trait).
2. **New PDF backend** — keep page open/text/render behind the `PdfEngine`
   trait in `engine/`. Swap hayro without touching detect/verify/cli.
3. **OCR** — produce `PageText` (string + boxes) the same way the text
   device does; pipeline stays unchanged (`ocr` feature, `OcrBackend` trait,
   modes auto/on/off; pure Rust ocrs + rten).
4. **CLI command** — add a clap subcommand that calls `pipeline` or a
   focused core API (`detect_document`, `apply_regions`, `verify_output`).

### Data flow

```text
input.pdf bytes
    │
    ▼
 engine.open ──► per-page PageText + render
    │
    ▼
 detect ──► Match[]  ──► geometry ──► Region[]
    │                                    │
    │         findings.json (optional)   │
    │◄───────────────────────────────────┤
    ▼
 apply (hayro render → paint → krilla) ──► output.pdf bytes
    │         always FULL SAVE (no /Prev, no incremental update)
    ▼
 verify (re-open output only) ──► VerificationResult
    │  • text-removal: re-extract after parse/decompress
    │  • metadata-clean / annotations-removed
    │  • raw-byte-scan: non-stream bytes only (stream bodies masked)
    │  • full-save: reject /Prev incremental trailers
    ▼
 cert (SHA-256 only) ──► certificate.json
```

### Incremental saves (PDF 32000 §7.5.6)

Incremental updates append changes and leave deleted objects in the file.
**We never write that way:** `apply` builds a new krilla document and serializes
once. Verification also fails if `/Prev` appears outside stream bodies.

## Tests layout

```text
crates/redact-core/tests/     # library integration tests
crates/redact-cli/tests/e2e.rs
testdata/fixtures/synthetic/  # committed real PDFs + *.meta.json
testdata/generated/           # gitignored runtime outputs
```

- Unit tests sit next to the module they cover.
- E2E invokes the `redact` binary (black box) and uses core `verify` helpers
  so product and tests cannot drift.

## Tooling

| File | Role |
|------|------|
| `mise.toml` | Rust version + tasks (`test`, `lint`, `check`) |
| `rust-toolchain.toml` | rustup mirror of mise pin |

## Versioning conventions

- Certificate format: `redact-certificate/v1` (bump only on breaking schema).
- Findings file: `version: 1` field at top level.
- CLI exit codes: `0` ok, `1` operational failure, `2` usage/IO.
