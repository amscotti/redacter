//! O0 OCR spike — pure-Rust `ocrs` on one JSL Medium (image-only) PDF page.
//!
//! Usage (release — debug is extremely slow):
//!   cargo run -p redact-ocr-spike --release -- \
//!     testdata/corpus/jsl-pdf-deid/medium/00_PDF_Deid_Deidentification_Medium_0.pdf
//!
//! Writes:
//!   testdata/generated/ocr_spike/<stem>_p0.png          — page render
//!   testdata/generated/ocr_spike/<stem>_p0_boxes.png    — word boxes overlay
//!   testdata/generated/ocr_spike/<stem>_p0_ocr.txt      — recognized lines
//!   testdata/generated/ocr_spike/<stem>_p0_report.json  — stats + GT hits

use std::collections::BTreeSet;
use std::fs;
use std::path::{Path, PathBuf};
use std::time::Instant;

use anyhow::{Context, Result, bail};
use image::{Rgba, RgbaImage};
use ocrs::{ImageSource, OcrEngine, OcrEngineParams, TextItem};
use rten::Model;
use serde_json::json;

fn main() -> Result<()> {
    let mut args = std::env::args().skip(1);
    let pdf_path = args.next().map(PathBuf::from).unwrap_or_else(|| {
        PathBuf::from(
            "testdata/corpus/jsl-pdf-deid/medium/00_PDF_Deid_Deidentification_Medium_0.pdf",
        )
    });
    let page_index: usize = args.next().and_then(|s| s.parse().ok()).unwrap_or(0);
    let scale: f32 = args.next().and_then(|s| s.parse().ok()).unwrap_or(2.5);

    if !pdf_path.is_file() {
        bail!(
            "PDF not found: {} — run: LEVEL=Medium MAX_PDFS=10 ./scripts/fetch_public_corpus.sh",
            pdf_path.display()
        );
    }

    let models_dir = find_models_dir()?;
    let det_path = models_dir.join("text-detection.rten");
    let rec_path = models_dir.join("text-recognition.rten");
    for p in [&det_path, &rec_path] {
        if !p.is_file() {
            bail!(
                "missing model {} — run: ./scripts/download_ocrs_models.sh",
                p.display()
            );
        }
    }

    println!("pdf:   {}", pdf_path.display());
    println!("page:  {page_index}");
    println!("scale: {scale}");
    println!("models: {}", models_dir.display());

    let bytes = fs::read(&pdf_path).with_context(|| format!("read {}", pdf_path.display()))?;
    let doc = redact_core::HayroDocument::open(bytes)?;
    let n_pages = doc.page_count();
    if page_index >= n_pages {
        bail!("page {page_index} out of range (doc has {n_pages} pages)");
    }

    // Confirm image-only baseline.
    let native = doc.page_text(page_index)?;
    println!(
        "native text layer: {} chars, {} spans, page {}x{} pts",
        native.text.chars().count(),
        native.spans.len(),
        native.width,
        native.height
    );

    let t_render = Instant::now();
    let rgba = doc.render_page(page_index, scale)?;
    let (img_w, img_h) = (rgba.width(), rgba.height());
    println!(
        "render: {img_w}x{img_h} px in {:.2}s",
        t_render.elapsed().as_secs_f32()
    );

    let out_dir = PathBuf::from("testdata/generated/ocr_spike");
    fs::create_dir_all(&out_dir)?;
    let stem = pdf_path
        .file_stem()
        .and_then(|s| s.to_str())
        .unwrap_or("page");
    let base = format!("{stem}_p{page_index}");

    let plain_png = out_dir.join(format!("{base}.png"));
    rgba.save(&plain_png)
        .with_context(|| format!("write {}", plain_png.display()))?;
    println!("wrote {}", plain_png.display());

    // ocrs wants RGB u8.
    let rgb = rgba_to_rgb(&rgba);
    let img_source = ImageSource::from_bytes(rgb.as_raw(), rgb.dimensions())
        .map_err(|e| anyhow::anyhow!("ImageSource: {e:?}"))?;

    println!("loading ocrs models (release build recommended)…");
    let t_load = Instant::now();
    let detection_model = Model::load_file(&det_path)
        .with_context(|| format!("load detection {}", det_path.display()))?;
    let recognition_model = Model::load_file(&rec_path)
        .with_context(|| format!("load recognition {}", rec_path.display()))?;
    let engine = OcrEngine::new(OcrEngineParams {
        detection_model: Some(detection_model),
        recognition_model: Some(recognition_model),
        ..Default::default()
    })
    .map_err(|e| anyhow::anyhow!("OcrEngine::new: {e}"))?;
    println!("models loaded in {:.2}s", t_load.elapsed().as_secs_f32());

    let t_ocr = Instant::now();
    let ocr_input = engine
        .prepare_input(img_source)
        .map_err(|e| anyhow::anyhow!("prepare_input: {e}"))?;
    let word_rects = engine
        .detect_words(&ocr_input)
        .map_err(|e| anyhow::anyhow!("detect_words: {e}"))?;
    let line_rects = engine.find_text_lines(&ocr_input, &word_rects);
    let line_texts = engine
        .recognize_text(&ocr_input, &line_rects)
        .map_err(|e| anyhow::anyhow!("recognize_text: {e}"))?;
    let ocr_secs = t_ocr.elapsed().as_secs_f32();
    println!(
        "ocr: {} word boxes, {} lines, {:.2}s",
        word_rects.len(),
        line_rects.len(),
        ocr_secs
    );

    // Collect lines / words for report + overlay.
    let mut lines_out: Vec<String> = Vec::new();
    let mut words_out: Vec<(String, [f32; 4])> = Vec::new(); // text, xywh px
    let mut annotated = rgba.clone();

    for line in line_texts.iter().flatten() {
        let line_s = line.to_string();
        if line_s.chars().count() <= 1 {
            continue;
        }
        lines_out.push(line_s.clone());

        // Word-level boxes when available; fall back to line box.
        let words: Vec<_> = line.words().collect();
        if words.is_empty() {
            if let Some(bb) = aabb_from_text_item(line) {
                draw_rect(&mut annotated, bb, Rgba([255, 0, 0, 255]));
                words_out.push((line_s, bb));
            }
        } else {
            for w in words {
                let t = w.to_string();
                if t.trim().is_empty() {
                    continue;
                }
                if let Some(bb) = aabb_from_text_item(&w) {
                    draw_rect(&mut annotated, bb, Rgba([255, 40, 40, 255]));
                    words_out.push((t, bb));
                }
            }
        }
    }

    let boxes_png = out_dir.join(format!("{base}_boxes.png"));
    annotated
        .save(&boxes_png)
        .with_context(|| format!("write {}", boxes_png.display()))?;
    println!("wrote {}", boxes_png.display());

    let text_path = out_dir.join(format!("{base}_ocr.txt"));
    fs::write(&text_path, lines_out.join("\n") + "\n")?;
    println!("wrote {} ({} lines)", text_path.display(), lines_out.len());

    let full_text = lines_out.join("\n");
    let gt_hits = match_ground_truth(&pdf_path, &full_text);

    let report = json!({
        "pdf": pdf_path.display().to_string(),
        "page_index": page_index,
        "scale": scale,
        "render_px": [img_w, img_h],
        "page_pts": [native.width, native.height],
        "native_text_chars": native.text.chars().count(),
        "ocr_word_boxes": word_rects.len(),
        "ocr_lines_kept": lines_out.len(),
        "ocr_words_kept": words_out.len(),
        "ocr_secs": ocr_secs,
        "ocr_char_count": full_text.chars().count(),
        "gt_unique": gt_hits.gt_unique,
        "gt_note": gt_hits.note,
        "gt_hits": gt_hits.hits,
        "gt_misses": gt_hits.misses,
        "gt_hit_count": gt_hits.hits.len(),
        "gt_miss_count": gt_hits.misses.len(),
        "sample_lines": lines_out.iter().take(40).cloned().collect::<Vec<_>>(),
        "sample_words": words_out.iter().take(30).map(|(t, b)| json!({
            "text": t,
            "xywh_px": b,
        })).collect::<Vec<_>>(),
        "artifacts": {
            "page_png": plain_png.display().to_string(),
            "boxes_png": boxes_png.display().to_string(),
            "ocr_txt": text_path.display().to_string(),
        },
        "go_no_go_notes": [
            "GO if: ocr_lines_kept > 0, boxes visibly cover text, some GT PHI appears in OCR text.",
            "NO-GO if: empty OCR, garbage only, or boxes wildly misaligned on boxes_png.",
            "Pure Rust ocrs+rten only (no System Tesseract).",
        ],
    });

    let report_path = out_dir.join(format!("{base}_report.json"));
    fs::write(&report_path, serde_json::to_string_pretty(&report)? + "\n")?;
    println!("wrote {}", report_path.display());

    println!("\n=== OCR text (first 30 lines) ===");
    for (i, line) in lines_out.iter().take(30).enumerate() {
        println!("{i:3}: {line}");
    }
    if lines_out.len() > 30 {
        println!("… ({} more lines)", lines_out.len() - 30);
    }

    println!("\n=== Ground truth string hits (loose) ===");
    if let Some(note) = &gt_hits.note {
        println!("  note: {note}");
    }
    println!(
        "hits {}/{} unique GT strings",
        gt_hits.hits.len(),
        gt_hits.gt_unique
    );
    if !gt_hits.hits.is_empty() {
        println!("HIT samples:");
        for s in gt_hits.hits.iter().take(15) {
            println!("  + {s}");
        }
    }
    if !gt_hits.misses.is_empty() {
        println!("MISS samples:");
        for s in gt_hits.misses.iter().take(15) {
            println!("  - {s}");
        }
    }

    println!("\n=== Go / no-go checklist ===");
    let has_text = !lines_out.is_empty();
    let has_boxes = !words_out.is_empty();
    let any_gt = !gt_hits.hits.is_empty();
    println!("  [{}] OCR produced lines", yn(has_text));
    println!("  [{}] Word/line boxes drawn", yn(has_boxes));
    println!(
        "  [{}] At least one GT PHI string found in OCR text",
        yn(any_gt)
    );
    println!(
        "  [?] Visual: open {} and confirm boxes cover ink",
        boxes_png.display()
    );
    if has_text && has_boxes {
        println!("\nPreliminary: ENGINE SPIKE LOOKS VIABLE — inspect boxes PNG before O1 wiring.");
    } else {
        println!(
            "\nPreliminary: ENGINE SPIKE WEAK — empty or unusable OCR; try scale=3 or alternate backend."
        );
    }

    Ok(())
}

fn yn(b: bool) -> char {
    if b { 'x' } else { ' ' }
}

fn find_models_dir() -> Result<PathBuf> {
    if let Ok(p) = std::env::var("REDACT_OCR_MODELS") {
        let p = PathBuf::from(p);
        if p.is_dir() {
            return Ok(p);
        }
    }
    let candidates = [
        PathBuf::from("models/ocr"),
        PathBuf::from("models"),
        dirs_next_home_cache(),
    ];
    for c in candidates {
        if c.join("text-detection.rten").is_file() && c.join("text-recognition.rten").is_file() {
            return Ok(c);
        }
    }
    Ok(PathBuf::from("models/ocr"))
}

fn dirs_next_home_cache() -> PathBuf {
    // Match ocrs-cli cache layout if user ran `ocrs` once.
    if let Some(home) = std::env::var_os("HOME") {
        return PathBuf::from(home).join(".cache/ocrs");
    }
    PathBuf::from(".cache/ocrs")
}

fn rgba_to_rgb(rgba: &RgbaImage) -> image::RgbImage {
    let (w, h) = rgba.dimensions();
    let mut rgb = image::RgbImage::new(w, h);
    for (x, y, p) in rgba.enumerate_pixels() {
        rgb.put_pixel(x, y, image::Rgb([p[0], p[1], p[2]]));
    }
    rgb
}

/// Axis-aligned bounding box [x, y, w, h] in pixel space from a TextItem.
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

fn draw_rect(img: &mut RgbaImage, xywh: [f32; 4], color: Rgba<u8>) {
    let (iw, ih) = img.dimensions();
    let x0 = xywh[0].floor().max(0.0) as u32;
    let y0 = xywh[1].floor().max(0.0) as u32;
    let x1 = (xywh[0] + xywh[2]).ceil().min(iw as f32 - 1.0).max(0.0) as u32;
    let y1 = (xywh[1] + xywh[3]).ceil().min(ih as f32 - 1.0).max(0.0) as u32;
    if x1 <= x0 || y1 <= y0 {
        return;
    }
    // Rectangle outline, 2px thick.
    for t in 0..2u32 {
        for x in x0..=x1 {
            if y0 + t < ih {
                img.put_pixel(x, y0 + t, color);
            }
            if y1.saturating_sub(t) < ih {
                img.put_pixel(x, y1.saturating_sub(t), color);
            }
        }
        for y in y0..=y1 {
            if x0 + t < iw {
                img.put_pixel(x0 + t, y, color);
            }
            if x1.saturating_sub(t) < iw {
                img.put_pixel(x1.saturating_sub(t), y, color);
            }
        }
    }
}

struct GtHits {
    gt_unique: usize,
    hits: Vec<String>,
    misses: Vec<String>,
    /// Diagnostic note (e.g. GT file missing) — not counted as a miss.
    note: Option<String>,
}

fn match_ground_truth(pdf_path: &Path, ocr_text: &str) -> GtHits {
    let gt_path =
        PathBuf::from("testdata/corpus/jsl-pdf-deid/ground_truth/pdf_deid_gts_medium.json");
    let Ok(raw) = fs::read_to_string(&gt_path) else {
        return GtHits {
            gt_unique: 0,
            hits: vec![],
            misses: vec![],
            note: Some("(no medium GT file)".into()),
        };
    };
    let Ok(map) = serde_json::from_str::<serde_json::Map<String, serde_json::Value>>(&raw) else {
        return GtHits {
            gt_unique: 0,
            hits: vec![],
            misses: vec![],
            note: Some("(bad GT json)".into()),
        };
    };

    let name = pdf_path.file_name().and_then(|s| s.to_str()).unwrap_or("");
    // 00_PDF_Deid_Deidentification_Medium_0.pdf → PDF_Deid_Deidentification_Medium_0.pdf
    let key = name
        .split_once('_')
        .map(|(_, rest)| rest.to_string())
        .unwrap_or_else(|| name.to_string());

    let list = map
        .get(&key)
        .and_then(|v| v.as_array())
        .cloned()
        .unwrap_or_default();

    let mut seen = BTreeSet::new();
    let mut unique: Vec<String> = Vec::new();
    for v in list {
        if let Some(s) = v.as_str()
            && seen.insert(s.to_string())
        {
            unique.push(s.to_string());
        }
    }

    // Normalize the OCR text once; both passes are reused for every GT string
    // (loose = alnum-only, spaced = whitespace-collapsed, punctuation kept).
    let ocr_norm = normalize_loose(ocr_text);
    let ocr_spaced = normalize_space(ocr_text);
    let mut hits = Vec::new();
    let mut misses = Vec::new();
    for g in &unique {
        let gn = normalize_loose(g);
        // No length gate: short GT values (e.g. age "74") must still be able
        // to hit. Empty loose forms (punctuation-only GT) fall through to the
        // spaced pass below instead of being dropped.
        if !gn.is_empty() && ocr_norm.contains(&gn) {
            hits.push(g.clone());
            continue;
        }
        // Also try spaced normalized substring (keeps punctuation, so it can
        // match values whose loose form is empty).
        let g2 = normalize_space(g);
        if !g2.is_empty() && ocr_spaced.contains(&g2) {
            hits.push(g.clone());
        } else {
            // Unmatched or unmatchable (both normalizations empty) — count it
            // as a miss so hits + misses == gt_unique always.
            misses.push(g.clone());
        }
    }

    GtHits {
        gt_unique: unique.len(),
        hits,
        misses,
        note: None,
    }
}

fn normalize_loose(s: &str) -> String {
    s.chars()
        .filter(|c| c.is_ascii_alphanumeric())
        .map(|c| c.to_ascii_lowercase())
        .collect()
}

fn normalize_space(s: &str) -> String {
    s.split_whitespace()
        .collect::<Vec<_>>()
        .join(" ")
        .to_ascii_lowercase()
}
