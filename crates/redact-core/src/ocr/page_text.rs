//! Build `PageText` from OCR word/line geometry.

use crate::types::{PageText, Rect, TextSpan};

/// One recognized word (or line fallback) with page-point geometry.
#[derive(Debug, Clone)]
pub struct OcrWord {
    pub text: String,
    /// Top-left page points (unscaled), same as `text_device`.
    pub rect: Rect,
}

/// Build `PageText` from lines of words.
///
/// Words and lines are joined with a single space (not `\n`) so detectors see
/// continuous text — OCR often splits "Susan" / "Frances" / "Martin" or phone
/// groups across visual lines. Each word is still its own geometry span.
/// `PageText.width` / `height` are the unscaled page size in points.
pub fn page_text_from_lines(
    page_index: usize,
    page_width: f32,
    page_height: f32,
    lines: &[Vec<OcrWord>],
) -> PageText {
    let mut text = String::new();
    let mut spans = Vec::new();

    for (li, line) in lines.iter().enumerate() {
        for (wi, word) in line.iter().enumerate() {
            if li > 0 || wi > 0 {
                text.push(' ');
            }
            let start = text.len();
            text.push_str(&word.text);
            let end = text.len();
            spans.push(TextSpan {
                start,
                end,
                text: word.text.clone(),
                rect: word.rect,
                ink_w: None,
            });
        }
    }

    PageText {
        page_index,
        text,
        spans,
        width: page_width,
        height: page_height,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn word(s: &str, x: f32, y: f32, w: f32, h: f32) -> OcrWord {
        OcrWord {
            text: s.to_string(),
            rect: Rect::new(x, y, w, h),
        }
    }

    #[test]
    fn joins_words_and_lines_with_byte_offsets() {
        let lines = vec![
            vec![
                word("Hello", 0.0, 0.0, 40.0, 12.0),
                word("世界", 45.0, 0.0, 30.0, 12.0),
            ],
            vec![word("SSN", 0.0, 20.0, 25.0, 12.0)],
        ];
        let pt = page_text_from_lines(2, 612.0, 792.0, &lines);
        assert_eq!(pt.page_index, 2);
        assert_eq!(pt.width, 612.0);
        assert_eq!(pt.height, 792.0);
        // Lines join with space (not newline) for detector-friendly OCR text.
        assert_eq!(pt.text, "Hello 世界 SSN");
        assert_eq!(pt.spans.len(), 3);

        assert_eq!(pt.spans[0].text, "Hello");
        assert_eq!(&pt.text[pt.spans[0].start..pt.spans[0].end], "Hello");

        assert_eq!(pt.spans[1].text, "世界");
        assert_eq!(&pt.text[pt.spans[1].start..pt.spans[1].end], "世界");
        // "Hello " is 6 bytes; 世界 is 6 UTF-8 bytes.
        assert_eq!(pt.spans[1].start, 6);
        assert_eq!(pt.spans[1].end, 12);

        assert_eq!(pt.spans[2].text, "SSN");
        assert_eq!(&pt.text[pt.spans[2].start..pt.spans[2].end], "SSN");
        // after "Hello 世界 " = 6 + 6 + 1 = 13
        assert_eq!(pt.spans[2].start, 13);

        assert!((pt.spans[0].rect.x - 0.0).abs() < f32::EPSILON);
        assert!((pt.spans[2].rect.y - 20.0).abs() < f32::EPSILON);
    }

    #[test]
    fn empty_lines_yield_empty_page() {
        let pt = page_text_from_lines(0, 100.0, 200.0, &[]);
        assert!(pt.text.is_empty());
        assert!(pt.spans.is_empty());
        assert_eq!(pt.width, 100.0);
        assert_eq!(pt.height, 200.0);
    }
}
