//! Deprecated Kaggle W-2 corpus entrypoint.
//!
//! Prefer the John Snow Labs synthetic PDF de-id corpus:
//!   ./scripts/fetch_public_corpus.sh
//!   mise run test:corpus
//!
//! See `corpus_public.rs`.

#[test]
#[ignore = "deprecated: use corpus_public (JSL pdf-deid) via mise run test:corpus"]
fn corpus_w2_deprecated_redirect() {
    eprintln!(
        "The Kaggle W-2 corpus path is deprecated for default testing.\n\
         Use the John Snow Labs synthetic PDF de-id dataset instead:\n\
           ./scripts/fetch_public_corpus.sh\n\
           mise run test:corpus\n\
         See testdata/README.md."
    );
}
