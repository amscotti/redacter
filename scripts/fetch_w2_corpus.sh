#!/usr/bin/env bash
# Deprecated: W-2 Kaggle path is secondary (image scans; needs OCR).
# Primary public corpus is John Snow Labs PDF de-id:
echo "Note: prefer ./scripts/fetch_public_corpus.sh (JSL synthetic PDF de-id)."
echo "Redirecting..."
exec "$(cd "$(dirname "$0")" && pwd)/fetch_public_corpus.sh" "$@"
