#!/usr/bin/env bash
# Fetch a local subset of the John Snow Labs synthetic PDF de-identification
# dataset for optional corpus e2e tests.
#
# Dataset (synthetic medical PDFs; no real patient data):
#   https://github.com/JohnSnowLabs/pdf-deid-dataset
#
# Everything lands under testdata/corpus/ (gitignored). Never commit real PII.
#
# Usage:
#   ./scripts/fetch_public_corpus.sh
#   MAX_PDFS=30 LEVEL=Easy ./scripts/fetch_public_corpus.sh
#   LEVEL=Medium MAX_PDFS=10 ./scripts/fetch_public_corpus.sh
#   LEVEL=Hard MAX_PDFS=10 ./scripts/fetch_public_corpus.sh
#   LEVEL=all ./scripts/fetch_public_corpus.sh   # Easy+Medium+Hard
#
# Layout (levels do not overwrite each other):
#   testdata/corpus/jsl-pdf-deid/
#     easy/     # Easy PDFs (also mirrored to subset/ for backward compat)
#     medium/
#     hard/
#     subset/   # = easy/ (legacy path used by e2e)
#     ground_truth/
#     raw/

set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
REPO="JohnSnowLabs/pdf-deid-dataset"
LEVEL_IN="${LEVEL:-Easy}"
# Remember whether MAX_PDFS was explicitly set so per-level defaults for
# LEVEL=all only apply when the user did not override the cap.
MAX_PDFS_IS_SET="${MAX_PDFS+x}"
MAX_PDFS="${MAX_PDFS:-30}"
BASE_URL="https://raw.githubusercontent.com/${REPO}/main"

CORPUS_ROOT="${ROOT}/testdata/corpus/jsl-pdf-deid"
GT_DIR="${CORPUS_ROOT}/ground_truth"
RAW_DIR="${CORPUS_ROOT}/raw"

normalize_level() {
  case "$1" in
    Easy|easy) echo Easy ;;
    Medium|medium) echo Medium ;;
    Hard|hard) echo Hard ;;
    all|All) echo all ;;
    *)
      echo "error: LEVEL must be Easy, Medium, Hard, or all (got $1)" >&2
      return 1
      ;;
  esac
}

fetch_level() {
  local LEVEL="$1"
  local level_lc
  level_lc="$(echo "${LEVEL}" | tr '[:upper:]' '[:lower:]')"
  local SUBSET_DIR="${CORPUS_ROOT}/${level_lc}"
  local max="${MAX_PDFS}"

  # Full level sizes when MAX not overridden for "all"
  if [[ -z "${MAX_PDFS_IS_SET}" ]] && [[ "${LEVEL_IN}" == "all" || "${LEVEL_IN}" == "All" ]]; then
    case "${LEVEL}" in
      Easy) max=30 ;;
      Medium|Hard) max=10 ;;
    esac
  fi

  mkdir -p "${SUBSET_DIR}" "${GT_DIR}" "${RAW_DIR}"

  echo "Fetching JSL pdf-deid-dataset level=${LEVEL} max=${max}"
  echo "Source: https://github.com/${REPO}"
  echo

  local API_URL="https://api.github.com/repos/${REPO}/contents/PDF_Original/${LEVEL}"
  local LIST_JSON="${RAW_DIR}/list_${LEVEL}.json"
  if ! curl -fsSL -o "${LIST_JSON}" "${API_URL}"; then
    echo "error: failed to list ${API_URL}" >&2
    echo "Check network access to api.github.com" >&2
    return 1
  fi

  local NAMES_FILE="${RAW_DIR}/names_${LEVEL}.txt"
  python3 - <<PY
import json
from pathlib import Path
data = json.loads(Path("${LIST_JSON}").read_text())
names = sorted(
    x["name"] for x in data
    if x.get("type") == "file" and x["name"].lower().endswith(".pdf")
)
Path("${NAMES_FILE}").write_text("\n".join(names) + ("\n" if names else ""))
print(f"listed {len(names)} PDFs")
PY

  if [[ ! -s "${NAMES_FILE}" ]]; then
    echo "error: no PDFs listed for level ${LEVEL}" >&2
    return 1
  fi

  rm -rf "${SUBSET_DIR}"
  mkdir -p "${SUBSET_DIR}"

  local count=0
  while IFS= read -r name; do
    [[ -n "$name" ]] || continue
    if [[ "$count" -ge "$max" ]]; then
      break
    fi
    local url="${BASE_URL}/PDF_Original/${LEVEL}/${name}"
    local dest="${SUBSET_DIR}/$(printf '%02d' "$count")_${name}"
    echo "  download ${name}"
    if ! curl -fsSL -o "${dest}" "${url}"; then
      echo "  warn: failed ${url}" >&2
      rm -f "${dest}"
      continue
    fi
    if ! head -c 5 "${dest}" | grep -q '%PDF'; then
      echo "  warn: not a PDF, removing ${dest}" >&2
      rm -f "${dest}"
      continue
    fi
    count=$((count + 1))
  done <"${NAMES_FILE}"

  local GT_REMOTE="pdf_deid_gts_${level_lc}.json"
  local GT_URL="${BASE_URL}/Mapping/all_phi/${GT_REMOTE}"
  echo "  download ground truth ${GT_REMOTE}"
  if curl -fsSL -o "${GT_DIR}/${GT_REMOTE}" "${GT_URL}"; then
    echo "  ground truth -> ${GT_DIR}/${GT_REMOTE}"
  else
    echo "  warn: could not fetch ground truth (non-fatal)"
  fi

  {
    echo "# John Snow Labs PDF De-Identification Dataset (synthetic)"
    echo "# repo: https://github.com/${REPO}"
    echo "# level: ${LEVEL}"
    echo "# max_pdfs: ${max}"
    echo "# count: ${count}"
    echo "# generated: $(date -u +%Y-%m-%dT%H:%M:%SZ 2>/dev/null || date)"
    echo "# note: fully synthetic medical-style docs; no real patient data"
    echo
    ls -1 "${SUBSET_DIR}" 2>/dev/null || true
  } >"${SUBSET_DIR}/MANIFEST.txt"

  # Legacy path: subset/ mirrors Easy for existing e2e tests.
  if [[ "${LEVEL}" == "Easy" ]]; then
    rm -rf "${CORPUS_ROOT}/subset"
    mkdir -p "${CORPUS_ROOT}/subset"
    # Hardlink/copy files so tests keep working without path changes.
    cp -R "${SUBSET_DIR}/." "${CORPUS_ROOT}/subset/"
  fi

  echo
  if [[ "$count" -eq 0 ]]; then
    echo "error: downloaded 0 PDFs for ${LEVEL}" >&2
    return 1
  fi

  echo "Ready: ${count} PDFs in ${SUBSET_DIR}"
}

LEVEL="$(normalize_level "${LEVEL_IN}")"

mkdir -p "${CORPUS_ROOT}" "${GT_DIR}" "${RAW_DIR}"

if [[ "${LEVEL}" == "all" ]]; then
  fetch_level Easy
  fetch_level Medium
  fetch_level Hard
else
  fetch_level "${LEVEL}"
fi

{
  echo "# John Snow Labs PDF De-Identification Dataset (synthetic)"
  echo "# repo: https://github.com/${REPO}"
  echo "# levels present:"
  for d in easy medium hard subset; do
    if [[ -d "${CORPUS_ROOT}/${d}" ]]; then
      n=$(find "${CORPUS_ROOT}/${d}" -maxdepth 1 -name '*.pdf' 2>/dev/null | wc -l | tr -d ' ')
      echo "#   ${d}: ${n} pdfs"
    fi
  done
  echo "# generated: $(date -u +%Y-%m-%dT%H:%M:%SZ 2>/dev/null || date)"
} >"${CORPUS_ROOT}/MANIFEST.txt"

echo "Manifest: ${CORPUS_ROOT}/MANIFEST.txt"
echo
echo "Run eval:"
echo "  LEVEL=Easy   mise run eval:jsl"
echo "  LEVEL=Medium mise run eval:jsl"
echo "  LEVEL=Hard   mise run eval:jsl"
echo "  mise run test:corpus"
echo
echo "Reminder: only synthetic/public forms — never real personal documents."
