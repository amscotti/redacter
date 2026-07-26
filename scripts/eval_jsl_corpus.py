#!/usr/bin/env python3
"""Score redact detect+redact+verify against JSL pdf-deid ground-truth string lists."""
from __future__ import annotations

import json
import re
import subprocess
import sys
from collections import Counter
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
CORPUS = ROOT / "testdata/corpus/jsl-pdf-deid"
REDACT = ROOT / "target/release/redact"
# Per-doc timeouts (seconds), matching crates/redact-cli/tests/corpus_public.rs
# so one pathological PDF can never hang the whole evaluation.
DETECT_TIMEOUT = 120
REDACT_TIMEOUT = 180


def resolve_paths(level: str) -> tuple[Path, Path, Path]:
    """Return (subset_dir, gt_path, out_dir) for Easy|Medium|Hard."""
    lc = level.lower()
    if lc not in ("easy", "medium", "hard"):
        raise SystemExit(f"LEVEL must be Easy, Medium, or Hard (got {level})")
    # Prefer level-specific dir; fall back to legacy subset/ for Easy.
    subset = CORPUS / lc
    if not subset.is_dir() or not any(subset.glob("*.pdf")):
        if lc == "easy":
            subset = CORPUS / "subset"
        else:
            raise SystemExit(
                f"missing corpus at {CORPUS / lc} — run: "
                f"LEVEL={level.capitalize()} ./scripts/fetch_public_corpus.sh"
            )
    gt = CORPUS / "ground_truth" / f"pdf_deid_gts_{lc}.json"
    if not gt.is_file():
        raise SystemExit(f"missing ground truth {gt}")
    out = ROOT / "testdata/generated" / f"jsl_eval_{lc}"
    return subset, gt, out


def normalize(s: str) -> str:
    return re.sub(r"\s+", " ", s.strip().lower())


def normalize_loose(s: str) -> str:
    """Lowercase and strip all non-alphanumeric (handles glued vs spaced names)."""
    return re.sub(r"[^a-z0-9]+", "", s.strip().lower())


def rough_type(s: str) -> str:
    t = s.strip()
    if re.fullmatch(r"\d{3}-\d{2}-\d{4}", t):
        return "ssn"
    if re.fullmatch(r"\d{1,2}[/\-.]\d{1,2}[/\-.]\d{2,4}", t) or re.fullmatch(
        r"\d{4}-\d{2}-\d{2}", t
    ):
        return "date"
    if re.fullmatch(r"HOSP\d+", t, re.I):
        return "hosp_id"
    if re.fullmatch(r"DR\d+[A-Z]?", t, re.I):
        return "dr_id"
    if re.fullmatch(r"\d{1,3}-year-old", t, re.I):
        return "age_phrase"
    if re.fullmatch(r"\d{1,3}", t) and t.isdigit() and 1 <= int(t) <= 120:
        return "age_num"
    if re.fullmatch(r"\(?\d{3}\)?[\s\-.]?\d{3}[\s\-.]?\d{4}", t) or (
        t.startswith("+") and sum(c.isdigit() for c in t) >= 10
    ):
        return "phone_or_id"
    if any(
        w in t.lower()
        for w in ("inc", "medical", "hospital", "institute", "clinic", "center")
    ):
        return "name_or_org_text"
    if re.search(r"[A-Za-z]", t):
        return "name_or_org_text"
    return "other"


def strings_match(found: str, gt: str) -> bool:
    fn = normalize(found)
    gn = normalize(gt)
    if not fn or not gn:
        return False
    if gn == fn or gn in fn or fn in gn:
        return True
    # Space-insensitive: "KimberlyLawrence" ↔ "Kimberly Lawrence"
    fl = normalize_loose(found)
    gl = normalize_loose(gt)
    if fl and gl and (fl == gl or gl in fl or fl in gl):
        return True
    # Pull a years-integer from common age findings / GT forms.
    def age_years(s: str) -> str | None:
        s = normalize(s)
        for pat in (
            r"^age\s*:\s*(\d{1,3})$",
            r"^aged\s+(\d{1,3})$",
            r"^(\d{1,3})-year-old$",
            r"^(\d{1,3})$",
        ):
            m = re.match(pat, s)
            if m:
                return m.group(1)
        return None

    af, ag = age_years(found), age_years(gt)
    if af is not None and ag is not None and af == ag:
        # "Age: 56" / "aged 56" / "56" ↔ "56-year-old"
        if any(
            re.search(p, normalize(x))
            for x in (found, gt)
            for p in (r"age\s*:", r"aged\s+", r"year-old", r"^\d{1,3}$")
        ):
            return True
    return False


def match_gt(found: list[str], gt_unique: list[str]) -> tuple[set[str], list[str], set[str]]:
    """Return (tp_gt, fp_found, fn_gt).

    Recall: each GT string may be covered by any finding (one finding can cover
    multiple related GTs, e.g. "46-year-old" covers both that phrase and "46").
    Precision: a finding is FP only if it matches no GT string.
    """
    tp_gt = {g for g in gt_unique if any(strings_match(f, g) for f in found)}
    # FP counts per occurrence (a spurious string emitted twice is two FPs),
    # mirroring crates/redact-cli/tests/corpus_public.rs so both harnesses
    # report identical precision for the same findings.
    fp = [f for f in found if not any(strings_match(f, g) for g in gt_unique)]
    fn = {g for g in gt_unique if g not in tp_gt}
    return tp_gt, fp, fn


def ocr_cli_args() -> list[str]:
    """Extra CLI flags for OCR builds. OCR_MODE=off|auto|on|force (default: auto for Medium/Hard)."""
    import os

    mode = os.environ.get("OCR_MODE", "").strip().lower()
    level = os.environ.get("LEVEL", "Easy").strip().lower()
    if not mode:
        # Image-only tiers need OCR; Easy has a text layer.
        mode = "auto" if level in ("medium", "hard") else "off"
    if mode in ("", "off"):
        return []
    args = ["--ocr", mode]
    if scale := os.environ.get("OCR_SCALE", "").strip():
        args.extend(["--ocr-scale", scale])
    if prep := os.environ.get("OCR_PREPROCESS", "").strip().lower():
        if prep in ("off", "light", "strong"):
            args.extend(["--ocr-preprocess", prep])
    if os.environ.get("OCR_NO_RETRY", "").strip() in ("1", "true", "yes"):
        args.append("--ocr-no-retry")
    return args


def detect_extra_args() -> list[str]:
    """Non-OCR detect flags. AGGRESSIVE=1 enables recall mode (bare dates /
    phones): the mode the Easy GT floor is calibrated for."""
    import os

    if os.environ.get("AGGRESSIVE", "").strip() in ("1", "true", "yes"):
        return ["--aggressive"]
    return []


def run_one(pdf: Path, out: Path) -> dict:
    stem = pdf.stem
    findings_path = out / f"{stem}.findings.json"
    redacted = out / f"{stem}.redacted.pdf"
    cert = out / f"{stem}.cert.json"
    # Remove stale per-doc outputs from earlier runs so a failed detect can
    # never be followed by `redact --findings <stale file>` from a prior run.
    for stale in (findings_path, redacted, cert):
        try:
            stale.unlink()
        except FileNotFoundError:
            pass
    ocr_args = ocr_cli_args()
    detect_args = detect_extra_args()

    try:
        r = subprocess.run(
            [str(REDACT), "detect", str(pdf), "-o", str(findings_path), *ocr_args, *detect_args],
            capture_output=True,
            text=True,
            timeout=DETECT_TIMEOUT,
        )
        detect_ok = r.returncode == 0
        detect_err = r.stderr[-500:] if not detect_ok else ""
    except subprocess.TimeoutExpired as exc:
        # One pathological PDF must not hang the whole evaluation.
        detect_ok = False
        detect_err = f"detect timed out after {exc.timeout}s"
    found_texts: list[str] = []
    categories: Counter = Counter()
    if detect_ok and findings_path.exists():
        try:
            data = json.loads(findings_path.read_text())
            for it in data.get("items", []):
                if not isinstance(it, dict):
                    continue
                txt = it.get("text")
                if txt is None:
                    continue
                found_texts.append(txt)
                categories[it.get("category", "?")] += 1
        except (json.JSONDecodeError, TypeError, AttributeError) as exc:
            # Malformed findings output: fail just this doc instead of
            # aborting the whole evaluation.
            detect_ok = False
            detect_err = f"findings parse error: {exc}"

    try:
        r2 = subprocess.run(
            [
                str(REDACT),
                "redact",
                str(pdf),
                "-o",
                str(redacted),
                "--findings",
                str(findings_path),
                "--cert",
                str(cert),
            ],
            capture_output=True,
            text=True,
            timeout=REDACT_TIMEOUT,
        )
        redact_ok = r2.returncode == 0
        redact_stderr = r2.stderr[-500:] if not redact_ok else ""
    except subprocess.TimeoutExpired as exc:
        # One pathological PDF must not hang the whole evaluation.
        redact_ok = False
        redact_stderr = f"redact timed out after {exc.timeout}s"
    verified = False
    n_redactions = 0
    residual_in_raw = 0
    redact_extra_err = ""
    if redact_ok and cert.exists():
        try:
            c = json.loads(cert.read_text())
        except (json.JSONDecodeError, TypeError) as exc:
            # Malformed cert output: fail just this doc instead of aborting
            # the entire multi-doc evaluation.
            redact_ok = False
            redact_extra_err = f"cert parse error: {exc}"
            c = None
        if c is not None:
            ver = c.get("verification") or {}
            if isinstance(ver, dict) and "passed" in ver:
                verified = bool(ver["passed"])
            elif c.get("passed") is True or c.get("status") == "pass":
                verified = True
            # Explicit is-not-None checks so a legitimate zero (n_redactions: 0 or
            # an empty redactions list) is not silently replaced by len(found_texts).
            n_redactions = c.get("n_redactions")
            if n_redactions is None:
                n_redactions = c.get("redaction_count")
            if n_redactions is None:
                redactions = c.get("redactions")
                n_redactions = len(redactions) if isinstance(redactions, list) else None
            if n_redactions is None:
                n_redactions = len(found_texts)
            residual_in_raw = int(c.get("residual_in_raw") or 0)

    return {
        "detect_ok": detect_ok,
        "redact_ok": redact_ok,
        "verified": verified,
        "found_texts": found_texts,
        "categories": dict(categories),
        "n_redactions": n_redactions,
        "residual_in_raw": residual_in_raw,
        "detect_stderr": detect_err,
        "redact_stderr": (redact_stderr + "\n" + redact_extra_err).strip()
        if not redact_ok
        else "",
    }


def main() -> int:
    if not REDACT.exists():
        print(f"missing binary: {REDACT}", file=sys.stderr)
        return 1

    import os

    level = os.environ.get("LEVEL", "Easy")
    subset, gt_path, out = resolve_paths(level)
    gt_all = json.loads(gt_path.read_text())
    out.mkdir(parents=True, exist_ok=True)

    per_doc = []
    cat_detected = Counter()
    fn_types = Counter()
    tp_types = Counter()
    total_gt = total_tp = total_fp = total_findings = 0
    docs_verified = docs_redact = docs_findings = 0

    pdfs = sorted(subset.glob("*.pdf"))
    ocr_args = ocr_cli_args()
    print(f"Evaluating LEVEL={level} n={len(pdfs)} dir={subset} with {REDACT}", flush=True)
    print(f"GT: {gt_path}", flush=True)
    print(f"OCR args: {ocr_args or ['(none)']}", flush=True)
    print(f"Detect args: {detect_extra_args() or ['(none)']}", flush=True)

    for pdf in pdfs:
        # Map subset filename back to GT key
        # e.g. 00_PDF_Deid_Deidentification_0.pdf -> PDF_Deid_Deidentification_0.pdf
        name = pdf.name
        m = re.match(r"\d+_(.+)", name)
        gt_key = m.group(1) if m else name
        gt_list = gt_all.get(gt_key) or gt_all.get(name) or []
        # unique preserve order
        seen = set()
        gt_unique = []
        for s in gt_list:
            if s not in seen:
                seen.add(s)
                gt_unique.append(s)

        result = run_one(pdf, out)
        found = result["found_texts"]
        tp_gt, fp, fn = match_gt(found, gt_unique)
        for c, n in result["categories"].items():
            cat_detected[c] += n
        for g in tp_gt:
            tp_types[rough_type(g)] += 1
        for g in fn:
            fn_types[rough_type(g)] += 1

        recall = len(tp_gt) / len(gt_unique) if gt_unique else 1.0
        # precision: fraction of found strings that match some GT
        matched_found = len(found) - len(fp)
        precision = matched_found / len(found) if found else 1.0

        total_gt += len(gt_unique)
        total_tp += len(tp_gt)
        total_fp += len(fp)
        total_findings += len(found)
        if result["verified"]:
            docs_verified += 1
        if result["redact_ok"]:
            docs_redact += 1
        if found:
            docs_findings += 1

        row = {
            "file": gt_key,
            "gt_unique": len(gt_unique),
            "found": len(found),
            "tp_gt": len(tp_gt),
            "fp": len(fp),
            "fn": len(fn),
            "recall": round(recall, 3),
            "precision": round(precision, 3),
            "detect_ok": result["detect_ok"],
            "redact_ok": result["redact_ok"],
            "verified": result["verified"],
            "n_redactions": result["n_redactions"],
            "residual_in_raw": result["residual_in_raw"],
            "fp_samples": sorted(set(fp))[:12],
            "fn_samples": sorted(fn)[:12],
        }
        per_doc.append(row)
        print(
            f"  {gt_key}: recall={recall:.0%} prec={precision:.0%} "
            f"found={len(found)} gt={len(gt_unique)} verified={result['verified']}",
            flush=True,
        )
        if not result["detect_ok"]:
            print("    detect err:", result["detect_stderr"], flush=True)
        if not result["redact_ok"]:
            print("    redact err:", result["redact_stderr"], flush=True)

    n = len(per_doc)
    summary = {
        "level": level,
        "ocr_args": ocr_args,
        "n_docs": n,
        "micro_recall_vs_gt_strings": round(total_tp / total_gt, 4) if total_gt else 1.0,
        "micro_precision_vs_gt_strings": round(
            (total_findings - total_fp) / total_findings, 4
        )
        if total_findings
        else 1.0,
        "total_gt_unique_strings": total_gt,
        "total_gt_matched": total_tp,
        "total_findings": total_findings,
        "total_fp": total_fp,
        "docs_all_verified": docs_verified,
        "docs_redact_ok": docs_redact,
        "docs_with_any_findings": docs_findings,
        "avg_findings_per_doc": round(total_findings / n, 2) if n else 0,
        "avg_recall": round(sum(p["recall"] for p in per_doc) / n, 4) if n else 0,
        "avg_precision": round(sum(p["precision"] for p in per_doc) / n, 4) if n else 0,
        "category_counts_detected": dict(cat_detected),
        "fn_by_rough_type": dict(fn_types),
        "tp_by_rough_type": dict(tp_types),
        "notes": [
            "GT is a flat list of PHI strings per PDF (names, dates, SSNs, phones, orgs, addresses, etc.).",
            "Detector is regex + labeled-field heuristics (no OCR, no ML NER).",
            "Precision/recall are approximate string matches against GT, not bounding-box IoU.",
            "Verified means our post-redaction checks passed for listed redactions.",
            "Medium/Hard add visual noise and ADDRESS entities; text-layer still required.",
        ],
        "per_doc": per_doc,
    }
    out_path = out / "evaluation.json"
    out_path.write_text(json.dumps(summary, indent=2) + "\n")
    print("\n=== Summary ===")
    for k in (
        "level",
        "n_docs",
        "micro_recall_vs_gt_strings",
        "micro_precision_vs_gt_strings",
        "total_gt_unique_strings",
        "total_gt_matched",
        "total_findings",
        "total_fp",
        "docs_all_verified",
        "category_counts_detected",
        "fn_by_rough_type",
        "tp_by_rough_type",
    ):
        print(f"  {k}: {summary[k]}")
    print(f"\nWrote {out_path}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
