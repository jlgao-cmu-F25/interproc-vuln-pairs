"""Build vulnerable/fixed CVE pairs and paired prompts from sw-vuln records.

Run ``python -m repro.pairs`` after ``python -m repro.setup_data``. Generated
prompts stay under third_party/; the tracked manifest and review sample go in
results/.
"""
import csv
import json
import random

from .paths import PROMPTS_DIR, RESULTS_DIR, SWVULN_DATA

RAW_CVES = SWVULN_DATA / "raw_cves"
PAIRED_PROMPTS = SWVULN_DATA / "paired_prompts"
LANGUAGES = {"c": "C", "cpp": "C++", "python": "Python"}
CONTEXTS = {
    "CO": ("prompt_vuln.txt", None),
    "CC": ("prompt_vuln_callees.txt", "callees"),
    "CK": ("prompt_vuln_callers.txt", "callers"),
}
SEED = 795
N_SPOTCHECK = 30


def _load_raw():
    records = {}
    for path in RAW_CVES.glob("*.json"):
        row = json.loads(path.read_text(encoding="utf-8"))
        records[row.get("cve_id", path.stem)] = row
    return records


def _function_rows(record):
    for file_entry in record.get("files", []):
        for function in file_entry.get("vulnerable_functions", []):
            vuln = (function.get("vulnerable_code") or "").strip()
            fixed = (function.get("fixed_code") or "").strip()
            if vuln:
                yield function, vuln, fixed


def _changed_functions(record):
    return [
        (function, vuln, fixed)
        for function, vuln, fixed in _function_rows(record)
        if function.get("fixed_code_found") and fixed and vuln != fixed
    ]


def _after_context(record, key):
    blocks = []
    for function, _, _ in _function_rows(record):
        for neighbor in (function.get("after") or {}).get(key, []):
            code = (neighbor.get("code") or "").strip()
            if code:
                blocks.append(code)
    return blocks


def _extract_heading(prompt, context):
    """Find actual context heading spelling, including any punctuation."""
    candidates = (
        ("### Callees", "### Callers") if context == "CC" else
        ("### Callers", "### Callees")
    )
    positions = [(prompt.find(candidate), candidate) for candidate in candidates]
    positions = [(pos, name) for pos, name in positions if pos >= 0]
    if not positions:
        raise ValueError(f"No context heading found for {context}")
    pos, _ = min(positions)
    line_end = prompt.find("\n", pos)
    return prompt[pos:line_end].strip()


def _render_fixed_from_source(source_prompt, context, target_blocks, context_blocks):
    marker = "### Function under review ###"
    head, sep, body = source_prompt.partition(marker)
    if not sep:
        raise ValueError("Prompt has no function-under-review marker")
    if context == "CO":
        return head + marker + "\n\n" + "\n###\n".join(target_blocks)
    heading = _extract_heading(source_prompt, context)
    if heading not in body:
        raise ValueError(f"Context heading missing from {context} prompt")
    target_text = "\n###\n".join(target_blocks)
    context_text = "\n###\n".join(context_blocks)
    # These strings mirror the separators in the authors' generated prompts.
    return head + marker + "\n\n" + target_text + "\n\n" + heading + "\n\n" + context_text


def build():
    if not RAW_CVES.exists() or not PROMPTS_DIR.exists():
        raise SystemExit("Run `python -m repro.setup_data` first.")
    records = _load_raw()
    PAIRED_PROMPTS.mkdir(parents=True, exist_ok=True)
    rows = []
    pair_reviews = []
    context_counts = {lang: {ctx: 0 for ctx in CONTEXTS} for lang in LANGUAGES.values()}

    for folder, language in LANGUAGES.items():
        lang_dir = PROMPTS_DIR / folder
        for prompt_dir in sorted(p for p in lang_dir.iterdir() if p.is_dir()):
            cve = prompt_dir.name
            source_co = prompt_dir / "prompt_vuln.txt"
            record = records.get(cve)
            if not source_co.exists() or record is None:
                continue
            changed = _changed_functions(record)
            if not changed:
                continue

            # Keep all target functions in the CVE-level prompt. Functions with
            # recovered fixed code use it; unrecovered functions retain their
            # vulnerable code and are recorded in the manifest.
            target_vuln = [v for _, v, _ in _function_rows(record)]
            target_fixed = [
                fixed if function.get("fixed_code_found") and fixed else vuln
                for function, vuln, fixed in _function_rows(record)
            ]
            out_dir = PAIRED_PROMPTS / folder / cve
            out_dir.mkdir(parents=True, exist_ok=True)
            available = []
            for context, (filename, graph_key) in CONTEXTS.items():
                source = prompt_dir / filename
                if not source.exists():
                    continue
                source_text = source.read_text(encoding="utf-8").strip()
                ctx_blocks = _after_context(record, graph_key) if graph_key else []
                fixed_text = _render_fixed_from_source(source_text, context, target_fixed, ctx_blocks)
                (out_dir / f"{context}_vulnerable.txt").write_text(source_text + "\n", encoding="utf-8")
                (out_dir / f"{context}_fixed.txt").write_text(fixed_text + "\n", encoding="utf-8")
                available.append(context)
                context_counts[language][context] += 1

            if not available:
                continue
            changed_names = [f.get("name") or "unnamed_function" for f, _, _ in changed]
            rows.append({
                "cve": cve,
                "language": language,
                "changed_function_count": len(changed),
                "target_function_count": len(target_vuln),
                "fixed_contexts_available": ",".join(available),
                "changed_functions": " | ".join(changed_names),
                "fixed_code_missing_count": sum(
                    1 for f, _, _ in _function_rows(record) if not f.get("fixed_code_found")
                ),
            })
            pair_reviews.append({
                "cve": cve,
                "language": language,
                "changed_function_count": len(changed),
                "changed_functions": " | ".join(changed_names),
                "vulnerable_code": "\n\n### FUNCTION PAIR ###\n\n".join(v for _, v, _ in changed),
                "fixed_code": "\n\n### FUNCTION PAIR ###\n\n".join(f for _, _, f in changed),
                "review_status": "unreviewed",
                "reviewer_notes": "",
            })

    RESULTS_DIR.mkdir(exist_ok=True)
    rows.sort(key=lambda row: (row["language"], row["cve"]))
    review_sample = random.Random(SEED).sample(pair_reviews, min(N_SPOTCHECK, len(pair_reviews)))
    with (RESULTS_DIR / "pair_manifest.csv").open("w", newline="", encoding="utf-8-sig") as f:
        writer = csv.DictWriter(f, fieldnames=list(rows[0]) if rows else [])
        writer.writeheader()
        writer.writerows(rows)
    with (RESULTS_DIR / "pair_spotcheck_30.csv").open("w", newline="", encoding="utf-8-sig") as f:
        writer = csv.DictWriter(f, fieldnames=list(review_sample[0]) if review_sample else [])
        writer.writeheader()
        writer.writerows(review_sample)

    summary = {
        "source_commit": "46796d168daf865331b1ca15d763d2e6746bf5a5",
        "seed": SEED,
        "cve_pairs": len(rows),
        "changed_function_pairs": sum(row["changed_function_count"] for row in rows),
        "pairs_by_language": {
            lang: sum(row["language"] == lang for row in rows)
            for lang in LANGUAGES.values()
        },
        "context_availability_by_language": context_counts,
        "function_spotcheck_rows": len(review_sample),
        "function_spotcheck_status": "unreviewed",
        "prompt_directory": "third_party/sw-vuln/data/paired_prompts",
        "note": "Counts are computed from changed vulnerable_functions in the pinned raw_cves files.",
    }
    (RESULTS_DIR / "pair_dataset_summary.json").write_text(
        json.dumps(summary, indent=2), encoding="utf-8"
    )
    print(json.dumps(summary, indent=2))
    return summary


if __name__ == "__main__":
    build()
