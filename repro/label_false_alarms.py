"""Label every code-only false alarm by what the model's explanation points at.

A false alarm is a "vulnerable" answer on the fixed version of a CVE. For each one
we take the code the model quotes (inline `backticks` and fenced code blocks, in
the explanation before the CLASSIFICATION line) and match it against the fixed
functions shown in the prompt:

* blames the fix    - the quotes hit lines the patch added or changed at least as
                      often as other lines;
* blames other code - the quotes mostly hit unchanged lines;
* no code cited     - nothing quoted matches the shown code.

The rule was fixed before looking at agreement with the 24 hand labels; two
variants are reported as sensitivity. Run after the paired prompts exist:

    python -m repro.label_false_alarms --responses <multi_eval dir> [--labels results/final/false_alarm_labels.csv]
"""
import argparse
import csv
import json
import re
from collections import Counter
from pathlib import Path

from .pairs import _function_rows, _load_raw
from .paths import RESULTS_DIR

MODELS = {"claude-haiku-4-5-20251001": "Claude Haiku 4.5", "gemini-3-flash-preview": "Gemini 3 Flash",
          "gpt-5-mini": "GPT-5 Mini"}
HAND = {"patched_code_fix_insufficient": "blames the fix", "specific_other_code": "blames other code",
        "generic_speculative": "no code cited"}
CATEGORIES = ["blames the fix", "blames other code", "no code cited"]


def norm(text):
    return re.sub(r"\s+", " ", text).strip()


def code_lines(code):
    out = []
    for line in code.splitlines():
        n = norm(line)
        if len(n) >= 4 and not n.startswith(("//", "/*", "*")) and n not in {"} else {", "else {", "break;", "return;"}:
            out.append(n)
    return out


IDENT = re.compile(r"[A-Za-z_][A-Za-z0-9_]*")


def target_lines(record):
    """(lines the patch added or changed, other lines) of the fixed functions in the prompt."""
    fixed_all, vuln_all = [], set()
    for fn, vuln, fixed in _function_rows(record):
        shown = fixed if fn.get("fixed_code_found") and fixed else vuln
        fixed_all += code_lines(shown)
        vuln_all |= set(code_lines(vuln))
    patched = sorted({l for l in fixed_all if l not in vuln_all})
    other = sorted({l for l in fixed_all if l in vuln_all})
    return patched, other


def quotes(text):
    body = re.split(r"CLASSIFICATION\s*:", text or "", flags=re.I)[0]
    found = []
    for block in re.findall(r"```[^\n]*\n(.*?)```", body, flags=re.S):
        found += [norm(l) for l in block.splitlines()]
    body = re.sub(r"```.*?```", " ", body, flags=re.S)
    found += [norm(q) for q in re.findall(r"`([^`\n]{2,200})`", body)]
    return [q for q in found if len(q) >= 3]


def classify(text, patched, other):
    """Count quotes that hit patched lines, other lines, or nothing."""
    patched_idents = {i for l in patched for i in IDENT.findall(l)} - {i for l in other for i in IDENT.findall(l)}
    hits = []
    for q in quotes(text):
        is_ident = bool(IDENT.fullmatch(q))
        if is_ident:
            if q in patched_idents and len(q) >= 3:
                hits.append("fix")
            continue
        if len(q) < 6:
            continue
        in_fix = any(q in l or (len(l) >= 8 and l in q) for l in patched)
        in_other = any(q in l or (len(l) >= 8 and l in q) for l in other)
        if in_fix:
            hits.append("fix")
        elif in_other:
            hits.append("other")
    if not hits:
        # Fallback for answers that paste code without backticks: shown lines quoted verbatim.
        body = norm(re.split(r"CLASSIFICATION\s*:", text or "", flags=re.I)[0])
        hits = ["fix" for l in patched if len(l) >= 15 and l in body] + ["other" for l in other if len(l) >= 15 and l in body]
    n_fix, n_other = hits.count("fix"), hits.count("other")
    if not hits:
        main = "no code cited"
    elif n_fix >= n_other:
        main = "blames the fix"
    else:
        main = "blames other code"
    any_fix = "no code cited" if not hits else ("blames the fix" if n_fix else "blames other code")
    first = "no code cited" if not hits else ("blames the fix" if hits[0] == "fix" else "blames other code")
    return {"label": main, "label_any_fix": any_fix, "label_first_quote": first, "fix_quotes": n_fix,
            "other_quotes": n_other}


def load(path):
    attempts = {}
    for line in Path(path).read_text(encoding="utf-8").splitlines():
        if line.strip():
            try:
                r = json.loads(line)
            except json.JSONDecodeError:
                continue
            attempts.setdefault(r["key"], []).append(r)
    out = {}
    for key, items in attempts.items():
        items.sort(key=lambda a: a["attempt"])
        parsed = [a for a in items if a["prediction"] is not None]
        if parsed:
            out[key] = parsed[0]
    return out


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--responses", type=Path, required=True, help="multi_eval checkpoint dir (one folder per model)")
    ap.add_argument("--labels", type=Path, default=RESULTS_DIR / "final" / "false_alarm_labels.csv")
    ap.add_argument("--out", type=Path, default=RESULTS_DIR / "final")
    args = ap.parse_args()
    records = _load_raw()
    targets = {}
    rows = []
    for model_id, name in MODELS.items():
        answers = load(args.responses / model_id / "responses.jsonl")
        for key, a in answers.items():
            cve, context, version = key.split("|")
            if context != "CO" or version != "fixed" or a["prediction"] != 1:
                continue
            if cve not in targets:
                targets[cve] = target_lines(records[cve])
            vuln = answers.get(f"{cve}|CO|vulnerable", {}).get("prediction")
            rows.append({"model": name, "cve": cve, "vulnerable_flagged": vuln == 1,
                         **classify(a.get("text", ""), *targets[cve])})
    rows.sort(key=lambda r: (r["model"], r["cve"]))
    args.out.mkdir(parents=True, exist_ok=True)
    with (args.out / "false_alarm_auto_labels.csv").open("w", newline="", encoding="utf-8") as fh:
        w = csv.DictWriter(fh, fieldnames=list(rows[0]), lineterminator="\n")
        w.writeheader()
        w.writerows(rows)

    summary = []
    for name in MODELS.values():
        mine = [r for r in rows if r["model"] == name]
        for rule in ("label", "label_any_fix", "label_first_quote"):
            c = Counter(r[rule] for r in mine)
            summary.append({"model": name, "rule": rule, "false_alarms": len(mine),
                            **{k: c.get(k, 0) for k in CATEGORIES},
                            **{f"{k} %": round(100 * c.get(k, 0) / len(mine), 1) for k in CATEGORIES}})
    with (args.out / "false_alarm_auto_summary.csv").open("w", newline="", encoding="utf-8") as fh:
        w = csv.DictWriter(fh, fieldnames=list(summary[0]), lineterminator="\n")
        w.writeheader()
        w.writerows(summary)

    agreement = {}
    if args.labels.exists():
        hand = list(csv.DictReader(args.labels.open(encoding="utf-8")))
        index = {(r["model"], r["cve"]): r for r in rows}
        for rule in ("label", "label_any_fix", "label_first_quote"):
            pairs = [(HAND[h["label"]], index[(h["model"], h["cve"])][rule]) for h in hand
                     if (h["model"], h["cve"]) in index]
            agreement[rule] = {"n": len(pairs), "agree": sum(a == b for a, b in pairs),
                               "disagreements": [f"{h['model']}|{h['cve']}: hand={HAND[h['label']]} auto={index[(h['model'], h['cve'])][rule]}"
                                                 for h in hand if (h["model"], h["cve"]) in index
                                                 and HAND[h["label"]] != index[(h["model"], h["cve"])][rule]]}
    (args.out / "false_alarm_auto_agreement.json").write_text(json.dumps(agreement, indent=2), encoding="utf-8")
    for s in summary:
        if s["rule"] == "label":
            print(s)
    print(json.dumps({k: {"n": v["n"], "agree": v["agree"]} for k, v in agreement.items()}))


if __name__ == "__main__":
    main()
