"""RQ1, RQ2 and the false-alarm analysis for all four models (C subset).

Offline only: reads saved responses, makes no API calls.

    python -m repro.rq_analysis --gpt41 <paired_eval_raw.json> --multi <multi_eval dir> --out results/final

Unit of analysis: one CVE x context pair (vulnerable prompt + fixed prompt).
Primary rule (from the proposal): an answer that is still unparsed after one
retry is wrong, i.e. a missed vulnerability or an alert on the fixed version.
Every table is also reported on complete cases (both sides parsed).
"""
import argparse
import csv
import difflib
import json
import math
from pathlib import Path
import random
import re

from . import paper_values as P
from .cached_analysis import exact_mcnemar, holm_adjust
from .pairs import PAIRED_PROMPTS

CONTEXTS = ("CO", "CC", "CK")
COMPARISONS = (("CO", "CC"), ("CO", "CK"), ("CC", "CK"))
MODEL_ORDER = ("Claude Haiku 4.5", "Gemini 3 Flash", "GPT-5 Mini", "GPT-4.1 Mini")
MULTI_LABELS = {"gpt-5-mini": "GPT-5 Mini", "claude-haiku-4-5-20251001": "Claude Haiku 4.5",
                "gemini-3-flash-preview": "Gemini 3 Flash"}
BOOTSTRAP = 2000
SEED = 795


# --------------------------------------------------------------------------- loading

def load_gpt41(path):
    cache = json.loads(Path(path).read_text(encoding="utf-8"))
    out = {}
    for key, item in cache.items():
        attempts = [a for a in item["attempts"] if not a.get("superseded_by_output_limit")]
        chosen = next((a for a in attempts if parse(a.get("text")) is not None), attempts[-1] if attempts else {})
        out[key] = {"prediction": item["prediction"], "text": chosen.get("text", ""),
                    "calls": len(item["attempts"]), "cost_usd": sum(a.get("cost_usd", 0) for a in item["attempts"]) / 1.25,
                    "prompt_sha256": item.get("prompt_sha256")}
    return out


def load_multi(path):
    attempts = {}
    for line in Path(path).read_text(encoding="utf-8").splitlines():
        if line.strip():
            try:
                record = json.loads(line)
            except json.JSONDecodeError:
                continue
            attempts.setdefault(record["key"], []).append(record)
    out = {}
    for key, items in attempts.items():
        items.sort(key=lambda a: a["attempt"])
        parsed = [a for a in items if a["prediction"] is not None]
        chosen = parsed[0] if parsed else items[-1]
        complete = bool(parsed) or len(items) >= 2
        if complete:
            out[key] = {"prediction": chosen["prediction"], "text": chosen.get("text", ""), "calls": len(items),
                        "cost_usd": sum(a["cost_usd"] for a in items), "prompt_sha256": chosen["prompt_sha256"],
                        "finish_reason": chosen.get("finish_reason"), "served_model": chosen.get("served_model")}
    return out


def parse(text):
    match = re.search(r"CLASSIFICATION:\s*([01])", text or "", re.IGNORECASE)
    return int(match.group(1)) if match else None


def pair_rows(predictions, model):
    grouped = {}
    for key, item in predictions.items():
        cve, context, version = key.split("|")
        grouped.setdefault((cve, context), {})[version] = item
    rows = []
    for (cve, context), sides in sorted(grouped.items()):
        if set(sides) != {"vulnerable", "fixed"}:
            continue
        v, f = sides["vulnerable"]["prediction"], sides["fixed"]["prediction"]
        v_eff = 1 if v == 1 else 0          # unparsed vulnerable -> missed
        f_eff = 0 if f == 0 else 1          # unparsed fixed -> counted as an alert (wrong)
        rows.append({"model": model, "cve": cve, "year": int(cve.split("-")[1]), "context": context,
                     "v_raw": v, "f_raw": f, "v": v_eff, "f": f_eff, "parsed": v is not None and f is not None,
                     "category": {(1, 0): "P-C", (1, 1): "P-V", (0, 0): "P-B", (0, 1): "P-R"}[v_eff, f_eff],
                     "v_text": sides["vulnerable"]["text"], "f_text": sides["fixed"]["text"]})
    return rows


def misaligned_cves():
    """C CVEs where a 'fixed' function has a different name from its vulnerable one.

    Covers real renames in the fix and pairs that ReposVul misaligned (for
    example bson_malloc -> bson_free); both are excluded in the sensitivity rows.
    """
    from .pairs import _load_raw, _changed_functions
    records = _load_raw()
    flagged = set()
    for cve, record in records.items():
        for _, vuln, fixed in _changed_functions(record):
            nv, nf = _function_name(vuln), _function_name(fixed)
            if nv and nf and nv != nf:
                flagged.add(cve)
    return flagged


def _function_name(code):
    names = re.findall(r"([A-Za-z_]\w*)\s*\(", code.split("{")[0])
    return names[-1] if names else None


# --------------------------------------------------------------------------- metrics

def mcc(tp, fn, fp, tn):
    denom = math.sqrt((tp + fp) * (tp + fn) * (tn + fp) * (tn + fn))
    return (tp * tn - fp * fn) / denom if denom else 0.0


def point(rows):
    n = len(rows)
    tp = sum(r["v"] for r in rows)
    fp = sum(r["f"] for r in rows)
    fn, tn = n - tp, n - fp
    cat = {c: sum(r["category"] == c for r in rows) for c in ("P-C", "P-V", "P-B", "P-R")}
    return {"pairs": n, "TP": tp, "FN": fn, "FP": fp, "TN": tn,
            "recall": tp / n if n else None,
            "precision": tp / (tp + fp) if tp + fp else None,
            "fpr": fp / n if n else None,
            "specificity": tn / n if n else None,
            "balanced_accuracy": (tp + tn) / (2 * n) if n else None,
            "F1_paired": 2 * tp / (2 * tp + fp + fn) if tp else 0.0,
            "MCC": mcc(tp, fn, fp, tn),
            "F1_vulnerable_only": 2 * tp / (n + tp) if n else None,
            **{f"{c}_rate": cat[c] / n if n else None for c in cat}, **cat}


CI_KEYS = ("recall", "precision", "fpr", "MCC", "P-C_rate", "P-V_rate")


def bootstrap_ci(rows, keys=CI_KEYS, reps=BOOTSTRAP, seed=SEED):
    rng = random.Random(seed)
    samples = {k: [] for k in keys}
    for _ in range(reps):
        draw = [rows[rng.randrange(len(rows))] for _ in rows]
        values = point(draw)
        for k in keys:
            if values[k] is not None:
                samples[k].append(values[k])
    out = {}
    for k, values in samples.items():
        values.sort()
        out[f"{k}_lo"] = values[int(0.025 * len(values))] if values else None
        out[f"{k}_hi"] = values[int(0.975 * len(values)) - 1] if values else None
    return out


def rq1(all_rows, exclude=frozenset()):
    table = []
    for model in MODEL_ORDER:
        for context in CONTEXTS:
            rows = [r for r in all_rows if r["model"] == model and r["context"] == context
                    and r["cve"] not in exclude]
            if not rows:
                continue
            complete = [r for r in rows if r["parsed"]]
            n_paper, _, recall_paper, f1_paper = P.TABLE6[(model, context)]
            entry = {"model": model, "context": context, "unparsed_pairs": len(rows) - len(complete),
                     "paper_C_N": n_paper, "paper_C_recall": recall_paper, "paper_C_F1": f1_paper,
                     **point(rows), **bootstrap_ci(rows)}
            cc = point(complete)
            entry.update({f"cc_{k}": cc[k] for k in ("pairs", "recall", "precision", "fpr", "MCC", "P-C_rate")})
            table.append(entry)
    return table


def paired_bootstrap_diff(a, b, reps=BOOTSTRAP, seed=SEED):
    rng = random.Random(seed)
    n = len(a)
    diffs = []
    for _ in range(reps):
        idx = [rng.randrange(n) for _ in range(n)]
        diffs.append(sum(a[i] - b[i] for i in idx) / n)
    diffs.sort()
    return diffs[int(0.025 * reps)], diffs[int(0.975 * reps) - 1]


RQ2_METRICS = {"fixed_alert": lambda r: r["f"] == 1,
               "vulnerable_recall": lambda r: r["v"] == 1,
               "pair_correct": lambda r: r["category"] == "P-C"}


def rq2(all_rows, complete_only=False, exclude=frozenset()):
    results = []
    for model in MODEL_ORDER:
        rows = [r for r in all_rows if r["model"] == model and (r["parsed"] or not complete_only)
                and r["cve"] not in exclude]
        lookup = {(r["cve"], r["context"]): r for r in rows}
        family = []
        for metric, fn in RQ2_METRICS.items():
            for c1, c2 in COMPARISONS:
                common = sorted({c for c, ctx in lookup if ctx == c1} & {c for c, ctx in lookup if ctx == c2})
                if not common:
                    continue
                x = [fn(lookup[c, c1]) for c in common]
                y = [fn(lookup[c, c2]) for c in common]
                lo, hi = paired_bootstrap_diff([int(v) for v in x], [int(v) for v in y])
                family.append({"model": model, "metric": metric, "comparison": f"{c1}-{c2}",
                               **exact_mcnemar(x, y), "diff": sum(x) / len(x) - sum(y) / len(y),
                               "diff_lo": lo, "diff_hi": hi})
        results.extend(holm_adjust(family))     # Holm within each model (9 tests)
    return results


# --------------------------------------------------------------------------- error analysis

IDENT = re.compile(r"[A-Za-z_][A-Za-z0-9_]{3,}")
STOP = set("this that with from function code have will when where which there their into than then "
           "check value pointer buffer data size length memory input user null return could would should "
           "because does here vulnerable vulnerability classification explanation potential issue".split())


def changed_identifiers(cve, context):
    folder = PAIRED_PROMPTS / "c" / cve
    vuln = (folder / f"{context}_vulnerable.txt").read_text(encoding="utf-8").splitlines()
    fixed = (folder / f"{context}_fixed.txt").read_text(encoding="utf-8").splitlines()
    removed, added = [], []
    for line in difflib.unified_diff(vuln, fixed, lineterm="", n=0):
        if line.startswith("-") and not line.startswith("---"):
            removed.append(line[1:])
        elif line.startswith("+") and not line.startswith("+++"):
            added.append(line[1:])
    unchanged = set(IDENT.findall("\n".join(fixed))) - set(IDENT.findall("\n".join(added)))
    diff_only = (set(IDENT.findall("\n".join(added + removed))) - unchanged) - STOP
    touched = set(IDENT.findall("\n".join(added + removed))) - STOP
    return {"removed": removed, "added": added, "diff_only": diff_only, "touched": touched}


def explanation_idents(text):
    return {t for t in IDENT.findall(text or "") if t.lower() not in STOP}


CWE = re.compile(r"CWE[-\s]?(\d+)", re.IGNORECASE)
CVE_ID = re.compile(r"CVE-\d{4}-\d{4,}", re.IGNORECASE)


def false_alarm_analysis(all_rows):
    """Heuristics over every fixed-version alert, plus a memorisation check."""
    per_alert, summary = [], []
    diff_cache = {}
    for r in all_rows:
        if r["f_raw"] != 1:
            continue
        key = (r["cve"], r["context"])
        if key not in diff_cache:
            diff_cache[key] = changed_identifiers(*key)
        d = diff_cache[key]
        f_ids, v_ids = explanation_idents(r["f_text"]), explanation_idents(r["v_text"])
        f_cwe, v_cwe = set(CWE.findall(r["f_text"] or "")), set(CWE.findall(r["v_text"] or ""))
        per_alert.append({
            "model": r["model"], "cve": r["cve"], "context": r["context"], "year": r["year"],
            "vulnerable_also_flagged": r["v_raw"] == 1,
            "mentions_changed_code": bool(f_ids & d["touched"]),
            "mentions_diff_only_identifier": bool(f_ids & d["diff_only"]),
            "same_cwe_as_vulnerable_answer": (bool(f_cwe & v_cwe) if r["v_raw"] == 1 and f_cwe and v_cwe else None),
            "identifier_jaccard_vs_vulnerable": (len(f_ids & v_ids) / len(f_ids | v_ids)) if (f_ids | v_ids) and r["v_raw"] == 1 else None,
            "cites_cve_id": bool(CVE_ID.search(r["f_text"] or "")),
            "diff_lines": len(d["added"]) + len(d["removed"]),
        })
    for model in MODEL_ORDER:
        alerts = [a for a in per_alert if a["model"] == model]
        if not alerts:
            continue
        both = [a for a in alerts if a["vulnerable_also_flagged"]]
        jac = sorted(a["identifier_jaccard_vs_vulnerable"] for a in both if a["identifier_jaccard_vs_vulnerable"] is not None)
        summary.append({
            "model": model, "fixed_alerts": len(alerts),
            "share_mentioning_changed_code": sum(a["mentions_changed_code"] for a in alerts) / len(alerts),
            "share_mentioning_diff_only_identifier": sum(a["mentions_diff_only_identifier"] for a in alerts) / len(alerts),
            "alerts_with_vulnerable_also_flagged": len(both),
            "answers_citing_cwe_in_both_versions": sum(a["same_cwe_as_vulnerable_answer"] is not None for a in both),
            "share_same_cwe_when_both_cite_one": _share([a["same_cwe_as_vulnerable_answer"] for a in both
                                                         if a["same_cwe_as_vulnerable_answer"] is not None]),
            "median_identifier_jaccard_vs_vulnerable": jac[len(jac) // 2] if jac else None,
        })
    return per_alert, summary


def _share(values):
    return sum(values) / len(values) if values else None


def year_bin(year):
    return "<=2015" if year <= 2015 else "2016-2018" if year <= 2018 else "2019-2021" if year <= 2021 else ">=2022"


def memorisation(all_rows):
    """P-V (both flagged) and P-C rate by CVE year, and explicit CVE-ID citations."""
    by_year, citations = [], []
    for model in MODEL_ORDER:
        rows = [r for r in all_rows if r["model"] == model and r["context"] == "CO"]
        for b in ("<=2015", "2016-2018", "2019-2021", ">=2022"):
            part = [r for r in rows if year_bin(r["year"]) == b]
            if part:
                by_year.append({"model": model, "context": "CO", "year_bin": b, "pairs": len(part),
                                "P-V_rate": sum(r["category"] == "P-V" for r in part) / len(part),
                                "P-C_rate": sum(r["category"] == "P-C" for r in part) / len(part),
                                "recall": sum(r["v"] for r in part) / len(part),
                                "fpr": sum(r["f"] for r in part) / len(part)})
        if rows:
            years = [r["year"] for r in rows]
            pv = [int(r["category"] == "P-V") for r in rows]
            trend = spearman(years, pv)
            by_year.append({"model": model, "context": "CO", "year_bin": "spearman(year, P-V)", "pairs": len(rows),
                            "P-V_rate": trend, "P-C_rate": None, "recall": None, "fpr": None})
        all_model = [r for r in all_rows if r["model"] == model]
        if not all_model:
            continue
        for side in ("v", "f"):
            texts = [(r["cve"], r[f"{side}_text"]) for r in all_model]
            cited = [(cve, CVE_ID.findall(t or "")) for cve, t in texts]
            cited = [(cve, ids) for cve, ids in cited if ids]
            citations.append({"model": model, "version": "vulnerable" if side == "v" else "fixed",
                              "answers": len(texts), "answers_citing_a_cve_id": len(cited),
                              "citing_the_correct_cve": sum(cve.upper() in {i.upper() for i in ids} for cve, ids in cited)})
    return by_year, citations


def spearman(x, y):
    def ranks(v):
        order = sorted(range(len(v)), key=lambda i: v[i])
        r = [0.0] * len(v)
        i = 0
        while i < len(v):
            j = i
            while j + 1 < len(v) and v[order[j + 1]] == v[order[i]]:
                j += 1
            for k in range(i, j + 1):
                r[order[k]] = (i + j) / 2 + 1
            i = j + 1
        return r
    rx, ry = ranks(x), ranks(y)
    mx, my = sum(rx) / len(rx), sum(ry) / len(ry)
    cov = sum((a - mx) * (b - my) for a, b in zip(rx, ry))
    sx = math.sqrt(sum((a - mx) ** 2 for a in rx))
    sy = math.sqrt(sum((b - my) ** 2 for b in ry))
    return cov / (sx * sy) if sx and sy else None


def sample_for_labelling(all_rows, per_model=8, seed=SEED):
    """Stratified sample of CO false alarms (both versions flagged) for manual labelling."""
    out = []
    for model in MODEL_ORDER:
        rng = random.Random(f"{seed}:{model}")   # per model, so adding a model never changes another's sample
        pool = [r for r in all_rows if r["model"] == model and r["context"] == "CO" and r["f_raw"] == 1]
        for r in rng.sample(pool, min(per_model, len(pool))):
            d = changed_identifiers(r["cve"], "CO")
            out.append({"model": model, "cve": r["cve"], "vulnerable_flagged": r["v_raw"] == 1,
                        "diff_removed": "\n".join(d["removed"])[:1500], "diff_added": "\n".join(d["added"])[:1500],
                        "fixed_explanation": (r["f_text"] or "")[:2500],
                        "vulnerable_explanation": (r["v_text"] or "")[:1200],
                        "label": "", "note": ""})
    return out


# --------------------------------------------------------------------------- driver

def write_csv(path, rows):
    if not rows:
        return
    fields = list(dict.fromkeys(k for r in rows for k in r))
    with Path(path).open("w", newline="", encoding="utf-8") as handle:
        writer = csv.DictWriter(handle, fieldnames=fields)
        writer.writeheader()
        writer.writerows(rows)


def main(argv=None):
    parser = argparse.ArgumentParser()
    parser.add_argument("--gpt41", type=Path, default=None,
                        help="GPT-4.1-mini paired_eval_raw.json; also the reference for prompt hashes")
    parser.add_argument("--multi", type=Path, required=True)
    parser.add_argument("--out", type=Path, default=Path("results/final"))
    args = parser.parse_args(argv)
    args.out.mkdir(parents=True, exist_ok=True)

    sources = {}
    if args.gpt41 and args.gpt41.exists():
        sources["GPT-4.1 Mini"] = load_gpt41(args.gpt41)
    for slug, label in MULTI_LABELS.items():
        path = args.multi / slug / "responses.jsonl"
        if path.exists():
            sources[label] = load_multi(path)
    if "GPT-4.1 Mini" in sources:
        reference = {k: v["prompt_sha256"] for k, v in sources["GPT-4.1 Mini"].items()}
    else:
        from .multi_eval import prompt_rows, item_key
        reference = {item_key(r): r["prompt_sha256"] for r in prompt_rows()}
        print("GPT-4.1-mini outputs not given: prompts checked against this machine's build only.")
    coverage = []
    all_rows = []
    for model, predictions in sources.items():
        mismatched = [k for k, v in predictions.items() if reference.get(k) != v["prompt_sha256"]]
        assert not mismatched, f"{model}: prompts differ from GPT-4.1-mini for {mismatched[:3]}"
        rows = pair_rows(predictions, model)
        all_rows.extend(rows)
        coverage.append({"model": model, "answered_prompts": len(predictions), "expected_prompts": len(reference),
                         "pairs": len(rows), "unparsed_answers": sum(v["prediction"] is None for v in predictions.values()),
                         "calls": sum(v["calls"] for v in predictions.values()),
                         "list_price_cost_usd": round(sum(v["cost_usd"] for v in predictions.values()), 4)})

    misaligned = misaligned_cves() & {r["cve"] for r in all_rows}
    table = rq1(all_rows)
    table_aligned = rq1(all_rows, exclude=misaligned)
    tests = rq2(all_rows)
    tests_cc = rq2(all_rows, complete_only=True)
    tests_aligned = rq2(all_rows, exclude=misaligned)
    per_alert, fa_summary = false_alarm_analysis(all_rows)
    by_year, citations = memorisation(all_rows)
    write_csv(args.out / "coverage.csv", coverage)
    write_csv(args.out / "rq1_paired_metrics.csv", table)
    write_csv(args.out / "rq2_context_tests.csv", tests)
    write_csv(args.out / "rq2_context_tests_complete_cases.csv", tests_cc)
    write_csv(args.out / "rq1_paired_metrics_aligned_only.csv", table_aligned)
    write_csv(args.out / "rq2_context_tests_aligned_only.csv", tests_aligned)
    write_csv(args.out / "misaligned_cves.csv", [{"cve": c} for c in sorted(misaligned)])
    write_csv(args.out / "false_alarms_per_alert.csv", per_alert)
    write_csv(args.out / "false_alarms_summary.csv", fa_summary)
    write_csv(args.out / "memorisation_by_year.csv", by_year)
    write_csv(args.out / "cve_id_citations.csv", citations)
    write_csv(args.out / "false_alarm_labelling_sample.csv", sample_for_labelling(all_rows))
    write_csv(args.out / "pair_predictions.csv",
              [{k: v for k, v in r.items() if k not in ("v_text", "f_text")} for r in all_rows])
    print(json.dumps({"coverage": coverage}, indent=2))


if __name__ == "__main__":
    main()
