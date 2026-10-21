"""Pure, offline calculations for the finished C experiment. No model clients/I/O.

The recording notebook bundles this source and frozen input data. It deliberately
does not import either paid runner, credentials, Drive control or networking.
"""
from collections import Counter
import math


CONTEXTS = ("CO", "CC", "CK")
COMPARISONS = (("CO", "CC"), ("CO", "CK"), ("CC", "CK"))


def divide(a, b):
    return a / b if b else None


def exact_mcnemar(first, second):
    """Two-sided conditional binomial McNemar; independent unit is one CVE."""
    assert len(first) == len(second) and first
    b = sum(bool(x) and not bool(y) for x, y in zip(first, second))
    c = sum(not bool(x) and bool(y) for x, y in zip(first, second))
    discordant = b + c
    p = min(1.0, 2 * sum(math.comb(discordant, i)
                        for i in range(min(b, c) + 1)) / 2 ** discordant) if discordant else 1.0
    return {"N": len(first), "first_only": b, "second_only": c, "p_exact": p,
            "first_rate": sum(first) / len(first), "second_rate": sum(second) / len(second)}


def holm_adjust(rows):
    """Proper step-down Holm adjusted p-values within this stated family."""
    running = 0.0
    for i, row in enumerate(sorted(rows, key=lambda x: x["p_exact"])):
        running = max(running, (len(rows) - i) * row["p_exact"])
        row["p_holm"] = min(1.0, running)
        row["significant_005"] = row["p_holm"] < 0.05
    return rows


def pair_records(cache):
    grouped = {}
    for key, item in cache.items():
        cve, context, version = key.split("|")
        assert key == f"{item['cve']}|{item['context']}|{item['version']}"
        assert context in CONTEXTS and version in ("vulnerable", "fixed")
        assert item["truth"] == (1 if version == "vulnerable" else 0)
        assert item["prediction"] in (0, 1) and item.get("complete", True)
        grouped.setdefault((cve, context), {})[version] = item["prediction"]
    rows = []
    for (cve, context), predictions in sorted(grouped.items()):
        assert set(predictions) == {"vulnerable", "fixed"}, (cve, context)
        v, f = predictions["vulnerable"], predictions["fixed"]
        category = {(1, 0): "P-C", (1, 1): "P-V", (0, 0): "P-B", (0, 1): "P-R"}[v, f]
        rows.append({"cve": cve, "context": context, "vulnerable_prediction": v,
                     "fixed_prediction": f, "pair_category": category})
    return rows


def context_metrics(pairs):
    rows = []
    for context in CONTEXTS:
        part = [x for x in pairs if x["context"] == context]
        n = len(part)
        tp = sum(x["vulnerable_prediction"] == 1 for x in part)
        fp = sum(x["fixed_prediction"] == 1 for x in part)
        tn, fn = n - fp, n - tp
        counts = Counter(x["pair_category"] for x in part)
        rows.append({"context": context, "pairs": n, "TP": tp, "FN": fn, "FP": fp, "TN": tn,
                     "recall": divide(tp, n), "precision": divide(tp, tp + fp),
                     "fpr": divide(fp, n), "F1_balanced": divide(2 * tp, 2 * tp + fp + fn),
                     "accuracy_balanced": divide(tp + tn, 2 * n),
                     "pair_correct_rate": divide(counts["P-C"], n),
                     **{label: counts[label] for label in ("P-C", "P-V", "P-B", "P-R")}})
    return rows


def paper_reproduction(paper):
    """Recalculate all 48 published rows from the authors' frozen predictions."""
    outputs, languages = paper["outputs"], paper["languages"]
    rows = []
    for expected in paper["accuracy_rows"]:
        labels = [record[expected["context"]]
                  for cve, record in outputs[expected["model"]].items()
                  if expected["language"] is None or languages.get(cve) == expected["language"]]
        labels = [x for x in labels if x is not None]
        n, tp = len(labels), sum(labels)
        recall = tp / n
        f1 = 2 * recall / (1 + recall)
        match = (n == expected["N"] and tp == expected["TP"]
                 and abs(recall - expected["accuracy"]) < 0.00005001
                 and abs(f1 - expected["F1"]) < 0.00005001)
        rows.append({"table": expected["table"], "model": expected["model"],
                     "context": expected["context"], "N": n, "TP": tp,
                     "accuracy_paper": expected["accuracy"], "accuracy_recomputed": recall,
                     "F1_paper": expected["F1"], "F1_recomputed": f1, "match": match})
    tests = []
    for expected in paper["mcnemar_rows"]:
        c1, c2 = expected["comparison"].split("-")
        part = [(x[c1], x[c2]) for x in outputs[expected["model"]].values()
                if x[c1] is not None and x[c2] is not None]
        n = len(part)
        b = sum(x == 1 and y == 0 for x, y in part)
        c = sum(x == 0 and y == 1 for x, y in part)
        chi2 = (abs(b - c) - 1) ** 2 / (b + c) if b + c else 0.0
        phi = (b - c) / math.sqrt((b + c) * n) if b + c else 0.0
        # Reproduce the published effect labels, not a new effect-size convention.
        tests.append({"expected": expected, "n": n, "chi2": chi2,
                      "p": math.erfc(math.sqrt(chi2 / 2)), "phi": phi,
                      "acc1": sum(x for x, y in part) / n, "acc2": sum(y for x, y in part) / n,
                      "effect": "Small" if abs(phi) < .1 else "Medium" if abs(phi) < .3 else "Large"})
    for rank, test in enumerate(sorted(tests, key=lambda x: x["p"])):
        test["alpha"] = .05 / (len(tests) - rank)
        test["sig"] = test["p"] < test["alpha"]
    for test in tests:
        expected = test["expected"]
        match = all(test[k] == expected[k] if k in ("n", "effect", "sig")
                    else abs(test[k] - expected[k]) <= (.00050001 if k in ("chi2", "phi") else .00005001)
                    for k in ("n", "chi2", "p", "alpha", "sig", "acc1", "acc2", "phi", "effect"))
        rows.append({"table": "Table 4", "model": expected["model"],
                     "context": expected["comparison"], "N": test["n"], "match": match})
    return rows


def matched_paper_comparison(pairs, paper):
    authors = paper["outputs"]["GPT-4.1 Mini"]
    rows, tests = [], []
    for context in CONTEXTS:
        part = [x for x in pairs if x["context"] == context]
        assert all(authors[x["cve"]][context] is not None for x in part)
        old = [authors[x["cve"]][context] for x in part]
        new = [x["vulnerable_prediction"] for x in part]
        published = next(x for x in paper["accuracy_rows"]
                         if x["table"] == "Table 6" and x["model"] == "GPT-4.1 Mini"
                         and x["context"] == context)
        rows.append({"context": context, "paper_C_N": published["N"],
                     "paper_C_recall": published["accuracy"], "matched_C_N": len(part),
                     "paper_matched_recall": sum(old) / len(old),
                     "ours_vulnerable_recall": sum(new) / len(new),
                     "delta_pp_matched": 100 * (sum(new) - sum(old)) / len(new),
                     "label_agreement": sum(x == y for x, y in zip(old, new)) / len(new)})
        tests.append({"comparison": f"shipped-vs-current {context}", **exact_mcnemar(old, new)})
    return rows, holm_adjust(tests)


def context_tests(pairs):
    lookup = {(x["cve"], x["context"]): x for x in pairs}
    results = []
    for metric in ("vulnerable_recall", "pair_correct"):
        family = []
        for c1, c2 in COMPARISONS:
            common = sorted({cve for cve, ctx in lookup if ctx == c1}
                            & {cve for cve, ctx in lookup if ctx == c2})
            def correct(cve, ctx):
                row = lookup[cve, ctx]
                return row["vulnerable_prediction"] == 1 if metric == "vulnerable_recall" else row["pair_category"] == "P-C"
            family.append({"metric": metric, "comparison": f"{c1}-{c2}",
                           **exact_mcnemar([correct(c, c1) for c in common], [correct(c, c2) for c in common])})
        results.extend(holm_adjust(family))
    return results


def audit(cache, summary, ledger, expected_keys):
    assert set(cache) == set(expected_keys), "Checkpoint missing/extra prompt IDs"
    pairs = pair_records(cache)
    attempts = [a for item in cache.values() for a in item["attempts"]]
    ids = [a["request_id"] for a in attempts]
    assert len(ids) == len(set(ids)), "Duplicate billed response IDs"
    assert all(x["requested_model"] == summary["model_requested"] for x in cache.values())
    pending = {k: v for k, v in ledger.items() if k not in set(ids)}
    cost = sum(a["cost_usd"] for a in attempts) + sum(x["cost_reserve_usd"] for x in pending.values())
    assert not pending and len(cache) == 1436
    assert abs(cost - summary["total_cost_usd"]) < .00005
    assert summary["calls"] == len(attempts)
    metrics = context_metrics(pairs)
    for row in metrics:
        old = summary["context_metrics"][row["context"]]
        for key in ("pairs", "precision", "recall", "fpr", "pair_correct_rate", "P-C", "P-V", "P-B", "P-R"):
            assert abs(row[key] - old[key]) < 1e-12, (row["context"], key)
    pilot_final = sum(item["attempts"][-1].get("max_output_tokens", 400) == 400 for item in cache.values())
    return {"rows": len(cache), "pairs_across_contexts": len(pairs), "unparsed": 0,
            "calls_including_history": len(attempts), "cost_with_25pct_margin_usd": cost,
            "reference_token_cost_before_margin_usd": cost / 1.25,
            "unresolved_requests": len(pending), "pilot_400_token_final_rows": pilot_final,
            "all_checks_passed": True}
