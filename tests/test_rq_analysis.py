import math

from repro import rq_analysis as A


def item(prediction, text="", sha="h"):
    return {"prediction": prediction, "text": text, "calls": 1, "cost_usd": 0.0, "prompt_sha256": sha}


def test_unparsed_counts_as_wrong_on_both_sides():
    preds = {
        "CVE-2016-1|CO|vulnerable": item(1), "CVE-2016-1|CO|fixed": item(0),      # P-C
        "CVE-2016-2|CO|vulnerable": item(None), "CVE-2016-2|CO|fixed": item(0),   # miss -> P-B
        "CVE-2016-3|CO|vulnerable": item(1), "CVE-2016-3|CO|fixed": item(None),   # alert -> P-V
        "CVE-2016-4|CO|vulnerable": item(0), "CVE-2016-4|CO|fixed": item(1),      # P-R
    }
    rows = A.pair_rows(preds, "M")
    assert [r["category"] for r in rows] == ["P-C", "P-B", "P-V", "P-R"]
    assert [r["parsed"] for r in rows] == [True, False, False, True]
    m = A.point(rows)
    assert (m["TP"], m["FN"], m["FP"], m["TN"]) == (2, 2, 2, 2)
    assert m["recall"] == 0.5 and m["fpr"] == 0.5 and m["precision"] == 0.5 and m["MCC"] == 0.0


def test_vulnerable_only_f1_matches_paper_formula():
    rows = [{"v": 1, "f": 1, "category": "P-V"}] * 3 + [{"v": 0, "f": 1, "category": "P-R"}]
    m = A.point(rows)
    recall = 0.75
    assert math.isclose(m["F1_vulnerable_only"], 2 * recall / (1 + recall))


def test_mcc_perfect_and_inverse():
    assert A.mcc(5, 0, 0, 5) == 1.0 and A.mcc(0, 5, 5, 0) == -1.0 and A.mcc(5, 0, 5, 0) == 0.0


def test_bootstrap_ci_brackets_point_estimate():
    rows = [{"v": i % 3 != 0, "f": i % 2 == 0, "category": "P-C"} for i in range(60)]
    for r in rows:
        r["v"], r["f"] = int(r["v"]), int(r["f"])
        r["category"] = {(1, 0): "P-C", (1, 1): "P-V", (0, 0): "P-B", (0, 1): "P-R"}[r["v"], r["f"]]
    ci = A.bootstrap_ci(rows, reps=500)
    p = A.point(rows)
    for k in ("recall", "fpr"):
        assert ci[f"{k}_lo"] <= p[k] <= ci[f"{k}_hi"]


def test_load_multi_prefers_first_parsed_attempt(tmp_path):
    import json
    path = tmp_path / "r.jsonl"
    lines = [
        {"key": "C|CO|fixed", "attempt": 1, "prediction": None, "text": "cut off", "cost_usd": 0.01, "prompt_sha256": "h"},
        {"key": "C|CO|fixed", "attempt": 2, "prediction": 0, "text": "CLASSIFICATION: 0", "cost_usd": 0.01, "prompt_sha256": "h"},
        {"key": "C|CO|vulnerable", "attempt": 1, "prediction": None, "text": "", "cost_usd": 0.01, "prompt_sha256": "h"},
    ]
    path.write_text("\n".join(json.dumps(l) for l in lines) + "\n")
    out = A.load_multi(path)
    assert out["C|CO|fixed"]["prediction"] == 0 and out["C|CO|fixed"]["calls"] == 2
    assert "C|CO|vulnerable" not in out   # one unparsed attempt and no retry yet: incomplete
