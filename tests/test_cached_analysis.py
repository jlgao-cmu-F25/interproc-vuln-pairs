"""Offline-only analysis checks; these tests cannot call a model API."""
import json
import math
from pathlib import Path

import pytest
from scipy import stats

from repro import cached_analysis as A


def test_exact_mcnemar_matches_scipy():
    for b, c in ((0, 0), (1, 0), (20, 4), (35, 35)):
        first = [True] * b + [False] * c + [True] * 3
        second = [False] * b + [True] * c + [True] * 3
        actual = A.exact_mcnemar(first, second)
        expected = stats.binomtest(b, b + c, .5).pvalue if b + c else 1.0
        assert math.isclose(actual["p_exact"], expected, abs_tol=1e-14)


def test_holm_is_monotone_step_down():
    rows = A.holm_adjust([{"p_exact": x} for x in (.02, .03, .04)])
    assert [x["p_holm"] for x in rows] == [.06, .06, .06]
    assert not any(x["significant_005"] for x in rows)


def test_pair_metrics_and_missing_version_fail_closed():
    rows = [{"cve": str(i), "context": ctx, "vulnerable_prediction": v,
             "fixed_prediction": f, "pair_category": category}
            for ctx in A.CONTEXTS
            for i, (v, f, category) in enumerate(((1, 0, "P-C"), (1, 1, "P-V"),
                                                 (0, 0, "P-B"), (0, 1, "P-R")))]
    for metric in A.context_metrics(rows):
        assert metric["pairs"] == 4 and metric["TP"] == metric["TN"] == 2
        assert metric["fpr"] == metric["F1_balanced"] == .5
        assert metric["pair_correct_rate"] == .25
    incomplete = {"CVE-1|CO|vulnerable": {"cve": "CVE-1", "context": "CO", "version": "vulnerable",
                                          "truth": 1, "prediction": 1, "complete": True}}
    with pytest.raises(AssertionError):
        A.pair_records(incomplete)


def test_final_recorded_metrics_independently_match():
    path = Path(__file__).resolve().parents[1] / ".colab" / "final"
    if not path.exists():
        pytest.skip("Private frozen result downloads are not present")
    cache = json.loads((path / "paired_eval_raw.json").read_text(encoding="utf-8"))
    summary = json.loads((path / "paired_eval_summary.json").read_text(encoding="utf-8"))
    ledger = json.loads((path / "paired_eval_requests.json").read_text(encoding="utf-8"))
    result = A.audit(cache, summary, ledger, list(cache))
    assert result["rows"] == 1436 and result["pilot_400_token_final_rows"] == 24
    assert math.isclose(result["cost_with_25pct_margin_usd"], 4.789768)
    expected = {"CO": (225, 118, 191, 152), "CC": (101, 95, 89, 107), "CK": (105, 74, 81, 98)}
    for row in A.context_metrics(A.pair_records(cache)):
        assert tuple(row[x] for x in ("TP", "FN", "FP", "TN")) == expected[row["context"]]
