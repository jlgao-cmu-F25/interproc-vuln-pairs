import json

import pytest

from repro import live_rerun, metrics
from repro.paths import SHIPPED_OUTPUTS

needs_data = pytest.mark.skipif(not SHIPPED_OUTPUTS.exists(), reason="run `python -m repro.setup_data` first")


def test_accuracy_drops_none_and_f1_follows_recall():
    a = metrics.accuracy([1, 1, 0, None, 1])
    assert (a.n, a.tp) == (4, 3)
    assert a.accuracy == 0.75
    assert a.f1 == pytest.approx(2 * 0.75 / 1.75)


def test_mcnemar_matches_hand_computation():
    pairs = [(1, 1)] * 10 + [(1, 0)] * 6 + [(0, 1)] * 1 + [(0, 0)] * 3
    t = metrics.mcnemar(pairs)
    assert (t.n, t.a, t.b, t.c, t.d) == (20, 10, 6, 1, 3)
    assert t.chi2 == pytest.approx((5 - 1) ** 2 / 7)
    assert t.phi == pytest.approx(5 / (7 * 20) ** 0.5)
    assert t.acc1 == 0.8 and t.acc2 == 0.55


def test_holm_thresholds():
    ts = [metrics.mcnemar([(1, 1)]) for _ in range(3)]
    for t, p in zip(ts, [0.04, 0.01, 0.03]):
        t.p = p
    metrics.holm(ts)
    assert [round(t.alpha, 4) for t in ts] == [0.05, round(0.05 / 3, 4), 0.025]
    assert [t.sig for t in ts] == [True, True, False]


def test_parse_response_uses_authors_format():
    r = live_rerun.parse_response("EXPLANATION: overflow in foo\nCLASSIFICATION: 1")
    assert r == {"explanation": "overflow in foo", "classification": 1}
    assert live_rerun.parse_response("I think it's fine")["classification"] is None


@needs_data
def test_tables_4_to_7_match_paper():
    from repro.tables import run
    results, mismatches = run(write=False)
    assert mismatches.empty, mismatches.to_string()
    assert all(df.match.all() for name, df in results.items() if "match" in df)


@needs_data
def test_live_report_on_fake_answers(tmp_path, monkeypatch):
    monkeypatch.setattr(live_rerun, "RESULTS_DIR", tmp_path)
    monkeypatch.setattr(live_rerun, "CACHE", tmp_path / "raw.json")
    monkeypatch.setattr(live_rerun, "SUMMARY", tmp_path / "summary.json")
    monkeypatch.setattr(live_rerun, "PER_CVE", tmp_path / "per_cve.csv")
    cves = live_rerun.sample_cves()
    assert len(cves) == 50 and cves == live_rerun.sample_cves()
    shipped = live_rerun.load_outputs(live_rerun.SHIPPED_MODEL)
    fake = {c: dict(label=shipped[c]["CO"], cost_usd=0.001,
                    attempts=[dict(text=f"EXPLANATION: x\nCLASSIFICATION: {shipped[c]['CO']}",
                                   prompt_tokens=1000, completion_tokens=100, model="gpt-4.1-mini")])
            for c in cves}
    live_rerun.CACHE.write_text(json.dumps(fake))
    s = live_rerun.report(cves)
    assert s["label_agreement"] == 1.0 and s["delta"] == 0.0 and s["n"] == 50
