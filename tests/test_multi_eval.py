import json

import pytest

from repro import multi_eval as M


ROWS = [
    {"cve": f"CVE-0-{i}", "context": "CO", "version": v, "truth": int(v == "vulnerable"),
     "prompt": f"p{i}{v}", "prompt_sha256": f"h{i}{v}"}
    for i in range(3) for v in ("vulnerable", "fixed")
]


class FakeError(Exception):
    status_code = 503


class FakeProvider:
    def __init__(self, answers):
        self.answers = answers
        self.calls = []

    def call(self, prompt):
        self.calls.append(prompt)
        answer = self.answers[prompt].pop(0)
        if isinstance(answer, Exception):
            raise answer
        return {"text": answer, "input_tokens": 1000, "output_tokens": 100, "reasoning_tokens": None,
                "finish_reason": "stop", "served_model": "fake"}


@pytest.fixture
def run(tmp_path, monkeypatch):
    monkeypatch.setattr(M, "CHECKPOINT_ROOT", tmp_path)
    monkeypatch.setattr(M, "retry_after", lambda exc, attempt: 0)
    return lambda answers, budget=10.0: (M.ModelRun("gpt-5-mini", ROWS, workers=2, budget=budget, log=lambda m: None),
                                         FakeProvider(answers))


def drive(model_run, provider):
    for row in ROWS:
        model_run.evaluate(provider, row)


def test_parse_retry_transient_and_resume(run):
    answers = {r["prompt"]: ["CLASSIFICATION: 1"] for r in ROWS}
    answers["p0fixed"] = ["no label", "still none"]            # unparsed twice -> stays None, 2 calls
    answers["p1fixed"] = ["no label", "CLASSIFICATION: 0"]     # retry succeeds
    answers["p2fixed"] = [FakeError("busy"), "CLASSIFICATION: 0"]  # transient, not a protocol attempt
    model_run, provider = run(answers)
    drive(model_run, provider)
    assert len(provider.calls) == 9
    status = model_run.status()
    assert status["complete"] == 6 and status["unparsed_after_retry"] == 1 and status["calls"] == 8
    resumed, provider2 = run({})
    drive(resumed, provider2)                                    # nothing left to do
    assert provider2.calls == [] and resumed.status() == status
    lines = [json.loads(l) for l in resumed.path.read_text().splitlines()]
    assert [l["prediction"] for l in lines if l["key"] == "CVE-0-1|CO|fixed"] == [None, 0]


def test_budget_stop_sends_nothing_over_cap(run):
    answers = {r["prompt"]: ["CLASSIFICATION: 1"] for r in ROWS}
    model_run, provider = run(answers, budget=0.0)
    assert model_run.evaluate(provider, ROWS[0]) == "budget"
    assert provider.calls == []


def test_parse_rule_matches_milestone_runner():
    from repro.paired_eval import parse_response
    for text in ("CLASSIFICATION: 1", "classification:0 then CLASSIFICATION: 1", "", None, "CLASSIFICATION: 2"):
        assert M.parse_response(text) == parse_response(text)


def test_prompt_verification_rejects_any_difference():
    expected = {M.item_key(r): r["prompt_sha256"] for r in ROWS}
    assert M.verify_prompts(ROWS, expected) == 6
    expected["CVE-0-0|CO|fixed"] = "other"
    with pytest.raises(SystemExit):
        M.verify_prompts(ROWS, expected)
