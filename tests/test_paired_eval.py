import json
import os
from pathlib import Path
import tempfile
import threading
import types
import unittest
from unittest.mock import Mock, patch

from repro import paired_eval


class PairedEvalCheckpointTests(unittest.TestCase):
    def test_atomic_checkpoint_round_trip(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            payload = {"pair": {"attempts": [], "prediction": 1}}
            with patch.object(paired_eval, "RESULTS_DIR", root), patch.object(
                paired_eval, "CACHE", root / "cache.json"
            ):
                paired_eval.save_cache(payload)
                self.assertEqual(paired_eval.load_cache(), payload)
                self.assertEqual(list(root.glob("*.tmp")), [])

    def test_resume_from_incomplete_pair_and_retry_connection_error(self):
        class TransientConnectionError(Exception):
            pass

        fake_openai = types.ModuleType("openai")
        for name in (
            "RateLimitError", "APIConnectionError", "APITimeoutError",
            "InternalServerError", "APIStatusError",
        ):
            setattr(fake_openai, name, TransientConnectionError)

        def response(text):
            return types.SimpleNamespace(
                output_text=text,
                usage=types.SimpleNamespace(input_tokens=50, output_tokens=20),
                model="gpt-4.1-mini-1",
            )

        client = types.SimpleNamespace(
            responses=types.SimpleNamespace(
                create=Mock(
                    side_effect=[
                        TransientConnectionError("temporary connection loss"),
                        response("No label"),
                        RuntimeError("simulated interruption"),
                        response("CLASSIFICATION: 1"),
                    ]
                )
            )
        )
        fake_openai.OpenAI = Mock(return_value=client)
        row = {
            "cve": "CVE-TEST-1", "context": "CO", "version": "vulnerable",
            "label": 1, "prompt": "short prompt for retry tests",
        }
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            with (
                patch.dict(os.environ, {
                    "OPENAI_API_KEY": "test-only",
                    "OPENAI_MAX_CONCURRENCY": "1",
                }),
                patch.dict("sys.modules", {"openai": fake_openai}),
                patch.object(paired_eval, "RESULTS_DIR", root),
                patch.object(paired_eval, "CACHE", root / "cache.json"),
                patch.object(paired_eval, "TPM_STATE", root / "tpm.json"),
                patch.object(paired_eval, "REQUEST_LEDGER", root / "requests.json"),
                patch.object(paired_eval, "STOP_FILE", root / "STOP"),
                patch.object(paired_eval.time, "sleep"),
                patch.object(paired_eval.random, "uniform", return_value=-1.5),
            ):
                with self.assertRaisesRegex(RuntimeError, "simulated interruption"):
                    paired_eval.run([row])
                saved = json.loads((root / "cache.json").read_text(encoding="utf-8"))
                self.assertFalse(saved["CVE-TEST-1|CO|vulnerable"]["complete"])
                self.assertEqual(len(saved["CVE-TEST-1|CO|vulnerable"]["attempts"]), 1)

                result = paired_eval.run([row])
                item = result["CVE-TEST-1|CO|vulnerable"]
                self.assertTrue(item["complete"])
                self.assertEqual(item["prediction"], 1)
                self.assertEqual(len(item["attempts"]), 2)
                self.assertEqual(client.responses.create.call_count, 4)

    def test_stop_preserves_in_flight_response_and_sends_no_next_request(self):
        stop = threading.Event()

        def finish_response(**kwargs):
            stop.set()
            return types.SimpleNamespace(
                output_text="CLASSIFICATION: 1", model="test",
                usage=types.SimpleNamespace(input_tokens=10, output_tokens=5),
            )

        create = Mock(side_effect=finish_response)
        fake_openai = types.SimpleNamespace(OpenAI=Mock(return_value=types.SimpleNamespace(
            responses=types.SimpleNamespace(create=create))))
        rows = [{"cve": f"TEST-{i}", "context": "CO", "version": "vulnerable",
                 "label": 1, "prompt": "test"} for i in range(8)]
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            with (
                patch.dict(os.environ, {"OPENAI_API_KEY": "test-only", "OPENAI_MAX_CONCURRENCY": "1"}),
                patch.dict("sys.modules", {"openai": fake_openai}),
                patch.object(paired_eval, "CACHE", root / "cache.json"),
                patch.object(paired_eval, "TPM_STATE", root / "tpm.json"),
                patch.object(paired_eval, "REQUEST_LEDGER", root / "requests.json"),
                patch.object(paired_eval, "STOP_FILE", root / "STOP"),
            ):
                with self.assertRaises(paired_eval.RunStopped):
                    paired_eval.run(rows, stop_event=stop)
                self.assertEqual(create.call_count, 1)
                saved = paired_eval.load_cache()
                self.assertEqual(len(saved), 1)
                self.assertTrue(saved["TEST-0|CO|vulnerable"]["complete"])

    def test_budget_survives_lost_response_and_restart(self):
        class ConnectionError(Exception):
            pass

        class StatusError(Exception):
            pass

        create = Mock(side_effect=ConnectionError("response lost"))
        fake_openai = types.SimpleNamespace(
            OpenAI=Mock(return_value=types.SimpleNamespace(responses=types.SimpleNamespace(create=create))),
            APIConnectionError=ConnectionError, APITimeoutError=ConnectionError,
            RateLimitError=StatusError, InternalServerError=StatusError, APIStatusError=StatusError,
        )
        row = {"cve": "TEST", "context": "CO", "version": "vulnerable", "label": 1, "prompt": "test"}
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            with (
                patch.dict(os.environ, {"OPENAI_API_KEY": "test-only", "OPENAI_MAX_CONCURRENCY": "1"}),
                patch.dict("sys.modules", {"openai": fake_openai}),
                patch.object(paired_eval, "CACHE", root / "cache.json"),
                patch.object(paired_eval, "TPM_STATE", root / "tpm.json"),
                patch.object(paired_eval, "REQUEST_LEDGER", root / "requests.json"),
                patch.object(paired_eval, "STOP_FILE", root / "STOP"),
                patch.object(paired_eval, "MAX_COST_USD", 0.001),
                patch.object(paired_eval, "MAX_OUTPUT_TOKENS", 400),
                patch.object(paired_eval, "input_token_reserve", return_value=100),
                patch.object(paired_eval.random, "uniform", return_value=-1.5),
            ):
                for _ in range(2):
                    with self.assertRaisesRegex(SystemExit, "budget stop"):
                        paired_eval.run([row])
                self.assertEqual(create.call_count, 1)
                ledger = json.loads((root / "requests.json").read_text(encoding="utf-8"))
                self.assertEqual(len(ledger), 1)


if __name__ == "__main__":
    unittest.main()
