import json
from pathlib import Path
import tempfile
import threading
import time
import unittest
from unittest.mock import Mock, patch

from repro import colab_control


class ColabControlTests(unittest.TestCase):
    def test_local_runtime_is_rejected_before_any_model_call(self):
        with patch.object(colab_control, "configuration", return_value={
            "colab_runtime": False, "persistent_checkpoint": False, "api_key_present": True,
        }), patch.object(colab_control.paired_eval, "run") as model_run:
            with self.assertRaisesRegex(RuntimeError, "Complete Colab"):
                colab_control.serve([])
            model_run.assert_not_called()

    def test_hold_and_stale_start_cannot_trigger_evaluation(self):
        self.exercise_control(stop=False)

    def test_stop_command_reaches_the_in_flight_run(self):
        self.exercise_control(stop=True)

    def exercise_control(self, stop):
        cfg = {
            "colab_runtime": True, "persistent_checkpoint": True, "api_key_present": True,
            "budget_usd": 10.0, "workers": 32, "tpm_limit": 200_000, "max_output_tokens": 4096,
        }
        errors = []

        def fake_run(rows, stop_event):
            if stop:
                if not stop_event.wait(2):
                    raise AssertionError("stop command never reached the runner")
                raise colab_control.paired_eval.RunStopped("test stop")
            return {}

        def wait_for(path, predicate):
            deadline = time.monotonic() + 3
            while time.monotonic() < deadline:
                data = colab_control.read_json(path, {})
                if predicate(data):
                    return data
                time.sleep(0.01)
            raise AssertionError("controller state was not published")

        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            status_path = root / "colab_status.json"
            control_path = root / "colab_control.json"
            colab_control.write_status(control_path, {"action": "hold", "run_id": None})
            with (
                patch.object(colab_control, "configuration", return_value=cfg),
                patch.object(colab_control, "progress", return_value={"completed_rows": 263}),
                patch.object(colab_control.paired_eval, "CACHE", root / "cache.json"),
                patch.object(colab_control.paired_eval, "run", side_effect=fake_run) as model_run,
                patch.object(colab_control.paired_eval, "summarize", return_value={"done": True}),
            ):
                def target():
                    try:
                        colab_control.serve([], poll_seconds=0.01)
                    except BaseException as exc:
                        errors.append(exc)

                thread = threading.Thread(target=target, daemon=True)
                thread.start()
                ready = wait_for(status_path, lambda data: data.get("phase") == "ready")
                model_run.assert_not_called()
                colab_control.write_status(control_path, {"action": "start", "run_id": "stale-runtime"})
                time.sleep(0.05)
                model_run.assert_not_called()
                colab_control.write_status(control_path, {
                    "action": "start", "run_id": ready["run_id"], "ping_nonce": "test-nonce",
                })
                if stop:
                    wait_for(status_path, lambda data: data.get("phase") == "running")
                    colab_control.write_status(control_path, {"action": "stop", "run_id": ready["run_id"]})
                thread.join(timeout=3)
                self.assertFalse(thread.is_alive())
                self.assertEqual(errors, [])
                model_run.assert_called_once()
                final = json.loads(status_path.read_text(encoding="utf-8"))
                self.assertEqual(final["phase"], "stopped" if stop else "complete")
                if not stop:
                    self.assertEqual(final["ack_ping_nonce"], "test-nonce")


if __name__ == "__main__":
    unittest.main()
