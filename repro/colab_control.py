"""Colab-only evaluation controlled through private files on mounted Drive.

The notebook completes setup before advertising a fresh run_id. A start
command must name that run_id; commands from earlier runtimes cannot start it.
No API key is written to Drive or the status file.
"""
from datetime import datetime, timezone
import json
import os
from pathlib import Path
import sys
import threading
import time
import uuid

from . import paired_eval


def read_json(path, default):
    try:
        return json.loads(Path(path).read_text(encoding="utf-8"))
    except (FileNotFoundError, json.JSONDecodeError):
        return default


def write_status(path, payload):
    # Keep the existing Drive file ID stable for connector reads.
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8") as handle:
        json.dump(payload, handle, indent=2)
        handle.flush()
        os.fsync(handle.fileno())


def configuration():
    return {
        "colab_runtime": "google.colab" in sys.modules,
        "base_url": paired_eval.get_setting("OPENAI_BASE_URL", paired_eval.DEFAULT_BASE_URL),
        "deployment": paired_eval.get_model(),
        "workers": paired_eval.get_concurrency(),
        "tpm_limit": paired_eval.TPM_LIMIT,
        "budget_usd": paired_eval.MAX_COST_USD,
        "max_output_tokens": paired_eval.MAX_OUTPUT_TOKENS,
        "api_key_present": bool(paired_eval.get_api_key()),
        "persistent_checkpoint": str(paired_eval.CACHE).startswith("/content/drive/"),
        "checkpoint": str(paired_eval.CACHE),
    }


def progress(total_rows):
    cache = paired_eval.load_cache()
    attempts = [attempt for item in cache.values() for attempt in item["attempts"]]
    completed_ids = {attempt.get("request_id") for attempt in attempts}
    ledger = read_json(paired_eval.REQUEST_LEDGER, {})
    pending = [entry for request_id, entry in ledger.items() if request_id not in completed_ids]
    response_cost = sum(attempt.get("cost_usd", 0) for attempt in attempts)
    uncertain_cost = sum(entry["cost_reserve_usd"] for entry in pending if entry.get("status") != "in_flight")
    in_flight_cost = sum(entry["cost_reserve_usd"] for entry in pending if entry.get("status") == "in_flight")
    return {
        "total_rows": total_rows,
        "saved_rows": len(cache),
        "completed_rows": sum(item.get("complete", True) for item in cache.values()),
        "parsed_rows": sum(item["prediction"] is not None for item in cache.values()),
        "successful_calls": len(attempts),
        "budget_accounted_usd": round(response_cost + uncertain_cost, 6),
        "in_flight_reserve_usd": round(in_flight_cost, 6),
        "in_flight_requests": sum(entry.get("status") == "in_flight" for entry in pending),
    }


def serve(rows, poll_seconds=5):
    """Publish readiness; wait for a verified start command; run only in Colab."""
    cfg = configuration()
    if not (cfg["colab_runtime"] and cfg["persistent_checkpoint"] and cfg["api_key_present"]):
        raise RuntimeError("Complete Colab, Drive, and credential setup before starting the controller.")
    if (cfg["budget_usd"] != 10.0 or cfg["workers"] != 32
            or cfg["tpm_limit"] != 200_000 or cfg["max_output_tokens"] != 4096):
        raise RuntimeError("The requested budget, concurrency, TPM, or output limit is not configured.")

    folder = paired_eval.CACHE.parent
    command_path = folder / "colab_control.json"
    status_path = folder / "colab_status.json"
    run_id = uuid.uuid4().hex
    stop_event = threading.Event()
    finished = threading.Event()
    status_lock = threading.Lock()
    phase = "ready"
    sequence = 0
    latest_command = {}

    def publish(error=None, summary=None):
        nonlocal sequence
        with status_lock:
            sequence += 1
            payload = {
                "schema_version": 1,
                "run_id": run_id,
                "phase": phase,
                "sequence": sequence,
                "heartbeat_utc": datetime.now(timezone.utc).isoformat(),
                "runtime_pid": os.getpid(),
                "ack_ping_nonce": latest_command.get("ping_nonce") if latest_command.get("run_id") == run_id else None,
                "configuration": cfg,
                "progress": progress(len(rows)),
            }
            if error is not None:
                message = str(error)
                secret = paired_eval.get_api_key()
                payload["error"] = message.replace(secret, "[redacted]")[:1000] if secret else message[:1000]
            if summary is not None:
                payload["summary"] = summary
            write_status(status_path, payload)

    print(f"Colab setup ready. Waiting for a start command for run_id={run_id}.", flush=True)
    print(f"Status: {status_path}", flush=True)
    publish()
    try:
        while True:
            latest_command = read_json(command_path, {})
            if latest_command.get("run_id") == run_id:
                if latest_command.get("action") == "stop":
                    phase = "stopped"
                    publish()
                    return None
                if latest_command.get("action") == "start":
                    break
            publish()
            time.sleep(poll_seconds)
    except KeyboardInterrupt:
        phase = "stopped"
        publish()
        raise

    def monitor():
        nonlocal latest_command, phase
        failures = 0
        while not finished.wait(poll_seconds):
            try:
                command = read_json(command_path, None)
                if not isinstance(command, dict):
                    raise ValueError("Colab control file is unavailable.")
                latest_command = command
                if latest_command.get("run_id") == run_id and latest_command.get("action") == "stop":
                    phase = "stopping"
                    stop_event.set()
                publish()
                failures = 0
            except (OSError, ValueError):
                failures += 1
                if failures >= 3:
                    stop_event.set()
                    return

    phase = "running"
    publish()
    watcher = threading.Thread(target=monitor, name="colab-drive-control", daemon=True)
    watcher.start()
    result = None
    failure = None
    try:
        cache = paired_eval.run(rows, stop_event=stop_event)
        result = paired_eval.summarize(rows, cache)
        phase = "complete"
    except (paired_eval.RunStopped, KeyboardInterrupt):
        phase = "stopped"
    except SystemExit as exc:
        phase = "budget_stop" if "budget stop" in str(exc).lower() else "failed"
        failure = exc
    except BaseException as exc:
        phase = "failed"
        failure = exc
    finally:
        finished.set()
        watcher.join(timeout=poll_seconds + 1)
        publish(error=failure, summary=result)
    if failure is not None:
        raise failure
    return result
