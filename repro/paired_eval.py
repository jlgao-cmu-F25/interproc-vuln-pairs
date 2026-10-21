"""Paired GPT-4.1 Mini evaluation for the milestone's C subset.

After pair generation, run ``python -m repro.paired_eval --dry-run``. To run
against Azure AI, set OPENAI_API_KEY, OPENAI_BASE_URL, and OPENAI_MODEL (or add
them under Colab Secrets) and run without --dry-run.
The raw response cache is resumable and ignored by git.
"""
import argparse
from collections import deque
from concurrent.futures import ThreadPoolExecutor, as_completed
import csv
from email.utils import parsedate_to_datetime
from functools import lru_cache
import hashlib
import json
import math
import os
from pathlib import Path
import random
import re
import tempfile
import threading
import time
import uuid

from .pairs import CONTEXTS, PAIRED_PROMPTS
from .paths import RESULTS_DIR

MODEL = "gpt-4.1-mini-1"
DEFAULT_BASE_URL = "https://14795-resource.services.ai.azure.com/openai/v1"
INPUT_USD_PER_MILLION = 0.40
OUTPUT_USD_PER_MILLION = 1.60
PRICE_SAFETY_MULTIPLIER = 1.25
MAX_OUTPUT_TOKENS = 4096
MAX_COST_USD = 10.00
TOKEN_CHARS = 3.0  # conservative rough estimate for source-code prompts
RETRY_UNPARSED_ONCE = True
TPM_LIMIT = 200_000
TPM_WINDOW_SECONDS = 60
MAX_TRANSIENT_RETRIES = 8
DEFAULT_CONCURRENCY = 32
MAX_CONCURRENCY = 32
CHECKPOINT_DIR = Path(os.environ.get("PAIRED_CHECKPOINT_DIR", RESULTS_DIR))
CACHE = CHECKPOINT_DIR / "paired_eval_raw.json"
TPM_STATE = CHECKPOINT_DIR / "paired_eval_tpm.json"
REQUEST_LEDGER = CHECKPOINT_DIR / "paired_eval_requests.json"
STOP_FILE = CHECKPOINT_DIR / "paired_eval.STOP"
SUMMARY = CHECKPOINT_DIR / "paired_eval_summary.json"
PREDICTIONS = CHECKPOINT_DIR / "paired_eval_predictions.csv"


class RunStopped(RuntimeError):
    """Requested interruption after preserving completed responses."""


def get_setting(name, default=None):
    value = os.environ.get(name)
    if value:
        return value
    try:
        from google.colab import userdata
        return userdata.get(name) or default
    except Exception:
        return default


def get_api_key():
    return get_setting("OPENAI_API_KEY")


def get_model():
    return get_setting("OPENAI_MODEL", MODEL)


def get_concurrency():
    raw = get_setting("OPENAI_MAX_CONCURRENCY", str(DEFAULT_CONCURRENCY))
    try:
        workers = int(raw)
    except (TypeError, ValueError):
        raise SystemExit("OPENAI_MAX_CONCURRENCY must be an integer from 1 to 32.")
    if not 1 <= workers <= MAX_CONCURRENCY:
        raise SystemExit("OPENAI_MAX_CONCURRENCY must be an integer from 1 to 32.")
    return workers


def parse_response(text):
    match = re.search(r"CLASSIFICATION:\s*([01])", text or "", re.IGNORECASE)
    return int(match.group(1)) if match else None


@lru_cache(maxsize=1)
def tokenizer():
    try:
        import tiktoken
        return tiktoken.get_encoding("o200k_base")
    except ImportError:
        return None


def input_token_reserve(prompt):
    encoding = tokenizer()
    count = (len(encoding.encode(prompt, disallowed_special=())) if encoding is not None
             else len(prompt.encode("utf-8")))
    # Also accommodate Azure's character-based quota estimate and request framing.
    return max(count + 32, math.ceil(len(prompt) / TOKEN_CHARS))


def examples():
    root = PAIRED_PROMPTS / "c"
    if not root.exists():
        raise SystemExit("Run `python -m repro.pairs` first.")
    rows = []
    for folder in sorted(p for p in root.iterdir() if p.is_dir()):
        for context, _ in CONTEXTS.items():
            for version, label in (("vulnerable", 1), ("fixed", 0)):
                path = folder / f"{context}_{version}.txt"
                if path.exists():
                    rows.append({"cve": folder.name, "context": context, "version": version,
                                 "label": label, "prompt": path.read_text(encoding="utf-8").strip()})
    return rows


def estimate_cost(rows):
    input_tokens = sum(input_token_reserve(row["prompt"]) for row in rows)
    first_pass_output = len(rows) * MAX_OUTPUT_TOKENS
    retry_worst_input = input_tokens if RETRY_UNPARSED_ONCE else 0
    retry_worst_output = first_pass_output if RETRY_UNPARSED_ONCE else 0
    first_pass = (input_tokens * INPUT_USD_PER_MILLION
                  + first_pass_output * OUTPUT_USD_PER_MILLION) / 1_000_000 * PRICE_SAFETY_MULTIPLIER
    retries = (retry_worst_input * INPUT_USD_PER_MILLION
               + retry_worst_output * OUTPUT_USD_PER_MILLION) / 1_000_000 * PRICE_SAFETY_MULTIPLIER
    return {"prompt_count": len(rows), "max_calls_with_retry": len(rows) * 2,
            "estimated_input_tokens_first_pass": round(input_tokens),
            "reserved_output_tokens_first_pass": first_pass_output,
            "estimated_first_pass_usd": round(first_pass, 4),
            "additional_cost_if_every_prompt_needs_retry_usd": round(retries, 4),
            "price_safety_multiplier": PRICE_SAFETY_MULTIPLIER,
            "tpm_limit": TPM_LIMIT,
            "default_parallel_workers": DEFAULT_CONCURRENCY,
            "budget_usd": MAX_COST_USD}


def load_cache():
    return json.loads(CACHE.read_text(encoding="utf-8")) if CACHE.exists() else {}


def atomic_json_write(path, payload):
    path.parent.mkdir(parents=True, exist_ok=True)
    temp_path = None
    try:
        with tempfile.NamedTemporaryFile(
            mode="w", encoding="utf-8", dir=path.parent,
            prefix=f"{path.name}.", suffix=".tmp", delete=False,
        ) as handle:
            temp_path = handle.name
            json.dump(payload, handle, indent=1, ensure_ascii=False)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temp_path, path)
    finally:
        if temp_path and os.path.exists(temp_path):
            os.unlink(temp_path)


def save_cache(cache):
    """Atomically persist completed responses so interruption cannot corrupt the checkpoint."""
    atomic_json_write(CACHE, cache)


def cost_of(usage):
    return (usage["prompt_tokens"] * INPUT_USD_PER_MILLION
            + usage["completion_tokens"] * OUTPUT_USD_PER_MILLION) / 1_000_000 * PRICE_SAFETY_MULTIPLIER


def run(rows, stop_event=None):
    key = get_api_key()
    if not key:
        raise SystemExit("No OPENAI_API_KEY found. No model requests were sent.")
    import openai

    stop_event = stop_event or threading.Event()

    def check_stop():
        if STOP_FILE.exists():
            stop_event.set()
        if stop_event.is_set():
            raise RunStopped("Run stopped; completed responses are checkpointed. Rerun to resume.")

    def interruptible_wait(seconds):
        deadline = time.monotonic() + seconds
        while True:
            check_stop()
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                return
            stop_event.wait(min(remaining, 0.5))

    cache = load_cache()
    recovered = 0
    for item in cache.values():
        if item.get("prediction") is not None:
            continue
        truncated = [attempt for attempt in item["attempts"]
                     if attempt.get("max_output_tokens", 400) < MAX_OUTPUT_TOKENS
                     and not attempt.get("superseded_by_output_limit")
                     and attempt["completion_tokens"] >= attempt.get("max_output_tokens", 400)]
        if truncated:
            for attempt in truncated:
                attempt["superseded_by_output_limit"] = MAX_OUTPUT_TOKENS
            item["complete"] = False
            recovered += 1
    if recovered:
        save_cache(cache)
        print(f"Recovering {recovered} output-truncated rows; earlier request costs remain in the budget.", flush=True)
    attempts_saved = [attempt for item in cache.values() for attempt in item["attempts"]]
    completed_ids = {attempt.get("request_id") for attempt in attempts_saved}
    ledger = json.loads(REQUEST_LEDGER.read_text(encoding="utf-8")) if REQUEST_LEDGER.exists() else {}
    ledger = {request_id: entry for request_id, entry in ledger.items() if request_id not in completed_ids}
    spent = (sum(attempt.get("cost_usd", 0) for attempt in attempts_saved)
             + sum(entry["cost_reserve_usd"] for entry in ledger.values()))
    reserved = 0.0
    budget_lock = threading.Lock()
    cache_lock = threading.Lock()
    tpm_lock = threading.Lock()
    now = time.time()
    persisted_events = json.loads(TPM_STATE.read_text(encoding="utf-8")) if TPM_STATE.exists() else []
    token_events = deque((float(timestamp), int(tokens)) for timestamp, tokens in persisted_events
                         if float(timestamp) > now - TPM_WINDOW_SECONDS)
    tokens_in_window = sum(tokens for _, tokens in token_events)
    base_url = get_setting("OPENAI_BASE_URL", DEFAULT_BASE_URL)
    client = openai.OpenAI(api_key=key, base_url=base_url, max_retries=0, timeout=120.0)
    model = get_model()
    RESULTS_DIR.mkdir(exist_ok=True)
    for row in rows:
        item_key = f"{row['cve']}|{row['context']}|{row['version']}"
        previous = cache.get(item_key, {})
        digest = hashlib.sha256(row["prompt"].encode("utf-8")).hexdigest()
        if previous.get("prompt_sha256", digest) != digest or previous.get("requested_model", model) != model:
            raise RuntimeError(f"Checkpoint prompt/model differs for {item_key}; choose a separate PAIRED_CHECKPOINT_DIR.")

    def acquire_tpm(tokens):
        nonlocal tokens_in_window
        if tokens > TPM_LIMIT:
            raise RuntimeError(f"One request needs an estimated {tokens:,} tokens, above the {TPM_LIMIT:,} TPM limit.")
        while True:
            check_stop()
            with tpm_lock:
                now = time.time()
                while token_events and token_events[0][0] <= now - TPM_WINDOW_SECONDS:
                    _, expired_tokens = token_events.popleft()
                    tokens_in_window -= expired_tokens
                if tokens_in_window + tokens <= TPM_LIMIT:
                    token_events.append((now, tokens))
                    tokens_in_window += tokens
                    atomic_json_write(TPM_STATE, list(token_events))
                    return
                wait = max(0.05, token_events[0][0] + TPM_WINDOW_SECONDS - now)
            interruptible_wait(wait)

    def retry_delay(exc, retry_index):
        headers = getattr(getattr(exc, "response", None), "headers", {}) or {}
        delay = None
        try:
            if headers.get("retry-after-ms") is not None:
                delay = float(headers["retry-after-ms"]) / 1000
            elif headers.get("retry-after") is not None:
                try:
                    delay = float(headers["retry-after"])
                except ValueError:
                    delay = parsedate_to_datetime(headers["retry-after"]).timestamp() - time.time()
        except (TypeError, ValueError):
            delay = None
        if delay is not None:
            return max(0.0, delay) + random.uniform(0.1, 0.8)
        return min(60.0, 1.5 * (2 ** retry_index)) + random.uniform(0.1, 0.8)

    def is_retryable(exc):
        if getattr(exc, "code", None) in ("insufficient_quota", "billing_hard_limit_reached", "quota_exceeded"):
            return False
        if isinstance(exc, (openai.RateLimitError, openai.APIConnectionError,
                            openai.APITimeoutError, openai.InternalServerError)):
            return True
        return (isinstance(exc, openai.APIStatusError)
                and exc.status_code in (408, 409, 429, 500, 502, 503, 504))

    def evaluate(row):
        nonlocal spent, reserved
        item_key = f"{row['cve']}|{row['context']}|{row['version']}"
        check_stop()
        previous = cache.get(item_key, {})
        if item_key in cache and previous.get("complete", True):
            return None
        attempts = list(previous.get("attempts", []))
        item = previous or None
        prediction = previous.get("prediction")
        blocked = None
        spent_snapshot = spent
        response_slots = 2 if RETRY_UNPARSED_ONCE else 1
        protocol_attempts = sum(not attempt.get("superseded_by_output_limit") for attempt in attempts)
        for parse_attempt in range(protocol_attempts, response_slots):
            check_stop()
            # Reserve this request using a conservative source-code token estimate
            # and the configured output ceiling before crossing the API boundary.
            estimated_tokens = input_token_reserve(row["prompt"]) + MAX_OUTPUT_TOKENS
            reserve = (
                (estimated_tokens - MAX_OUTPUT_TOKENS) * INPUT_USD_PER_MILLION
                + MAX_OUTPUT_TOKENS * OUTPUT_USD_PER_MILLION
            ) / 1_000_000 * PRICE_SAFETY_MULTIPLIER
            for retry_index in range(MAX_TRANSIENT_RETRIES + 1):
                acquire_tpm(estimated_tokens)
                check_stop()
                request_id = uuid.uuid4().hex
                with budget_lock:
                    if spent + reserved + reserve > MAX_COST_USD:
                        blocked = (f"budget stop before {item_key}: accrued ${spent:.4f}, "
                                   f"in-flight reserve ${reserved:.4f}, next-call reserve ${reserve:.4f} "
                                   f"would exceed ${MAX_COST_USD:.2f}")
                        break
                    ledger[request_id] = {"item_key": item_key, "cost_reserve_usd": reserve,
                                          "started_at": time.time(), "status": "in_flight"}
                    atomic_json_write(REQUEST_LEDGER, ledger)
                    reserved += reserve
                try:
                    response = client.responses.create(
                        model=model, temperature=0, max_output_tokens=MAX_OUTPUT_TOKENS,
                        input=row["prompt"],
                    )
                    break
                except BaseException as exc:
                    status = getattr(exc, "status_code", None)
                    known_unbilled = status is not None and 400 <= status < 500 and status != 408
                    with budget_lock:
                        reserved -= reserve
                        if known_unbilled:
                            ledger.pop(request_id, None)
                        else:
                            # A lost response may already have been billed. Keep its
                            # reserve across restarts instead of spending it twice.
                            spent += reserve
                            ledger[request_id]["status"] = "uncertain"
                        atomic_json_write(REQUEST_LEDGER, ledger)
                    if not isinstance(exc, Exception) or not is_retryable(exc) or retry_index >= MAX_TRANSIENT_RETRIES:
                        stop_event.set()
                        raise
                    wait = retry_delay(exc, retry_index)
                    print(f"retry {retry_index + 1}/{MAX_TRANSIENT_RETRIES} for {item_key} "
                          f"after {type(exc).__name__}; sleeping {wait:.1f}s", flush=True)
                    interruptible_wait(wait)
            if blocked:
                return item_key, item, spent_snapshot, blocked
            text = getattr(response, "output_text", "") or ""
            usage = {"prompt_tokens": response.usage.input_tokens,
                     "completion_tokens": response.usage.output_tokens}
            billed = cost_of(usage)
            with budget_lock:
                reserved -= reserve
                spent += billed
                spent_snapshot = spent
            attempts.append({"text": text, **usage, "cost_usd": billed,
                             "served_model": response.model, "request_id": request_id,
                             "max_output_tokens": MAX_OUTPUT_TOKENS,
                             "response_status": getattr(response, "status", None),
                             "incomplete_reason": getattr(getattr(response, "incomplete_details", None), "reason", None)})
            prediction = parse_response(text)
            complete = prediction is not None or parse_attempt == response_slots - 1
            item = {"cve": row["cve"], "context": row["context"],
                    "version": row["version"], "truth": row["label"],
                    "prediction": prediction, "attempts": list(attempts),
                    "prompt_sha256": hashlib.sha256(row["prompt"].encode("utf-8")).hexdigest(),
                    "requested_model": model,
                    "complete": complete}
            with cache_lock:
                cache[item_key] = item
                save_cache(cache)
            with budget_lock:
                ledger.pop(request_id, None)
                atomic_json_write(REQUEST_LEDGER, ledger)
            if complete:
                break
        return item_key, item, spent_snapshot, blocked

    pending = [row for row in rows
               if (f"{row['cve']}|{row['context']}|{row['version']}" not in cache
                   or not cache[f"{row['cve']}|{row['context']}|{row['version']}"].get("complete", True))]
    failures = []
    budget_stop = None
    workers = get_concurrency()
    executor = ThreadPoolExecutor(max_workers=workers)
    interrupted = False
    try:
        futures = [executor.submit(evaluate, row) for row in pending]
        for future in as_completed(futures):
            try:
                result = future.result()
            except RunStopped:
                interrupted = True
                continue
            except Exception as exc:
                failures.append(exc)
                continue
            if result is None:
                continue
            item_key, item, accrued, blocked = result
            if item is not None:
                print(f"{item_key}: prediction={item['prediction']}; accrued=${accrued:.4f}", flush=True)
            if blocked and budget_stop is None:
                budget_stop = blocked
    except KeyboardInterrupt:
        interrupted = True
        stop_event.set()
        print("Stopping new requests; saving responses already in flight...", flush=True)
    finally:
        if interrupted or stop_event.is_set():
            stop_event.set()
        executor.shutdown(wait=True, cancel_futures=True)
    if failures:
        raise failures[0]
    if interrupted or stop_event.is_set():
        raise RunStopped("Run stopped; completed responses are checkpointed. Rerun to resume.")
    if budget_stop:
        raise SystemExit(budget_stop)
    return cache


def summarize(rows, cache):
    # Each CVE/context is one vulnerable-fixed pair.
    by_pair = {}
    for row in rows:
        key = f"{row['cve']}|{row['context']}|{row['version']}"
        item = cache[key]
        by_pair.setdefault((row["cve"], row["context"]), {})[row["version"]] = item["prediction"]
    output = []
    for (cve, context), pred in sorted(by_pair.items()):
        v, f = pred.get("vulnerable"), pred.get("fixed")
        category = "unparsed" if v is None or f is None else {
            (1, 0): "P-C", (1, 1): "P-V", (0, 0): "P-B", (0, 1): "P-R"
        }[(v, f)]
        output.append({"cve": cve, "context": context,
                       "vulnerable_prediction": v, "fixed_prediction": f,
                       "pair_category": category,
                       "vulnerable_correct": v == 1,
                       "fixed_correct": f == 0,
                       "pair_correct": category == "P-C"})

    metrics = {}
    for context in ("CO", "CC", "CK"):
        subset = [r for r in output if r["context"] == context]
        n_vuln = len(subset)
        parsed = [r for r in subset if r["vulnerable_prediction"] is not None and r["fixed_prediction"] is not None]
        # A response that remains unparsed after retry counts as an error:
        # vulnerable-side None is FN; fixed-side None is FP.
        tp = sum(r["vulnerable_prediction"] == 1 for r in subset)
        fn = sum(r["vulnerable_prediction"] != 1 for r in subset)
        fp = sum(r["fixed_prediction"] != 0 for r in subset)
        tn = sum(r["fixed_prediction"] == 0 for r in subset)
        metrics[context] = {
            "pairs": n_vuln,
            "unparsed_pairs": n_vuln - len(parsed),
            "recall": tp / (tp + fn) if tp + fn else None,
            "precision": tp / (tp + fp) if tp + fp else None,
            "fpr": fp / (fp + tn) if fp + tn else None,
            "pair_correct_rate": sum(r["pair_category"] == "P-C" for r in subset) / n_vuln if n_vuln else None,
            "P-C": sum(r["pair_category"] == "P-C" for r in subset),
            "P-V": sum(r["pair_category"] == "P-V" for r in subset),
            "P-B": sum(r["pair_category"] == "P-B" for r in subset),
            "P-R": sum(r["pair_category"] == "P-R" for r in subset),
        }

    all_attempts = [attempt for item in cache.values() for attempt in item["attempts"]]
    completed_ids = {attempt.get("request_id") for attempt in all_attempts}
    ledger = json.loads(REQUEST_LEDGER.read_text(encoding="utf-8")) if REQUEST_LEDGER.exists() else {}
    uncertain = {key: entry for key, entry in ledger.items() if key not in completed_ids}
    uncertain_cost = sum(entry["cost_reserve_usd"] for entry in uncertain.values())
    result = {
        "model_requested": get_model(),
        "served_models": sorted({a["served_model"] for a in all_attempts}),
        "context_metrics": metrics,
        "total_cost_usd": round(sum(a["cost_usd"] for a in all_attempts) + uncertain_cost, 4),
        "uncertain_request_reserve_usd": round(uncertain_cost, 4),
        "uncertain_requests": len(uncertain),
        "price_safety_multiplier": PRICE_SAFETY_MULTIPLIER,
        "calls": len(all_attempts),
        "superseded_truncated_calls": sum(bool(attempt.get("superseded_by_output_limit")) for attempt in all_attempts),
        "max_output_tokens": MAX_OUTPUT_TOKENS,
        "prompt_tokens": sum(a["prompt_tokens"] for a in all_attempts),
        "completion_tokens": sum(a["completion_tokens"] for a in all_attempts),
        "unparsed_responses": sum(item["prediction"] is None for item in cache.values()),
        "budget_usd": MAX_COST_USD,
    }
    with PREDICTIONS.open("w", newline="", encoding="utf-8-sig") as f:
        writer = csv.DictWriter(f, fieldnames=list(output[0]) if output else [])
        writer.writeheader()
        writer.writerows(output)
    SUMMARY.write_text(json.dumps(result, indent=2), encoding="utf-8")
    print(json.dumps(result, indent=2))
    return result


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--dry-run", action="store_true", help="list inputs and estimated cost without API calls")
    args = parser.parse_args()
    rows = examples()
    estimate = estimate_cost(rows)
    print(json.dumps(estimate, indent=2))
    print(f"API concurrency: {get_concurrency()} workers")
    if args.dry_run:
        return
    if estimate["estimated_first_pass_usd"] > MAX_COST_USD:
        print("Dataset estimate exceeds the budget; requests will stop and checkpoint at the cap.", flush=True)
    if not get_api_key():
        raise SystemExit("No OPENAI_API_KEY found. Add it to Colab Secrets, then rerun this cell.")
    cache = run(rows)
    summarize(rows, cache)


if __name__ == "__main__":
    main()
