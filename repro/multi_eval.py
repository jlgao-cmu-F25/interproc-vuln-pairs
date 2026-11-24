"""Paired C evaluation for the paper's other three models.

Runs GPT-5 Mini, Claude Haiku 4.5 and Gemini 3 Flash on exactly the same
1,436 vulnerable/fixed prompts as the completed GPT-4.1-mini run, with each
model's generation settings copied from the authors' runners
(third_party/sw-vuln/src/utilities/run_{openai,anthropic,gemini}.py):

    model                      API               temperature  max output tokens
    gpt-5-mini                 Chat Completions  1.0 (only)   4096 (incl. reasoning)
    claude-haiku-4-5-20251001  Messages          API default* 4096
    (*paper: 0.0; the API no longer accepts temperature for this model)
    gemini-3-flash-preview     generateContent   0.0          4096 (incl. thinking)

Protocol (same as repro.paired_eval): one request per prompt; if no
``CLASSIFICATION: 0/1`` can be parsed, retry once; a prompt still unparsed
counts as an error in the analysis. Transient API errors (429/5xx/timeouts)
are retried with exponential backoff and are not protocol attempts.

Every completed response is appended to ``<checkpoint>/<model>/responses.jsonl``
and flushed, so an interrupted run resumes where it stopped. Spending is
tracked from the token usage each API reports, at list prices, against a
per-model cap. The provider dashboard is the real invoice.

    python -m repro.multi_eval --dry-run
    python -m repro.multi_eval --models all --pilot 20      # first 20 prompts per model
    python -m repro.multi_eval --models all                 # everything (resumes)

API keys come from the environment or Colab Secrets:
OPENAI_API_KEY, ANTHROPIC_API_KEY, GEMINI_API_KEY.
"""
import argparse
from concurrent.futures import ThreadPoolExecutor, as_completed
import hashlib
import json
import os
from pathlib import Path
import random
import re
import threading
import time
import traceback

from .paths import RESULTS_DIR
from .pairs import PAIRED_PROMPTS, CONTEXTS

CHECKPOINT_ROOT = Path(os.environ.get("MULTI_CHECKPOINT_DIR", RESULTS_DIR / "multi_eval"))
MAX_OUTPUT_TOKENS = 4096
RESPONSE_ATTEMPTS = 2          # first answer + one retry when unparsed
MAX_TRANSIENT_RETRIES = 8
REQUEST_TIMEOUT = 180.0
PILOT_SEED = 795

MODELS = {
    "gpt-5-mini": {"label": "GPT-5 Mini", "provider": "openai", "temperature": 1.0,
                   "usd_per_m": (0.25, 2.00), "key": "OPENAI_API_KEY", "budget": 15.0},
    # The paper ran Haiku at temperature 0. As of Nov 2026 the Messages API rejects
    # `temperature` for this model ("Extra inputs are not permitted"), so the
    # request omits it and the model runs at the API default: a reported deviation.
    "claude-haiku-4-5-20251001": {"label": "Claude Haiku 4.5", "provider": "anthropic", "temperature": None,
                                  "usd_per_m": (1.00, 5.00), "key": "ANTHROPIC_API_KEY", "budget": 15.0},
    # Deviation: with the paper's settings (default thinking inside the 4,096-token
    # output limit) 5 of 7 pilot answers spent ~3,930 tokens thinking and ended with
    # MAX_TOKENS before any label. Thinking is set to "low" so answers can finish.
    "gemini-3-flash-preview": {"label": "Gemini 3 Flash", "provider": "gemini", "temperature": 0.0,
                               "thinking_level": "low",
                               "usd_per_m": (0.50, 3.00), "key": "GEMINI_API_KEY", "budget": 16.0},
}
ALIASES = {"gpt5": "gpt-5-mini", "haiku": "claude-haiku-4-5-20251001", "gemini": "gemini-3-flash-preview"}


def parse_response(text):
    """Same rule as repro.paired_eval: the first CLASSIFICATION: 0/1 wins."""
    match = re.search(r"CLASSIFICATION:\s*([01])", text or "", re.IGNORECASE)
    return int(match.group(1)) if match else None


def get_setting(name):
    value = os.environ.get(name)
    if value:
        return value
    try:
        from google.colab import userdata
        return userdata.get(name)
    except Exception:
        return None


def item_key(row):
    return f"{row['cve']}|{row['context']}|{row['version']}"


def prompt_rows():
    root = PAIRED_PROMPTS / "c"
    if not root.exists():
        raise SystemExit("Run `python -m repro.pairs` first.")
    rows = []
    for folder in sorted(p for p in root.iterdir() if p.is_dir()):
        for context in CONTEXTS:
            for version, label in (("vulnerable", 1), ("fixed", 0)):
                path = folder / f"{context}_{version}.txt"
                if path.exists():
                    prompt = path.read_text(encoding="utf-8").strip()
                    rows.append({"cve": folder.name, "context": context, "version": version,
                                 "truth": label, "prompt": prompt,
                                 "prompt_sha256": hashlib.sha256(prompt.encode("utf-8")).hexdigest()})
    return rows


def ordered_rows(rows):
    """Pilot order: random CVE/context pairs, both versions kept together."""
    pairs = sorted({(r["cve"], r["context"]) for r in rows})
    random.Random(PILOT_SEED).shuffle(pairs)
    rank = {pair: i for i, pair in enumerate(pairs)}
    return sorted(rows, key=lambda r: (rank[(r["cve"], r["context"])], r["version"] != "vulnerable"))


def verify_prompts(rows, expected_hashes):
    """Refuse to run unless every prompt is byte-identical to the GPT-4.1-mini run."""
    actual = {item_key(r): r["prompt_sha256"] for r in rows}
    missing = sorted(set(expected_hashes) - set(actual))
    extra = sorted(set(actual) - set(expected_hashes))
    differ = sorted(k for k in set(actual) & set(expected_hashes) if actual[k] != expected_hashes[k])
    if missing or extra or differ:
        raise SystemExit(f"Prompt mismatch vs GPT-4.1-mini run: missing={missing[:5]} "
                         f"extra={extra[:5]} differ={differ[:5]} (counts {len(missing)}/{len(extra)}/{len(differ)})")
    return len(actual)


# --------------------------------------------------------------------------- providers

class Provider:
    def __init__(self, model, spec):
        self.model, self.spec = model, spec
        key = get_setting(spec["key"])
        if not key:
            raise SystemExit(f"{spec['key']} not found (environment or Colab Secrets).")
        provider = spec["provider"]
        if provider == "openai":
            import openai
            self.client = openai.OpenAI(api_key=key, max_retries=0, timeout=REQUEST_TIMEOUT)
        elif provider == "anthropic":
            import anthropic
            self.client = anthropic.Anthropic(api_key=key, max_retries=0, timeout=REQUEST_TIMEOUT)
        elif provider == "gemini":
            from google import genai
            from google.genai import types
            self.types = types
            # The default API version (v1) does not serve the preview model.
            self.client = genai.Client(api_key=key, http_options=types.HttpOptions(
                api_version="v1beta", timeout=int(REQUEST_TIMEOUT * 1000)))
        self.provider = provider

    def call(self, prompt):
        """Return text, token usage and response metadata for one request."""
        temperature = self.spec["temperature"]
        if self.provider == "openai":
            r = self.client.chat.completions.create(
                model=self.model, max_completion_tokens=MAX_OUTPUT_TOKENS, temperature=temperature,
                messages=[{"role": "user", "content": prompt}])
            choice = r.choices[0] if r.choices else None
            details = getattr(r.usage, "completion_tokens_details", None)
            return {"text": (choice.message.content if choice else "") or "",
                    "input_tokens": r.usage.prompt_tokens, "output_tokens": r.usage.completion_tokens,
                    "reasoning_tokens": getattr(details, "reasoning_tokens", None),
                    "finish_reason": choice.finish_reason if choice else None, "served_model": r.model}
        if self.provider == "anthropic":
            extra = {} if temperature is None else {"extra_body": {"temperature": temperature}}
            r = self.client.messages.create(
                model=self.model, max_tokens=MAX_OUTPUT_TOKENS,
                messages=[{"role": "user", "content": prompt}], **extra)
            text = "".join(getattr(block, "text", "") for block in r.content)
            return {"text": text, "input_tokens": r.usage.input_tokens, "output_tokens": r.usage.output_tokens,
                    "reasoning_tokens": None, "finish_reason": r.stop_reason, "served_model": r.model}
        r = self.client.models.generate_content(
            model=self.model, contents=prompt,
            config=self.types.GenerateContentConfig(
                max_output_tokens=MAX_OUTPUT_TOKENS, temperature=temperature,
                thinking_config=self.types.ThinkingConfig(thinking_level=self.spec["thinking_level"])))
        meta = r.usage_metadata
        thoughts = getattr(meta, "thoughts_token_count", None) or 0
        candidates = getattr(meta, "candidates_token_count", None) or 0
        text = ""
        finish = None
        if r.candidates:
            finish = str(r.candidates[0].finish_reason)
            parts = getattr(getattr(r.candidates[0], "content", None), "parts", None) or []
            text = "".join(p.text for p in parts if getattr(p, "text", None) and not getattr(p, "thought", False))
        # Gemini bills thinking tokens as output tokens.
        return {"text": text, "input_tokens": getattr(meta, "prompt_token_count", 0) or 0,
                "output_tokens": candidates + thoughts, "reasoning_tokens": thoughts,
                "finish_reason": finish, "served_model": getattr(r, "model_version", None)}


def status_code(exc):
    for attr in ("status_code", "code"):
        value = getattr(exc, attr, None)
        if isinstance(value, int):
            return value
    response = getattr(exc, "response", None)
    return getattr(response, "status_code", None)


def is_transient(exc):
    text = str(exc).lower()
    # Hard money limits stop the run. Gemini's per-minute limit also says
    # "exceeded your current quota ... billing details", so it is retried.
    if any(s in text for s in ("insufficient_quota", "credit balance", "billing_hard_limit")):
        return False
    code = status_code(exc)
    if code in (408, 409, 425, 429, 500, 502, 503, 504, 529):
        return True
    name = type(exc).__name__.lower()
    return any(s in name for s in ("timeout", "connection", "remoteprotocol", "readerror", "servererror"))


def retry_after(exc, attempt):
    headers = getattr(getattr(exc, "response", None), "headers", None) or {}
    try:
        if headers.get("retry-after") is not None:
            return min(120.0, float(headers["retry-after"])) + random.uniform(0.2, 1.0)
    except (TypeError, ValueError):
        pass
    return min(60.0, 2.0 * (2 ** attempt)) + random.uniform(0.2, 1.5)


# --------------------------------------------------------------------------- runner

class ModelRun:
    def __init__(self, model, rows, workers, budget=None, log=print):
        self.model, self.spec = model, MODELS[model]
        self.rows = rows
        self.workers = workers
        self.budget = budget if budget is not None else self.spec["budget"]
        self.dir = CHECKPOINT_ROOT / model
        self.dir.mkdir(parents=True, exist_ok=True)
        self.path = self.dir / "responses.jsonl"
        self.errors = self.dir / "errors.log"
        self.stop_file = self.dir / "STOP"
        self.lock = threading.Lock()
        self.stop = threading.Event()
        self.log = log
        self.attempts = self.load()
        self.spent = sum(a["cost_usd"] for items in self.attempts.values() for a in items)
        self.reserved = 0.0
        self.max_call_cost = self.cost(60_000, MAX_OUTPUT_TOKENS)

    def cost(self, input_tokens, output_tokens):
        price_in, price_out = self.spec["usd_per_m"]
        return (input_tokens * price_in + output_tokens * price_out) / 1_000_000

    def load(self):
        attempts = {}
        if self.path.exists():
            for line in self.path.read_text(encoding="utf-8").splitlines():
                if line.strip():
                    try:
                        record = json.loads(line)
                    except json.JSONDecodeError:
                        continue  # a torn final line from a crash
                    attempts.setdefault(record["key"], []).append(record)
        return attempts

    def done(self, key):
        items = self.attempts.get(key, [])
        return any(a["prediction"] is not None for a in items) or len(items) >= RESPONSE_ATTEMPTS

    def append(self, record):
        with self.lock:
            with self.path.open("a", encoding="utf-8") as handle:
                handle.write(json.dumps(record, ensure_ascii=False) + "\n")
                handle.flush()
                os.fsync(handle.fileno())
            self.attempts.setdefault(record["key"], []).append(record)

    def evaluate(self, provider, row):
        key = item_key(row)
        while not self.done(key):
            if self.stop.is_set() or self.stop_file.exists():
                self.stop.set()
                return "stopped"
            with self.lock:
                if self.spent + self.reserved + self.max_call_cost > self.budget:
                    self.stop.set()
                    return "budget"
                self.reserved += self.max_call_cost
            try:
                for attempt in range(MAX_TRANSIENT_RETRIES + 1):
                    try:
                        started = time.time()
                        response = provider.call(row["prompt"])
                        break
                    except Exception as exc:
                        with open(self.errors, "a", encoding="utf-8") as handle:
                            handle.write(f"{time.strftime('%H:%M:%S')} {key} {type(exc).__name__}: {str(exc)[:300]}\n")
                        if not is_transient(exc) or attempt == MAX_TRANSIENT_RETRIES:
                            self.stop.set()
                            raise
                        time.sleep(retry_after(exc, attempt))
                        if self.stop_file.exists():
                            self.stop.set()
                            return "stopped"
            finally:
                with self.lock:
                    self.reserved -= self.max_call_cost
            cost = self.cost(response["input_tokens"], response["output_tokens"])
            with self.lock:
                self.spent += cost
            self.append({"key": key, "cve": row["cve"], "context": row["context"], "version": row["version"],
                         "truth": row["truth"], "model": self.model, "prompt_sha256": row["prompt_sha256"],
                         "attempt": len(self.attempts.get(key, [])) + 1,
                         "prediction": parse_response(response["text"]), "cost_usd": cost,
                         "latency_s": round(time.time() - started, 2), "max_output_tokens": MAX_OUTPUT_TOKENS,
                         "temperature": self.spec["temperature"], "thinking_level": self.spec.get("thinking_level"), "utc": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
                         **response})
        return "ok"

    def run(self, limit=None):
        todo = [r for r in self.rows if not self.done(item_key(r))]
        if limit is not None:
            allowed = {item_key(r) for r in self.rows[:limit]}
            todo = [r for r in todo if item_key(r) in allowed]
        self.log(f"[{self.model}] {len(todo)} prompts to run; ${self.spent:.4f} spent of ${self.budget:.2f}")
        if not todo:
            return self.status()
        provider = Provider(self.model, self.spec)
        outcomes = {}
        last = time.time()
        with ThreadPoolExecutor(max_workers=self.workers) as pool:
            futures = [pool.submit(self.evaluate, provider, row) for row in todo]
            for count, future in enumerate(as_completed(futures), 1):
                try:
                    outcome = future.result()
                except Exception as exc:
                    outcome = f"error: {type(exc).__name__}: {str(exc)[:200]}"
                    self.stop.set()
                outcomes[outcome] = outcomes.get(outcome, 0) + 1
                if time.time() - last > 30 or count == len(todo):
                    last = time.time()
                    self.log(f"[{self.model}] {count}/{len(todo)} finished; ${self.spent:.4f}; {outcomes}")
        status = self.status()
        status["last_outcomes"] = outcomes
        self.write_status(status)
        return status

    def status(self):
        keys = [item_key(r) for r in self.rows]
        complete = sum(self.done(k) for k in keys)
        unparsed = sum(self.done(k) and all(a["prediction"] is None for a in self.attempts.get(k, [])) for k in keys)
        calls = [a for items in self.attempts.values() for a in items]
        return {"model": self.model, "label": self.spec["label"], "prompts": len(keys), "complete": complete,
                "unparsed_after_retry": unparsed, "calls": len(calls), "spent_usd": round(self.spent, 4),
                "budget_usd": self.budget,
                "input_tokens": sum(a["input_tokens"] for a in calls),
                "output_tokens": sum(a["output_tokens"] for a in calls),
                "served_models": sorted({str(a.get("served_model")) for a in calls}),
                "finish_reasons": {f: sum(str(a.get("finish_reason")) == f for a in calls)
                                   for f in sorted({str(a.get("finish_reason")) for a in calls})}}

    def write_status(self, status):
        (self.dir / "status.json").write_text(json.dumps(status, indent=2), encoding="utf-8")


def resolve_models(names):
    if names == ["all"]:
        return list(MODELS)
    return [ALIASES.get(n, n) for n in names]


def main(argv=None):
    parser = argparse.ArgumentParser()
    parser.add_argument("--models", nargs="+", default=["all"])
    parser.add_argument("--pilot", type=int, default=None, help="only the first N prompts (pilot order) per model")
    parser.add_argument("--workers", type=int, default=8)
    parser.add_argument("--expected-hashes", type=Path, default=None,
                        help="JSON {key: sha256} from the GPT-4.1-mini run; the run refuses any mismatch")
    parser.add_argument("--dry-run", action="store_true")
    args = parser.parse_args(argv)
    rows = ordered_rows(prompt_rows())
    if args.expected_hashes:
        n = verify_prompts(rows, json.loads(args.expected_hashes.read_text(encoding="utf-8")))
        print(f"All {n} prompts are identical to the GPT-4.1-mini run.", flush=True)
    models = resolve_models(args.models)
    if args.dry_run:
        chars = sum(len(r["prompt"]) for r in rows)
        for model in models:
            spec = MODELS[model]
            approx_in = chars / 3.5
            print(f"{model}: {len(rows)} prompts, ~{approx_in/1e6:.2f}M input tokens, "
                  f"~${approx_in * spec['usd_per_m'][0] / 1e6:.2f} input cost before output; cap ${spec['budget']}")
        return
    log_lock = threading.Lock()

    def log(message):
        with log_lock:
            print(message, flush=True)
    runs = [ModelRun(model, rows, args.workers, log=log) for model in models]
    results = {}
    with ThreadPoolExecutor(max_workers=len(runs)) as pool:
        futures = {pool.submit(run.run, args.pilot): run.model for run in runs}
        for future in as_completed(futures):
            model = futures[future]
            try:
                results[model] = future.result()
            except Exception:
                results[model] = {"error": traceback.format_exc()}
    (CHECKPOINT_ROOT / "run_summary.json").write_text(json.dumps(results, indent=2), encoding="utf-8")
    print(json.dumps(results, indent=2), flush=True)


if __name__ == "__main__":
    main()
