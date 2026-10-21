"""Milestone step 3: re-query GPT-4.1 Mini on 50 random C functions (code-only).

    OPENAI_API_KEY=... python -m repro.live_rerun            # run (resumes from cache)
    python -m repro.live_rerun --dry-run                      # show sample + cost estimate, no API calls
    python -m repro.live_rerun --report                       # compare cached answers with shipped outputs

Protocol (from our proposal): the paper's CO prompt file is sent verbatim,
temperature 0, max 4096 output tokens. The answer is parsed with the authors'
regex; if no CLASSIFICATION is found we retry once, and a second failure counts
as a miss (the paper instead drops such answers from N).
"""
import argparse
import json
import os
import random
import re
import time

from .data import load_explanations, load_outputs
from .paths import PROMPTS_DIR, RESULTS_DIR

MODEL = "gpt-4.1-mini"
SHIPPED_MODEL = "GPT-4.1 Mini"
N_SAMPLE = 50
SEED = 795
TEMPERATURE = 0.0
MAX_TOKENS = 4096
PRICE_IN, PRICE_OUT = 0.40, 1.60  # USD per 1M tokens (paper, Table 1)
MAX_CALLS = 2 * N_SAMPLE  # hard cap: one retry per prompt at most
BUDGET_USD = 1.00

CACHE = RESULTS_DIR / "live_rerun_raw.json"
SUMMARY = RESULTS_DIR / "live_rerun_summary.json"
PER_CVE = RESULTS_DIR / "live_rerun_per_cve.csv"


def parse_response(text):
    """Same regexes as the authors' run_*.py scripts."""
    text = (text or "").strip()
    m = re.search(r"EXPLANATION:\s*(.+?)(?=CLASSIFICATION:|$)", text, re.DOTALL | re.IGNORECASE)
    c = re.search(r"CLASSIFICATION:\s*([01])", text, re.IGNORECASE)
    return {"explanation": m.group(1).strip() if m else "", "classification": int(c.group(1)) if c else None}


def sample_cves():
    """50 C CVEs drawn with a fixed seed from those the paper evaluated with CO."""
    shipped = load_outputs(SHIPPED_MODEL)
    pool = sorted(
        d.name for d in (PROMPTS_DIR / "c").iterdir()
        if (d / "prompt_vuln.txt").exists() and shipped.get(d.name, {}).get("CO") is not None
    )
    return sorted(random.Random(SEED).sample(pool, N_SAMPLE))


def prompt_for(cve):
    return (PROMPTS_DIR / "c" / cve / "prompt_vuln.txt").read_text(encoding="utf-8")


def estimate_cost(cves):
    # ~4 characters per token is a conservative estimate for code; outputs ~600 tokens.
    tin = sum(len(prompt_for(c)) for c in cves) / 4
    tout = 600 * len(cves)
    return tin, tout, (tin * PRICE_IN + tout * PRICE_OUT) / 1e6


def get_setting(name, default=None):
    value = os.environ.get(name)
    if value:
        return value
    try:  # Colab secrets panel
        from google.colab import userdata
        return userdata.get(name) or default
    except Exception:
        return default


def get_api_key():
    return get_setting("OPENAI_API_KEY")


def load_cache():
    return json.loads(CACHE.read_text(encoding="utf-8")) if CACHE.exists() else {}


def run(cves):
    import openai

    key = get_api_key()
    if not key:
        raise SystemExit("No OPENAI_API_KEY (env var or Colab secret). Use --dry-run or --report instead.")
    base_url = get_setting("OPENAI_BASE_URL")
    model = get_setting("OPENAI_MODEL", MODEL)
    client = openai.OpenAI(api_key=key, base_url=base_url)
    cache = load_cache()
    calls, spent = 0, sum(r["cost_usd"] for r in cache.values())
    RESULTS_DIR.mkdir(exist_ok=True)

    for i, cve in enumerate(cves, 1):
        if cve in cache:
            continue
        attempts = []
        label = None
        for _ in range(2):  # first try + one retry
            if calls >= MAX_CALLS or spent >= BUDGET_USD:
                raise SystemExit(f"Stopped at hard cap: {calls} calls, ${spent:.3f}")
            for backoff in (1, 4, 16, None):
                try:
                    resp = client.responses.create(
                        model=model, temperature=TEMPERATURE, max_output_tokens=MAX_TOKENS,
                        input=prompt_for(cve),
                    )
                    break
                except (openai.RateLimitError, openai.APIConnectionError, openai.InternalServerError):
                    if backoff is None:
                        raise
                    time.sleep(backoff)
            calls += 1
            text = getattr(resp, "output_text", "") or ""
            cost = (resp.usage.input_tokens * PRICE_IN + resp.usage.output_tokens * PRICE_OUT) / 1e6
            spent += cost
            attempts.append(dict(text=text, prompt_tokens=resp.usage.input_tokens,
                                 completion_tokens=resp.usage.output_tokens, model=resp.model))
            label = parse_response(text)["classification"]
            if label is not None:
                break
        cache[cve] = dict(label=label, attempts=attempts, cost_usd=sum(
            (a["prompt_tokens"] * PRICE_IN + a["completion_tokens"] * PRICE_OUT) / 1e6 for a in attempts))
        CACHE.write_text(json.dumps(cache, indent=1, ensure_ascii=False), encoding="utf-8")
        print(f"[{i:2d}/{len(cves)}] {cve}: {label}  (${spent:.4f} so far)", flush=True)
    return cache


def report(cves):
    cache = load_cache()
    missing = [c for c in cves if c not in cache]
    if missing:
        raise SystemExit(f"{len(missing)} of {len(cves)} sampled CVEs have no live answer yet; run without --report first.")
    shipped = load_outputs(SHIPPED_MODEL)
    shipped_expl = load_explanations(SHIPPED_MODEL, "CO")

    rows = []
    for c in cves:
        live = cache[c]["label"]
        rows.append(dict(cve=c, shipped=shipped[c]["CO"], live=live,
                         live_unparsed=live is None, retried=len(cache[c]["attempts"]) > 1,
                         agree=(live == shipped[c]["CO"]),
                         shipped_expl_chars=len(shipped_expl[c] or ""),
                         live_expl_chars=len(parse_response(cache[c]["attempts"][-1]["text"])["explanation"])))
    n = len(rows)
    shipped_acc = sum(r["shipped"] == 1 for r in rows) / n
    live_acc = sum(r["live"] == 1 for r in rows) / n  # unparsed after retry counts as a miss
    agree = sum(r["agree"] for r in rows) / n
    flips_to_1 = sum(r["shipped"] == 0 and r["live"] == 1 for r in rows)
    flips_to_0 = sum(r["shipped"] == 1 and r["live"] != 1 for r in rows)
    # Exact McNemar (binomial) on the discordant pairs, since b + c is small.
    from scipy.stats import binomtest
    disc = flips_to_1 + flips_to_0
    p = binomtest(flips_to_1, disc, 0.5).pvalue if disc else 1.0
    summary = dict(
        model=get_setting("OPENAI_MODEL", MODEL), served_models=sorted({a["model"] for c in cves for a in cache[c]["attempts"]}),
        n=n, seed=SEED, shipped_accuracy=round(shipped_acc, 4), live_accuracy=round(live_acc, 4),
        delta=round(live_acc - shipped_acc, 4), label_agreement=round(agree, 4),
        shipped0_live1=flips_to_1, shipped1_live0=flips_to_0, exact_mcnemar_p=round(p, 4),
        unparsed_after_retry=sum(r["live_unparsed"] for r in rows), retried=sum(r["retried"] for r in rows),
        total_cost_usd=round(sum(cache[c]["cost_usd"] for c in cves), 4),
        prompt_tokens=sum(a["prompt_tokens"] for c in cves for a in cache[c]["attempts"]),
        completion_tokens=sum(a["completion_tokens"] for c in cves for a in cache[c]["attempts"]),
    )
    import pandas as pd
    pd.DataFrame(rows).to_csv(PER_CVE, index=False)
    SUMMARY.write_text(json.dumps(summary, indent=2), encoding="utf-8")
    print(json.dumps(summary, indent=2))
    return summary


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--dry-run", action="store_true")
    ap.add_argument("--report", action="store_true")
    args = ap.parse_args()
    cves = sample_cves()
    if args.dry_run:
        shipped = load_outputs(SHIPPED_MODEL)
        tin, tout, usd = estimate_cost(cves)
        acc = sum(shipped[c]["CO"] == 1 for c in cves) / len(cves)
        print(f"{len(cves)} C CVEs (seed {SEED}): {', '.join(cves[:5])}, ...")
        print(f"Shipped GPT-4.1 Mini CO accuracy on this sample: {acc:.4f}")
        print(f"Estimated ~{tin:,.0f} input + ~{tout:,.0f} output tokens = ~${usd:.3f} (cap ${BUDGET_USD:.2f})")
        return
    if not args.report:
        run(cves)
    report(cves)


if __name__ == "__main__":
    main()
