# Do LLMs Really Find Interprocedural Vulnerabilities?

14-795 course project by Siwei Tan, Justun Gao and Mengchao Ren.

We extend Lira et al., *Vulnerability Detection with Interprocedural Context in Multiple Languages* (EASE 2026, [arXiv:2604.08417](https://arxiv.org/abs/2604.08417)), by adding the fixed version of each CVE as a negative example. That lets us measure false positives, which the original vulnerable-only benchmark cannot.

## Status: final (Nov 24)

All results are in [docs/final_results.md](docs/final_results.md); tables and figures are in `results/final/`.
The final presentation is [docs/Final_presentation_slides.pptx](docs/Final_presentation_slides.pptx), with the
speaker script in [docs/presentation_script.md](docs/presentation_script.md).

Claude Haiku 4.5, Gemini 3 Flash and GPT-5 Mini were run on all 1,436 paired C prompts (343 CVEs, 718
vulnerable/fixed pairs across code-only, + callees and + callers) with `repro.multi_eval`; GPT-4.1 Mini comes from
the milestone run.

| Question | Finding |
|---|---|
| RQ1: false alarms once the fixed version is added | Haiku 4.5 and Gemini 3 Flash flag 96.5% and 97.4% of fixed functions (code-only), GPT-5 Mini 87.2%, GPT-4.1 Mini 55.7%. Precision is about 0.5 and MCC near 0 for every model; paired F1 (0.59–0.66) sits at the 0.667 of always answering "vulnerable". |
| RQ2: does caller/callee context reduce false alarms? | Mostly no. Only GPT-5 Mini drops significantly (85.5% → 70.4% with callers on the same 179 CVEs, Holm p = 0.002), and its recall drops too (88% → 80%). |
| Error analysis | Of all 946 code-only false alarms, about 71% point at unchanged code and 28% quote the fix itself and still call it vulnerable (automatic labels; 17/24 agreement with hand labels). Memorisation of CVE IDs is rare. |
| Are the fixed functions really fixed? | All 343 pairs checked against their fix commit: none reversed, no removed line left in a fixed prompt; 14 CVEs (4%) questionable, and excluding them changes no conclusion. |

## Status: progress milestone (Oct 23)

| Milestone step | Status |
|---|---|
| 1. Get the authors' code running in a notebook | ✅ `notebooks/milestone_reproduction.ipynb` runs top to bottom. The authors' McNemar script runs with repaired paths. |
| 2. Recompute Tables 4–7 from the shipped outputs | ✅ **48/48 rows match the paper exactly.** The discrepancy log has 7 entries, all about text, method or code, none about table numbers. |
| 3. Build vulnerable/fixed pairs and prompts | ✅ 429 CVEs built from the pinned source data; 30 CVE pairs prepared for manual review. |
| 4. First paired run: GPT-4.1 Mini, C, CO/CC/CK | ✅ 1,436/1,436 predictions saved and parsed; cumulative reference-cost estimate $4.7898, including history and the 25% margin (not an Azure invoice). |

Code-only (CO) F1 across all languages, recalculated from the authors' saved
predictions (not new API inference for all four models):

| Model | F1 (paper) | F1 (recomputed) | Match |
|---|---|---|---|
| Claude Haiku 4.5 | 0.988 | 0.988 | yes |
| Gemini 3 Flash | 0.993 | 0.993 | yes |
| GPT-5 Mini | 0.951 | 0.951 | yes |
| GPT-4.1 Mini | 0.861 | 0.861 | yes |

The main finding for the rest of the project is in [D2](docs/discrepancy_log.md#d2-unparsed-answers-are-dropped-from-n-not-counted-as-misses). Gemini 3 Flash gave no parsable answer for 10% of CO prompts and about 30% of CC/CK prompts, and the paper leaves those out of N. If they count as misses, Gemini's CO accuracy falls from 0.985 to 0.891.

## Layout

```
repro/
  paths.py                 where the authors' package lives (pinned commit)
  setup_data.py            clone kevinwsbr/sw-vuln at that commit into third_party/
  data.py                  load shipped outputs + CVE languages
  metrics.py               accuracy/F1, McNemar, Holm (our own implementation)
  paper_values.py          Tables 4-7 transcribed from the paper
  tables.py                recompute Tables 4-7 and diff against the paper
  checks.py                coverage, unparsed answers, sensitivity, per-language McNemar
  run_authors_scripts.py   run the authors' mcnemar_analysis.py with paths repointed
  pairs.py                 build vulnerable/fixed pairs and fixed-version prompts
  paired_eval.py           paired C evaluation (GPT-4.1 Mini, CO/CC/CK)
  multi_eval.py            paired C evaluation for GPT-5 Mini, Claude Haiku 4.5, Gemini 3 Flash
  rq_analysis.py           RQ1/RQ2 tables, bootstrap CIs, McNemar+Holm, false-alarm analysis
  figures.py               RQ1/RQ2/error-analysis figures for the notebook (results/final/figures/)
  label_false_alarms.py    label every code-only false alarm by the code its explanation quotes
  live_rerun.py            optional 50-function CO sanity re-run
tools/
  make_notebook.py         generate notebooks/milestone_reproduction.ipynb
  audit_fixed_functions.py check every fixed function against its upstream fix commit
notebooks/
  milestone_reproduction.ipynb     reproduction, pairs, multi-model run (Step 5) and final analysis (Step 6)
  label_false_alarms_colab.ipynb   Colab run that labels all false alarms from the Drive responses
docs/
  final_results.md         RQ1, RQ2, error analysis, validity checks
  discrepancy_log.md       every difference between the paper and the package
  Final_presentation_slides.pptx, presentation_script.md   final deck and speaker script
  presentation/            deck sources (node build_deck.js; data in deck_data.json, notes in script.json)
results/                   CSV/markdown outputs (committed); final tables and figures in results/final/
tests/                     pytest
```

## Run it

**Video / no additional model calls:** open the existing
[completed Colab notebook](https://colab.research.google.com/drive/1LSpFai-QVSNe5ceGlM2ALT5mK1HdlWgh#scrollTo=cell-24)
and view its saved outputs. Do not choose *Run all*. The last section separates
the authors' metric reproduction, our new GPT-4.1-mini C rerun, and the
preliminary vulnerable/fixed extension. Viewing it needs no runtime or API key.

**Optional offline replay:** use
`notebooks/milestone_colab_cached_video.ipynb` on a Colab CPU runtime and choose
*Run all*. It embeds completed results and offline calculation code: no API
key, Drive mount, agent start, package installation or network data download
is required. It recomputes all 48 published table rows and the paired metrics.
This is a **cached-results replay**, not another inference run.
`tools/validate_cached_demo.py` checks it top-to-bottom in a fresh kernel and
empty working directory with network connections blocked. Detailed outputs
are in `results/paired_cached_analysis.json` and the new `paired_*.csv` files.

**Setting up a new Colab environment (not needed for the recording):**
1. Open `notebooks/milestone_reproduction.ipynb` from GitHub in Colab. Its short setup cell clones the project; it does not embed a Base64 source archive. The completed Drive notebook can pin the published project commit for provenance. `python tools/make_notebook.py` regenerates the GitHub-backed notebook; `--bundle` explicitly opts into the older embedded-source format.
2. Complete the Google Drive mount prompt once. Checkpoints and model results persist under `MyDrive/14795-interproc-vuln-pairs/gpt-4.1-mini-c/` across runtime resets.
3. Supply the API key through Colab Secrets (`OPENAI_API_KEY`) or the hidden runtime-only prompt. The final cell publishes readiness to `colab_status.json` and waits for a matching-runtime `start` command in `colab_control.json`; setup sends no model requests. The same channel accepts `stop` and reports progress without desktop automation. Direct execution remains disabled by default.

For the Azure deployment, add `OPENAI_API_KEY` under Colab *Secrets*. The
endpoint defaults to `https://14795-resource.services.ai.azure.com/openai/v1`
and the deployment defaults to `gpt-4.1-mini-1`; optionally override these with
`OPENAI_BASE_URL` and `OPENAI_MODEL`. Requests run with up to 32 workers and a
rolling-window limiter paced to the supplied 200,000 TPM quota. Then run
`!{sys.executable} -m repro.paired_eval`. The runner uses the Responses API,
resumes from an atomic checkpoint written after each model response, retries
an unparsed answer once, and retries transient rate-limit, timeout, connection,
and server errors up to 8 times with Retry-After-aware exponential backoff. Its
$10 guard applies a 25% margin to historical reference rates; Azure's exact
deployment pricing can differ, so the local estimate is not an invoice cap.
Never commit API keys to the repo.

Interrupting the API cell stops new requests and lets responses already in flight
finish checkpointing (up to the 120-second request timeout). Rerun the cell to
resume. A local run can also be stopped by creating `results/paired_eval.STOP`;
remove that flag before resuming. Set `PAIRED_CHECKPOINT_DIR` before importing
the runner to reuse a checkpoint directory elsewhere. A durable request ledger
reserves the cost of requests whose responses were lost, including across
restarts, so retries do not silently reset the budget.

**Locally (Python ≥ 3.10):**

```bash
python -m venv .venv && . .venv/bin/activate   # Windows: .venv\Scripts\activate
pip install -r requirements.txt
python -m repro.setup_data          # ~220 MB clone into third_party/
python -m repro.tables              # Tables 4-7 vs paper
python -m repro.checks              # discrepancy-log inputs
python -m repro.run_authors_scripts # authors' own McNemar script
python -m repro.live_rerun --dry-run
python -m repro.pairs               # build pair prompts, manifest, review sample
python -m repro.paired_eval --dry-run
$env:OPENAI_API_KEY = '<rotated-key>'
$env:OPENAI_MAX_CONCURRENCY = '32'
python -m repro.paired_eval # Azure-billed requests; 32 workers by default, estimated $10 guard
python -m pytest -q
```

**Final analysis (three new models, RQ1/RQ2, error analysis):**

```bash
# Paid runs (keys in OPENAI_API_KEY / ANTHROPIC_API_KEY / GEMINI_API_KEY; never commit them).
# Set MULTI_CHECKPOINT_DIR to a Drive folder in Colab so runs resume after a reset.
python -m repro.multi_eval --dry-run                      # cost estimate, no requests
python -m repro.multi_eval --models all --workers 8       # resumable; create a STOP file to stop
# Offline analysis of the saved responses (no keys needed)
python -m repro.rq_analysis --multi <checkpoint dir> --out results/final
python -m repro.figures                                   # results/final/figures/*.png
python -m repro.label_false_alarms --responses <checkpoint dir>
python tools/audit_fixed_functions.py                     # fixed side vs. fix commits
```

The raw responses (`<model>/responses.jsonl`) are kept on the team Drive under
`MyDrive/14795-interproc-vuln-pairs/multi_eval/`, not in the repo. Generation settings and the three unavoidable
deviations from the paper (Haiku temperature, Gemini low thinking, GPT-4.1 Mini on Azure) are in
[docs/final_results.md](docs/final_results.md).

The pinned upstream data yields 429 CVEs with at least one changed vulnerable
function and 910 changed function pairs (the proposal expected 886; an earlier
count of 916 came from a non-deterministic choice between duplicate records,
fixed in `repro/pairs.py`). Context availability for the C run is CO 343, CC 196,
and CK 179 CVE pairs. The 30-pair spot check is reviewed in
`results/final/pair_spotcheck_30_reviewed.csv` (28 valid, 1 valid with caveat,
1 misaligned).

## Limitations and future work

- The false-alarm hand labels and the spot check were done by one reviewer; the automatic labels agree with the
  hand labels 17 times out of 24, so their percentages are approximate.
- Each prompt was asked once, so run-to-run variation is not measured. GPT-4.1 Mini's recall in our Azure run was
  10 points below the authors' run on the same CVEs.
- The authors' prompt asks the model to explain where the vulnerability is; its effect on false alarms is untested
  (a neutral-prompt rerun on a subset would test it).
- Only the C subset is paired; C++ and Python have too few pairs for the statistics.
- Next steps (diff-aware prompting, verified alerts, calibrated thresholds, a human-validated benchmark, training on
  pairs) are on slides 10–11 of the final presentation.
