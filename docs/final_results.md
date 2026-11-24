# Final results: RQ1, RQ2 and the false-alarm analysis

C subset, 343 CVEs: 718 CVE × context pairs, each asked once as the vulnerable version and once as the fixed version.
All numbers below come from `results/final/*.csv`, produced by `python -m repro.rq_analysis` (see "Reproduce").

## Status by model

| Model | Paired run | Source of numbers |
|---|---|---|
| Claude Haiku 4.5 | complete, 1,436 / 1,436 prompts (Nov 22) | this run, pair-level |
| GPT-5 Mini | complete, 1,436 / 1,436 prompts (Nov 22) | this run, pair-level |
| GPT-4.1 Mini | complete (milestone, Oct 20) | `results/paired_context_metrics_final.csv` (aggregates). Pair-level `paired_eval_raw.json` is on the Drive of the account that ran the milestone, so it isn't in this analysis yet |
| Gemini 3 Flash | complete, 1,436 / 1,436 prompts (Nov 23, low thinking) | this run, pair-level |

## RQ1: false alarms once the fixed version is added

Headline table (C, code-only, 343 pairs per model). Every fixed function a model flags is a false positive.

| Model | TP | FN | FP (fixed flagged) | TN | Recall | Precision | Paired F1 |
|---|---|---|---|---|---|---|---|
| Claude Haiku 4.5 | 333 | 10 | 331 | 12 | 0.971 | 0.502 | 0.661 |
| Gemini 3 Flash | 326 | 17 | 334 | 9 | 0.950 | 0.494 | 0.650 |
| GPT-5 Mini | 308 | 35 | 299 | 44 | 0.898 | 0.507 | 0.648 |
| GPT-4.1 Mini* | 225 | 118 | 191 | 152 | 0.656 | 0.541 | 0.593 |

Answering "vulnerable" to every sample scores recall 1.0, precision 0.5 and paired F1 0.667, so on paired data F1
barely penalises false alarms. GPT-4.1 Mini flags the fewest fixed functions but has the lowest F1 because of its
recall. FPR, MCC and the both-right rate below are what separate the models.

Full detail, all contexts:

| Model | Ctx | Pairs | Paper F1 (C, vuln-only) | Our vuln-only F1 | Recall | Precision | FPR on fixed [95% CI] | MCC [95% CI] | Both right (P-C) | Both flagged (P-V) |
|---|---|---|---|---|---|---|---|---|---|---|
| Claude Haiku 4.5 | CO | 343 | 0.990 | 0.985 | 0.971 | 0.502 | 96.5% [94.5–98.3] | 0.017 [-0.051, 0.082] | 2.6% | 94.5% |
| Claude Haiku 4.5 | CC | 196 | 0.990 | 0.974 | 0.949 | 0.499 | 95.4% [92.3–98.0] | -0.012 [-0.093, 0.077] | 3.1% | 91.8% |
| Claude Haiku 4.5 | CK | 179 | 0.989 | 0.986 | 0.972 | 0.501 | 96.6% [93.9–98.9] | 0.016 [-0.087, 0.105] | 2.8% | 94.4% |
| Gemini 3 Flash | CO | 343 | 0.997 | 0.975 | 0.950 | 0.494 | 97.4% [95.6–98.8] | -0.061 [-0.122, 0.000] | 1.5% | 93.6% |
| Gemini 3 Flash | CC | 196 | 0.978 | 0.968 | 0.939 | 0.496 | 95.4% [92.3–98.0] | -0.034 [-0.107, 0.038] | 2.0% | 91.8% |
| Gemini 3 Flash | CK | 179 | 0.984 | 0.953 | 0.911 | 0.491 | 94.4% [90.5–97.8] | -0.065 [-0.149, 0.023] | 3.4% | 87.7% |
| GPT-5 Mini | CO | 343 | 0.950 | 0.946 | 0.898 | 0.507 | 87.2% [83.7–90.4] | 0.041 [-0.026, 0.106] | 9.3% | 80.5% |
| GPT-5 Mini | CC | 196 | 0.915 | 0.883 | 0.791 | 0.500 | 79.1% [73.5–84.7] | 0.000 [-0.071, 0.068] | 8.2% | 70.9% |
| GPT-5 Mini | CK | 179 | 0.885 | 0.892 | 0.804 | 0.533 | 70.4% [63.1–77.1] | 0.117 [0.033, 0.200] | 17.9% | 62.6% |
| GPT-4.1 Mini* | CO | 343 | 0.861 | — | 0.656 | 0.541 | 55.7% | 0.101 | 19.0% | 46.6% |
| GPT-4.1 Mini* | CC | 196 | 0.675 | — | 0.515 | 0.532 | 45.4% | 0.061 | 13.8% | 37.8% |
| GPT-4.1 Mini* | CK | 179 | 0.815 | — | 0.587 | 0.565 | 45.3% | 0.134 | 18.4% | 40.2% |

\* GPT-4.1 Mini rows are the milestone run (aggregates; no bootstrap CI without the pair-level file).
CIs are 2,000-sample percentile bootstraps over CVE pairs. A pair counts as "both right" (P-C) when the vulnerable version is flagged and the fixed version is cleared.

**H1 is supported.** Every model's precision is about 0.49 to 0.57 and every MCC is near zero. The models flag the fixed code almost as often as the vulnerable code.
- Haiku 4.5 and Gemini 3 Flash are the extreme cases. Gemini flags 97.4% of fixed functions (CO), gets both versions right for 1.5% of CVEs, and has a slightly negative MCC (−0.061, CI −0.122 to 0.000). Haiku 4.5's vulnerable-only F1 (0.985) reproduces the paper's 0.990, yet it flags 96.5% of fixed functions and gets both versions right for only 2.6% of CVEs.
- The paper's near-perfect F1 scores therefore mostly measure a tendency to say "vulnerable", not detection.
- Ranking flips: the paper's weakest model, GPT-4.1 Mini, has the lowest false-alarm rate and the highest both-right rate.

Robustness: excluding the 17 CVEs whose "fixed" function name differs from the vulnerable one (`rq1_paired_metrics_aligned_only.csv`), or counting only pairs where both answers parsed (`cc_*` columns), changes no conclusion. Rates move by at most about 2 points, except Gemini's recall on complete cases, which rises by up to 4.5 points because its 47 unparsed answers drop out; its false-alarm rate barely moves.

## RQ2: does interprocedural context reduce false alarms?

Exact McNemar tests on the CVEs that have both contexts. Holm correction covers the 9 tests within each model. Δ is a paired bootstrap 95% CI.

| Model | Metric | Comparison | Matched CVEs | Rate A | Rate B | Δ (A−B) [95% CI] | Holm p |
|---|---|---|---|---|---|---|---|
| Claude Haiku 4.5 | fixed_alert | CO-CC | 196 | 97.4% | 95.4% | +2.0 pp [-1.5, +5.6] | 1.000 |
| Claude Haiku 4.5 | fixed_alert | CO-CK | 179 | 97.2% | 96.6% | +0.6 pp [-2.8, +3.9] | 1.000 |
| Claude Haiku 4.5 | fixed_alert | CC-CK | 107 | 94.4% | 96.3% | -1.9 pp [-5.6, +1.9] | 1.000 |
| Claude Haiku 4.5 | vulnerable_recall | CO-CC | 196 | 98.5% | 94.9% | +3.6 pp [+1.0, +6.1] | 0.141 |
| Claude Haiku 4.5 | vulnerable_recall | CO-CK | 179 | 96.1% | 97.2% | -1.1 pp [-5.0, +2.2] | 1.000 |
| Claude Haiku 4.5 | vulnerable_recall | CC-CK | 107 | 93.5% | 96.3% | -2.8 pp [-9.3, +2.8] | 1.000 |
| Claude Haiku 4.5 | pair_correct | CO-CC | 196 | 2.0% | 3.1% | -1.0 pp [-3.6, +1.5] | 1.000 |
| Claude Haiku 4.5 | pair_correct | CO-CK | 179 | 1.7% | 2.8% | -1.1 pp [-3.9, +1.7] | 1.000 |
| Claude Haiku 4.5 | pair_correct | CC-CK | 107 | 3.7% | 2.8% | +0.9 pp [-1.9, +3.7] | 1.000 |
| Gemini 3 Flash | fixed_alert | CO-CC | 196 | 98.5% | 95.4% | +3.1 pp [+0.0, +6.1] | 0.984 |
| Gemini 3 Flash | fixed_alert | CO-CK | 179 | 97.2% | 94.4% | +2.8 pp [-1.1, +6.7] | 1.000 |
| Gemini 3 Flash | fixed_alert | CC-CK | 107 | 94.4% | 96.3% | -1.9 pp [-7.5, +2.8] | 1.000 |
| Gemini 3 Flash | vulnerable_recall | CO-CC | 196 | 94.4% | 93.9% | +0.5 pp [-4.1, +5.1] | 1.000 |
| Gemini 3 Flash | vulnerable_recall | CO-CK | 179 | 93.9% | 91.1% | +2.8 pp [-2.2, +7.8] | 1.000 |
| Gemini 3 Flash | vulnerable_recall | CC-CK | 107 | 95.3% | 91.6% | +3.7 pp [-1.9, +9.3] | 1.000 |
| Gemini 3 Flash | pair_correct | CO-CC | 196 | 0.0% | 2.0% | -2.0 pp [-4.1, -0.5] | 1.000 |
| Gemini 3 Flash | pair_correct | CO-CK | 179 | 0.6% | 3.4% | -2.8 pp [-5.6, +0.0] | 1.000 |
| Gemini 3 Flash | pair_correct | CC-CK | 107 | 2.8% | 2.8% | +0.0 pp [-4.7, +4.7] | 1.000 |
| GPT-5 Mini | fixed_alert | CO-CC | 196 | 86.2% | 79.1% | +7.1 pp [+0.5, +13.8] | 0.218 |
| GPT-5 Mini | fixed_alert | CO-CK | 179 | 85.5% | 70.4% | +15.1 pp [+7.3, +22.9] | 0.002 **✓** |
| GPT-5 Mini | fixed_alert | CC-CK | 107 | 77.6% | 71.0% | +6.5 pp [-2.8, +15.0] | 0.689 |
| GPT-5 Mini | vulnerable_recall | CO-CC | 196 | 87.8% | 79.1% | +8.7 pp [+3.1, +14.3] | 0.027 **✓** |
| GPT-5 Mini | vulnerable_recall | CO-CK | 179 | 88.3% | 80.4% | +7.8 pp [+2.2, +13.4] | 0.088 |
| GPT-5 Mini | vulnerable_recall | CC-CK | 107 | 75.7% | 77.6% | -1.9 pp [-9.3, +6.5] | 1.000 |
| GPT-5 Mini | pair_correct | CO-CC | 196 | 8.7% | 8.2% | +0.5 pp [-4.6, +5.6] | 1.000 |
| GPT-5 Mini | pair_correct | CO-CK | 179 | 10.1% | 17.9% | -7.8 pp [-14.5, -1.1] | 0.201 |
| GPT-5 Mini | pair_correct | CC-CK | 107 | 8.4% | 15.9% | -7.5 pp [-15.0, +0.0] | 0.461 |

**H2 is partly supported, and only for GPT-5 Mini.**
- **Gemini 3 Flash:** like Haiku, context changes nothing. Its false-alarm rate stays at 94–98%, and no test survives correction.
- **GPT-5 Mini:** callers (CK) cut false alarms on fixed code by 15.1 points (Holm p = 0.002). This holds when excluding misaligned CVEs (p = 0.006) and on complete cases (p = 0.002). But context also lowers recall on vulnerable code (−8.7 pp CO→CC, significant; −7.8 pp CO→CK, significant on complete cases). Both-right pairs rise from 10.1% to 17.9% without reaching significance after correction. So the effect is mainly a shift toward answering "safe" more often, with a modest gain in discrimination (MCC 0.041 → 0.117).
- **Haiku 4.5:** context changes nothing. Its false-alarm rate stays at 95–97% everywhere.
- **GPT-4.1 Mini:** the milestone false-alarm rate also falls from 55.7% (CO) to about 45% (CC/CK). It can't be tested at the pair level until the milestone `paired_eval_raw.json` is added.

## False-alarm analysis

**What the false alarms point at.** A random sample of 8 CO false alarms per model (seed 795) was labelled by reading the patch diff and the explanation given for the fixed version (`results/final/false_alarm_labels.csv`). The labels were made by Claude and should be confirmed by a team member.

| Category | Haiku 4.5 | Gemini 3 Flash | GPT-5 Mini |
|---|---|---|---|
| Points at the patched lines and calls the fix insufficient | 5 / 8 | 3 / 8 | 1 / 8 |
| Makes a specific claim about different code | 2 / 8 | 5 / 8 | 7 / 8 |
| Generic or speculative ("no NULL check") | 1 / 8 | 0 / 8 | 0 / 8 |

The models fail differently. Gemini sits between the other two. One of its "different code" cases, CVE-2012-3400, flags the partition-map length loop, which was the second half of that CVE's upstream fix, so it may be a real remaining bug rather than a false alarm.
- **Haiku** usually reads the fix itself as the bug. For CVE-2018-8786 it quotes the new `UINT32 count` line and calls it an integer overflow. For CVE-2021-32672 it quotes the newly added bounds check as the flaw.
- **GPT-5 Mini** usually accepts the patched area and finds a different, plausible-sounding weakness elsewhere: unchecked `strcpy` in a nearby branch, a TOCTOU race in another part of the function, an unchecked return value. These could be real secondary bugs or speculation. Confirming them would need per-case triage, which was out of scope.

**Memorisation.** Haiku and GPT-5 Mini show no sign of it; Gemini shows a small one.
- Haiku and GPT-5 Mini: across 2,872 answers, exactly one cites any CVE ID, and never the correct one.
- Gemini 3 Flash: 154 of its 1,436 answers cite a CVE ID. 17 of them name the correct CVE, including 10 answers about the *fixed* code, so the model recognises the code as the known vulnerability even after the patch (`cve_id_citations.csv`). That is about 1% of answers, too few to explain its 97% false-alarm rate.
- For all three models, the rate of flagging both versions does not trend with CVE year (Spearman ρ: Haiku 0.017, Gemini 0.002, GPT-5 Mini 0.053; `memorisation_by_year.csv`).

**Automatic indicators** (`false_alarms_summary.csv`, all fixed-version alerts):
- About 90% of alert explanations mention an identifier that occurs in the changed lines.
- The explanation for the fixed version shares only about 22–24% of its identifiers with the same model's explanation for the vulnerable version (median Jaccard).

These are weak signals, because changed lines often reuse common identifiers. Treat them as context for the manual labels, not as findings.

## Validity of the negatives

- **30-pair spot check** (`results/final/pair_spotcheck_30_reviewed.csv`). 28 pairs are valid, 1 is valid with a caveat (CVE-2012-3400: the buggy code moved into a helper that isn't in the prompt), and 1 is **misaligned** (CVE-2020-9433: the "fixed" code is a different function). This was an assisted review by Claude; please have one person confirm it.
- **Automated misalignment check.** 17 of the 343 C CVEs have a "fixed" function with a different name from its vulnerable counterpart. Some are genuine renames in the fix; others are ReposVul pairing errors. They are listed in `misaligned_cves.csv` and excluded in the `*_aligned_only` sensitivity files. No conclusion changes.
- **Manifest correction.** `results/pair_manifest.csv` had been generated on Windows from the wrong duplicate raw record for CVE-2016-5356 and CVE-2016-5357. The prompts actually sent always used the correct record. The pair builder now loads duplicates deterministically, and the corrected count is 910 changed function pairs (was 916).

## Deviations from the paper's settings

| Model | Paper | This run | Why |
|---|---|---|---|
| Claude Haiku 4.5 | temperature 0 | API default | The Messages API now rejects `temperature` for this model ("Extra inputs are not permitted") |
| Gemini 3 Flash | default thinking, 4,096 tokens | thinking "low", 4,096 tokens | With the paper's settings, 5 of 7 pilot answers ran out of tokens while thinking and gave no label. The team chose low thinking. Even so, 105 of 1,499 calls hit the limit; 47 prompts stayed unparsed after one retry and count as errors |
| GPT-5 Mini | temperature 1, 4,096 tokens | same | 144 of 1,535 calls hit the token limit; 45 prompts stayed unparsed after one retry and count as errors |

## Cost (list prices, from reported token usage)

| Model | Calls | Cost |
|---|---|---|
| Claude Haiku 4.5 | 1,438 | $11.64 |
| GPT-5 Mini | 1,535 | $9.23 |
| Gemini 3 Flash | 1,499 (+7 discarded default-thinking pilot calls) | $8.12 (+$0.10 pilot) |
| GPT-4.1 Mini (milestone) | 1,544 | $4.79 incl. 25% margin |

## Reproduce

All runs happened in Colab. Checkpoints are on Drive at `MyDrive/14795-interproc-vuln-pairs/multi_eval/<model>/responses.jsonl` and every result table is in `.../results_final/`.

```bash
python -m repro.setup_data && python -m repro.pairs
python -m repro.multi_eval --dry-run
python -m repro.multi_eval --models haiku gpt5 gemini        # resumes from checkpoints; needs API keys
python -m repro.rq_analysis --multi <checkpoint dir> --gpt41 <paired_eval_raw.json> --out results/final
python -m pytest -q tests/test_multi_eval.py tests/test_rq_analysis.py
```

## Are the fixed functions really fixed? (audit of all 343 C pairs)

`tools/audit_fixed_functions.py` compares every pair with the upstream fix commit stored in its raw record
(`results/final/fixed_function_audit.csv`); flagged pairs were then read by hand (`results/final/fixed_side_review.csv`).

- Prompts: every vulnerable prompt contains the vulnerable functions and every fixed prompt the fixed functions.
- Direction: no pair is reversed. Lines the commit adds are in the fixed version, lines it removes in the vulnerable one.
- No line that the commit removes survives in any fixed prompt.
- Coverage: for 271 CVEs at least 90% of the commit's code change is inside the shown functions; for 59 it is 50–90%,
  almost always because the rest is version strings, `#include`s, macros, comments or new helper functions.
- Questionable fixed side, 14 CVEs (4%): 4 not valid pairs (CVE-2013-6401, CVE-2015-2696, CVE-2020-27777, CVE-2020-9433),
  2 partially fixed (CVE-2012-3400, CVE-2020-5208) and 8 with a second fix commit in the dataset that is not applied.
  Another 11 are valid with a caveat (part of the fix sits in a helper or declaration the model does not see).
- Effect: excluding the 14 moves GPT-4.1 Mini's code-only false-alarm rate from 55.7% to 55.9%. For the other models,
  even the extreme cases (all 14 were alerts, or none were) keep the rate within 96.4–100% (Haiku), 97.3–100% (Gemini)
  and 86.6–90.9% (GPT-5 Mini), so no conclusion changes.

## All code-only false alarms, labelled automatically

`python -m repro.label_false_alarms --responses <multi_eval dir>` matches the code each explanation quotes (backticks,
code blocks, or shown lines pasted verbatim) against the lines the patch added or changed in the fixed functions.
The main rule was set before checking it against the hand labels: "quotes the fix" if quotes of patched lines are at
least as many as quotes of unchanged lines. Outputs: `results/final/false_alarm_auto_labels.csv`, `..._summary.csv`,
`..._agreement.json`. Counts exclude unparsed answers (counted as alerts in RQ1), so they are slightly below the FP column.

| Model | False alarms | Quotes the fix | Unchanged code | No code cited | Any quote of the fix |
|---|---|---|---|---|---|
| Claude Haiku 4.5 | 331 | 27.8% | 71.9% | 0.3% | 58.0% |
| Gemini 3 Flash | 326 | 35.6% | 63.5% | 0.9% | 66.3% |
| GPT-5 Mini | 289 | 19.0% | 78.5% | 2.4% | 38.8% |

Agreement with the 24 hand labels: 17/24 (main rule), 18/24 ("any quote of the fix"), 16/24 (first quote decides).
The hand sample overstated "blames the fix" for Haiku (5 of 8); at full scale pointing at unchanged code is the most
common pattern for every model. Treat the split as approximate.
