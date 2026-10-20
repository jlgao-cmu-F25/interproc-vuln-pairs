"""Regenerate notebooks/milestone_reproduction.ipynb (keeps the notebook diff-friendly).

    python tools/make_notebook.py
"""
import json
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent

cells = []


def md(text):
    cells.append({"cell_type": "markdown", "metadata": {}, "source": text.strip("\n")})


def code(text):
    cells.append({"cell_type": "code", "metadata": {}, "execution_count": None, "outputs": [], "source": text.strip("\n")})


md("""
# Progress milestone: reproducing Lira et al. (EASE 2026)

14-795 project, Siwei Tan, Justun Gao, Mengchao Ren.

This notebook covers the three milestone steps from our proposal:

1. **Get the code running.** Fetch the authors' replication package ([kevinwsbr/sw-vuln](https://github.com/kevinwsbr/sw-vuln), pinned commit) and run their own McNemar script with fixed paths.
2. **Recompute the results.** Rebuild Tables 4-7 offline from the shipped model outputs, compare every cell with the paper, and log each mismatch.
3. **Small live re-run.** Query GPT-4.1 Mini on 50 random C functions (code-only) with the paper's prompt and compare with the shipped outputs. This is the only step that costs money (about $0.10).

**Runtime:** a free Colab CPU runtime. Steps 1 and 2 need no API keys. For step 3, add `OPENAI_API_KEY` in Colab's 🔑 *Secrets* panel. If the key is missing, step 3 is skipped.
""")

code("""
# --- Setup: works on a fresh Colab runtime and in a local checkout -------------
import os, sys, subprocess
from pathlib import Path

REPO_URL = "https://github.com/YOUR-ORG/interproc-vuln-pairs.git"  # <- set after pushing the repo

if Path("repro").is_dir():
    pass                                   # already at the repo root
elif Path("../repro").is_dir():
    os.chdir("..")                         # opened from notebooks/
else:                                      # fresh Colab runtime
    subprocess.run(["git", "clone", "--depth", "1", REPO_URL, "interproc-vuln-pairs"], check=True)
    os.chdir("interproc-vuln-pairs")
sys.path.insert(0, os.getcwd())
if "google.colab" in sys.modules:          # locally, install requirements.txt into your own venv instead
    subprocess.run([sys.executable, "-m", "pip", "install", "-q", "-r", "requirements.txt"], check=True)
print("repo root:", os.getcwd())
""")

md("## Step 1: Get the authors' code running")

code("""
!{sys.executable} -m repro.setup_data
""")

md("""
Load the shipped outputs. Each model file maps a CVE to a label (1 = vulnerable, 0 = not, `None` = no answer) for CO / CC / CK. Language comes from the prompt folder the CVE was generated into.
""")

code("""
import pandas as pd
pd.set_option("display.width", 200, "display.max_columns", 40)
from repro.data import load_all_outputs, cve_languages
from repro import checks

outputs = load_all_outputs()
langs = cve_languages()
prompt_counts, evaluated = checks.coverage(outputs, langs)
print("prompt folders:", prompt_counts)
print("CVEs in model outputs:", evaluated, "=", sum(evaluated.values()))
print("language map disagreements:", checks.language_map_agreement(langs) or "none")
""")

md("""
Run the authors' **own** `src/utilities/mcnemar_analysis.py`, unchanged except for its paths. In the reorganised repo its `RESULTS_DIR` points at a folder that no longer exists, so we import the module and repoint the path. Its full report is written to `results/authors_mcnemar_report.md`. The report is in Portuguese.
""")

code("""
!{sys.executable} -m repro.run_authors_scripts
""")

md("## Step 2: Recompute Tables 4-7 from the shipped outputs")

md("""
Our own implementation (`repro/metrics.py`) follows Sec. 3.3-3.4 of the paper. N counts answers with a label. Accuracy = recall = TP/N. F1 = 2R/(1+R), because precision is 1 by construction. McNemar uses the continuity correction, φ = (b−c)/√((b+c)N), and Holm-Bonferroni across all 12 tests.
""")

code("""
from repro.tables import run
results, mismatches = run()
for name in ["Table 5 (all)", "Table 6 (C)", "Table 7 (Python)"]:
    print(f"=== {name} ==="); display(results[name])
""")

code("""
print("=== Table 4 (McNemar) ===")
cols = ["model", "comparison", "N_paper", "N_ours", "chi2_paper", "chi2_ours", "p_paper", "p_ours",
        "sig_paper", "sig_ours", "phi_paper", "phi_ours", "match"]
display(results["Table 4 (McNemar)"][cols])
print("C++ (not tabulated in the paper):"); display(results["C++ (not in paper)"].round(4))
""")

code("""
total = sum(len(df) for df in results.values() if "match" in df)
ok = sum(df.match.sum() for df in results.values() if "match" in df)
print(f"{ok}/{total} table rows match the paper exactly; {len(mismatches)} mismatching cells")
display(mismatches)
""")

md("""
### Discrepancy log inputs

Every number in Tables 4-7 matches. The checks below are the rest of `docs/discrepancy_log.md`. They cover what the paper's tables do not show.
""")

code("""
u = checks.unparsed_counts(outputs)
print("Answers without a label: 'no_prompt' = context not available, 'unparsed' = model answered but no CLASSIFICATION line")
display(u)
""")

code("""
print("Sensitivity: count an unparsed answer as a miss (the protocol we use for our own runs)")
display(checks.none_as_wrong(outputs, langs))
""")

code("""
lm = checks.language_mcnemar_vs_shipped(outputs, langs)
print("Per-language McNemar vs the shipped mcnemar_by_language.json")
print("cells where n, b, c, chi2, p and phi all agree:", (~lm.issue.str.contains("n:|b:|c:|chi2|p_value|phi|sig")).sum(), "/", len(lm))
display(lm[lm.issue != "match"])
""")

md("## Step 3: Small live re-run (GPT-4.1 Mini, 50 C functions, CO)")

code("""
from repro import live_rerun
cves = live_rerun.sample_cves()
tin, tout, usd = live_rerun.estimate_cost(cves)
print(f"{len(cves)} CVEs, seed {live_rerun.SEED}; estimated ${usd:.3f} (hard cap ${live_rerun.BUDGET_USD:.2f})")

if live_rerun.get_api_key():
    live_rerun.run(cves)               # resumes from results/live_rerun_raw.json if interrupted
if live_rerun.CACHE.exists() and all(c in live_rerun.load_cache() for c in cves):
    summary = live_rerun.report(cves)
else:
    summary = None
    print("No OPENAI_API_KEY and no cached answers: live re-run skipped (milestone fallback: offline reproduction only).")
""")

code("""
if summary:
    per = pd.read_csv(live_rerun.PER_CVE)
    print("Disagreements between the shipped answer and our live answer:")
    display(per[~per.agree])
""")

md("## Result: paper vs. ours, code-only (CO), all languages")

code("""
from IPython.display import Markdown
display(Markdown(open("results/headline_f1.md").read()))
if summary:
    display(Markdown(
        f"Live re-run (GPT-4.1 Mini, {summary['n']} C functions, CO): shipped accuracy "
        f"**{summary['shipped_accuracy']:.2f}**, ours **{summary['live_accuracy']:.2f}** "
        f"(agreement {summary['label_agreement']:.0%}, exact McNemar p = {summary['exact_mcnemar_p']}, "
        f"cost ${summary['total_cost_usd']:.3f})."))
""")

code("""
!{sys.executable} -m pytest -q
""")

nb = {
    "cells": cells,
    "metadata": {
        "colab": {"provenance": []},
        "kernelspec": {"display_name": "Python 3", "language": "python", "name": "python3"},
        "language_info": {"name": "python"},
    },
    "nbformat": 4,
    "nbformat_minor": 5,
}
for i, c in enumerate(nb["cells"]):
    c["id"] = f"cell-{i:02d}"
out = ROOT / "notebooks" / "milestone_reproduction.ipynb"
out.parent.mkdir(exist_ok=True)
out.write_text(json.dumps(nb, indent=1, ensure_ascii=False) + "\n", encoding="utf-8")
print("wrote", out)
