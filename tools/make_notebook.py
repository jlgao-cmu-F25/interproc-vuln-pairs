"""Regenerate notebooks/milestone_reproduction.ipynb (keeps the notebook diff-friendly).

    python tools/make_notebook.py
"""
import base64
import argparse
import hashlib
import io
import json
import sys
from pathlib import Path
import zipfile

ROOT = Path(__file__).resolve().parent.parent
parser = argparse.ArgumentParser()
parser.add_argument("--bundle", action="store_true", help="optionally create the legacy notebook with embedded source ZIP")
parser.add_argument("--with-checkpoint", action="store_true", help="bundle the stopped local run for Colab-only resumption")
args = parser.parse_args()

cells = []


def md(text):
    cells.append({"cell_type": "markdown", "metadata": {}, "source": text.strip("\n")})


def code(text):
    cells.append({"cell_type": "code", "metadata": {}, "execution_count": None, "outputs": [], "source": text.strip("\n")})


md("""
# Progress milestone: reproducing Lira et al. (EASE 2026)

14-795 project, Siwei Tan, Justun Gao, Mengchao Ren.

This notebook covers the milestone's offline reproduction and prepares the first paired run:

1. **Get the code running.** Fetch the authors' replication package ([kevinwsbr/sw-vuln](https://github.com/kevinwsbr/sw-vuln), pinned commit) and run their own McNemar script with fixed paths.
2. **Recompute the results.** Rebuild Tables 4-7 offline from the shipped model outputs, compare every cell with the paper, and log each mismatch.
3. **Build the paired dataset.** Generate vulnerable/fixed prompts for each available context and prepare a 30-pair manual review sample.
4. **First paired run.** GPT-4.1 Mini evaluates the C pairs under CO, CC and CK, with a $10 estimated budget cap.

**Runtime:** a free Colab CPU runtime. Steps 1–3 need no API key. The final step uses paid Azure API billing. The runner uses a resumable atomic checkpoint, 32 parallel workers paced to 200,000 TPM, bounded retries, and a $10 estimated budget guard.

**Setup/hold mode:** Run all cells to prepare the environment, mount Drive, import existing results, and configure credentials. The final cell advertises readiness and waits for a Drive start command for this exact runtime. Setup does not send model requests. Drive authorization and the hidden credential prompt happen in Colab.
""")

code("""
# --- Setup: works on a fresh Colab runtime and in a local checkout -------------
import os, sys, subprocess
from pathlib import Path

REPO_URL = "https://github.com/jlgao-cmu-F25/interproc-vuln-pairs.git"

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

md("## Step 3: Build vulnerable/fixed pairs")

code("""
from repro.pairs import build
pair_summary = build()
print("Manual review worksheet: results/pair_spotcheck_30.csv")
display(pd.read_csv("results/pair_manifest.csv").groupby("language").agg(
    cve_pairs=("cve", "count"), changed_function_pairs=("changed_function_count", "sum")))
""")

md("## Step 4: Paired GPT-4.1 Mini run (C subset, CO/CC/CK)")

code("""
# Checkpoints live on Drive so a Colab runtime reset does not discard results.
if "google.colab" in sys.modules:
    from google.colab import drive
    drive.mount("/content/drive")
    checkpoint_dir = Path("/content/drive/MyDrive/14795-interproc-vuln-pairs/gpt-4.1-mini-c")
    checkpoint_dir.mkdir(parents=True, exist_ok=True)
    os.environ["PAIRED_CHECKPOINT_DIR"] = str(checkpoint_dir)
    incoming_dir = Path(".checkpoint_import")
    if incoming_dir.is_dir():
        import shutil
        for incoming in sorted(incoming_dir.glob("*.json")):
            target = checkpoint_dir / incoming.name
            if target.exists():
                if target.read_bytes() != incoming.read_bytes():
                    raise RuntimeError(f"Drive already has a different {target.name}; reconcile checkpoints before running paid requests.")
            else:
                temporary = target.with_suffix(".import.tmp")
                shutil.copyfile(incoming, temporary)
                os.replace(temporary, target)
        print("Imported the existing responses and budget ledger into Drive.")

os.environ["OPENAI_BASE_URL"] = "https://14795-resource.services.ai.azure.com/openai/v1"
os.environ["OPENAI_MODEL"] = "gpt-4.1-mini-1"
os.environ["OPENAI_MAX_CONCURRENCY"] = "32"

from repro import paired_eval
paired_rows = paired_eval.examples()
paired_estimate = paired_eval.estimate_cost(paired_rows)
print(paired_estimate)
print("Expected inputs:", len(paired_rows), "version-context prompts")
print("Review results/pair_spotcheck_30.csv before running the model.")
""")

md("""
Add `OPENAI_API_KEY` to Colab Secrets. The endpoint and deployment default to the Azure resource and `gpt-4.1-mini-1` supplied for this run; they can be overridden with `OPENAI_BASE_URL` and `OPENAI_MODEL`. The Responses API uses up to 32 parallel workers, paced below 200,000 estimated tokens per rolling minute. Transient 429, timeout, connection, and server errors retry up to 8 times with Retry-After-aware exponential backoff; successful responses are atomically checkpointed immediately. Azure billing is separate from a ChatGPT subscription. The $10 guard uses token usage, historical reference rates, and a 25% safety margin; it is an estimate rather than a guarantee of the Azure invoice.
""")

code("""
PAIRED_READY = False
if "google.colab" in sys.modules:
    if not paired_eval.get_api_key():
        from getpass import getpass
        os.environ["OPENAI_API_KEY"] = getpass("Azure API key (hidden; only held in this runtime): ")
    assert paired_eval.get_api_key(), "Configure the Azure API key before enabling the evaluation."
    assert str(paired_eval.CACHE).startswith("/content/drive/"), "Checkpoint must be on mounted Drive."
    assert paired_eval.MAX_COST_USD == 10.0
    print("Deployment:", paired_eval.get_model())
    print("Workers:", paired_eval.get_concurrency(), "TPM:", paired_eval.TPM_LIMIT)
    print("Budget:", paired_eval.MAX_COST_USD, "Checkpoint:", paired_eval.CACHE)
    print("Saved rows:", len(paired_eval.load_cache()))
    PAIRED_READY = True
    print("Configuration ready. No model requests were sent by this cell.")
else:
    print("Colab-only evaluation: model calls remain disabled in this local runtime.")
""")

code("""
RUN_PAIRED_API = False  # direct execution disabled; Drive control waits for verified readiness
if RUN_PAIRED_API:
    assert PAIRED_READY, "Complete the Colab configuration cell first."
    cache = paired_eval.run(paired_rows)
    paired_summary = paired_eval.summarize(paired_rows, cache)
elif PAIRED_READY:
    from repro.colab_control import serve
    paired_summary = serve(paired_rows)  # wait for this runtime's verified Drive start command
else:
    paired_summary = None
    print("API run disabled. No model requests were sent.")
""")

md("## Result: paper vs. ours, code-only (CO), all languages")

code("""
from IPython.display import Markdown
display(Markdown(open("results/headline_f1.md").read()))
if paired_summary:
    display(pd.DataFrame(paired_summary["context_metrics"]).T)
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
out.write_text(json.dumps(nb, indent=1, ensure_ascii=False) + "\n", encoding="utf-8", newline="\n")
print("wrote", out)

# GitHub-backed setup is the default. Embedded snapshots are opt-in only.
if not (args.bundle or args.with_checkpoint):
    sys.exit(0)

# Ship a current-code snapshot inside the uploadable notebook. This avoids a
# push to the shared repository and excludes credentials, caches and raw data.
archive = io.BytesIO()
with zipfile.ZipFile(archive, "w", compression=zipfile.ZIP_DEFLATED) as package:
    sources = [ROOT / "requirements.txt"]
    for folder in ("repro", "tests"):
        sources.extend(sorted((ROOT / folder).glob("*.py")))
    for source in sources:
        entry = zipfile.ZipInfo(source.relative_to(ROOT).as_posix(), date_time=(2026, 1, 1, 0, 0, 0))
        package.writestr(entry, source.read_bytes(), compress_type=zipfile.ZIP_DEFLATED)
    if args.with_checkpoint:
        for name in ("paired_eval_raw.json", "paired_eval_requests.json", "paired_eval_tpm.json"):
            checkpoint = ROOT / "results" / name
            if checkpoint.exists():
                entry = zipfile.ZipInfo(".checkpoint_import/" + name, date_time=(2026, 1, 1, 0, 0, 0))
                package.writestr(entry, checkpoint.read_bytes(), compress_type=zipfile.ZIP_DEFLATED)
payload = archive.getvalue()
digest = hashlib.sha256(payload).hexdigest()
encoded = base64.b64encode(payload).decode("ascii")
portable = json.loads(json.dumps(nb))
portable["cells"][1]["source"] = f'''# Current local code is bundled in this notebook; no GitHub push is needed.
import base64, hashlib, io, os, sys, subprocess, zipfile
from pathlib import Path

package_bytes = base64.b64decode({encoded!r})
assert hashlib.sha256(package_bytes).hexdigest() == {digest!r}
project_dir = Path("/content/interproc-vuln-pairs") if "google.colab" in sys.modules else Path.cwd()
project_dir.mkdir(parents=True, exist_ok=True)
with zipfile.ZipFile(io.BytesIO(package_bytes)) as package:
    package.extractall(project_dir)
os.chdir(project_dir)
sys.path.insert(0, str(project_dir))
if "google.colab" in sys.modules:
    subprocess.run([sys.executable, "-m", "pip", "install", "-q", "-r", "requirements.txt"], check=True)
print("Code snapshot:", {digest[:12]!r}, "repo root:", os.getcwd())
'''
portable_out = ROOT / "notebooks" / ("milestone_colab_resume.ipynb" if args.with_checkpoint else "milestone_colab_ready.ipynb")
portable_out.write_text(json.dumps(portable, indent=1, ensure_ascii=False) + "\n", encoding="utf-8")
print("wrote", portable_out)
