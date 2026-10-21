"""Build a self-contained, zero-inference recording notebook from frozen results.

Only reads existing result files and upstream labels; never imports a paid runner.
Run from the repository root: .venv/Scripts/python tools/make_cached_demo.py
"""
import base64
import csv
import hashlib
import io
import json
from pathlib import Path
import subprocess
import sys
import zipfile

import nbformat as nbf

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
from repro import cached_analysis as A
from repro import paper_values as P
from repro.data import cve_languages, load_all_outputs
from repro.paths import PROMPTS_DIR, SHIPPED_OUTPUTS, SWVULN_COMMIT, SWVULN_DIR
from repro.pairs import _function_rows, _after_context, _render_fixed_from_source


def read_json(path):
    return json.loads(path.read_text(encoding="utf-8"))


def write_csv(path, rows):
    fields = list(dict.fromkeys(key for row in rows for key in row))
    with path.open("w", newline="", encoding="utf-8-sig") as handle:
        writer = csv.DictWriter(handle, fieldnames=fields)
        writer.writeheader()
        writer.writerows(rows)


def build():
    final = ROOT / ".colab" / "final"
    cache = read_json(final / "paired_eval_raw.json")
    summary = read_json(final / "paired_eval_summary.json")
    ledger = read_json(final / "paired_eval_requests.json")
    commit = subprocess.check_output(["git", "-C", str(SWVULN_DIR), "rev-parse", "HEAD"], text=True).strip()
    assert commit == SWVULN_COMMIT
    paper = {"outputs": load_all_outputs(), "languages": cve_languages(),
             "accuracy_rows": [], "mcnemar_rows": []}
    for table, source, language in (("Table 5", P.TABLE5, None), ("Table 6", P.TABLE6, "C"),
                                    ("Table 7", P.TABLE7, "Python")):
        for (model, context), (n, tp, recall, f1) in source.items():
            paper["accuracy_rows"].append({"table": table, "model": model, "context": context,
                                           "language": language, "N": n, "TP": tp,
                                           "accuracy": recall, "F1": f1})
    for (model, comparison), expected in P.TABLE4.items():
        paper["mcnemar_rows"].append({"model": model, "comparison": comparison, **expected})
    with (ROOT / "results" / "pair_manifest.csv").open(encoding="utf-8-sig") as handle:
        manifest = [row for row in csv.DictReader(handle) if row["language"] == "C"]
    expected_keys = sorted(f"{row['cve']}|{ctx}|{version}" for row in manifest
                           for ctx in row["fixed_contexts_available"].split(",")
                           for version in ("vulnerable", "fixed"))
    audit = A.audit(cache, summary, ledger, expected_keys)
    pairs = A.pair_records(cache)
    metrics = A.context_metrics(pairs)
    reproduction = A.paper_reproduction(paper)
    assert len(reproduction) == 48 and all(x["match"] for x in reproduction)
    matched, matched_tests = A.matched_paper_comparison(pairs, paper)
    context_tests = A.context_tests(pairs)
    # Check source identity without invoking the runner or building any prompts.
    prompt_hash_matches = 0
    original_prompt_matches = 0
    names = {"CO": "prompt_vuln.txt", "CC": "prompt_vuln_callees.txt", "CK": "prompt_vuln_callers.txt"}
    raw_paths = list((SWVULN_DIR / "data" / "raw_cves").glob("*.json"))
    resolved_records = {}
    duplicate_sources = []
    for row in manifest:
        cve = row["cve"]
        paths = [p for p in raw_paths if p.stem == cve or p.stem.startswith(cve + "_")]
        matches = []
        for path in paths:
            record = read_json(path)
            target_fixed = [fixed if f.get("fixed_code_found") and fixed else vuln
                            for f, vuln, fixed in _function_rows(record)]
            good = True
            for ctx in row["fixed_contexts_available"].split(","):
                source = (PROMPTS_DIR / "c" / cve / names[ctx]).read_text(encoding="utf-8").strip()
                blocks = _after_context(record, "callees" if ctx == "CC" else "callers") if ctx != "CO" else []
                rendered = _render_fixed_from_source(source, ctx, target_fixed, blocks) + "\n"
                # Emulate Linux write/read_text universal-newline behavior.
                rendered = io.StringIO(rendered, newline=None).read().strip()
                digest_for_prompt = hashlib.sha256(rendered.encode()).hexdigest()
                if digest_for_prompt != cache[f"{cve}|{ctx}|fixed"]["prompt_sha256"]:
                    good = False
                    break
            if good:
                matches.append((path, record))
        assert matches, f"Cannot reconstruct actual Colab fixed prompts for {cve}"
        chosen_path, chosen = matches[0]
        resolved_records[cve] = chosen
        if len(paths) > 1:
            duplicate_sources.append({"cve": cve, "candidate_files": [p.name for p in paths],
                                      "matching_files": [p.name for p, _ in matches],
                                      "chosen_file": chosen_path.name})
    local_fixed_mismatches = []
    for key, item in cache.items():
        cve, ctx, version = key.split("|")
        path = SWVULN_DIR / "data" / "paired_prompts" / "c" / cve / f"{ctx}_{version}.txt"
        actual_hash = hashlib.sha256(path.read_text(encoding="utf-8").strip().encode()).hexdigest()
        if actual_hash != item["prompt_sha256"]:
            assert version == "fixed", key
            local_fixed_mismatches.append(key)
        # Every fixed hash was reconstructed from a matching raw record above;
        # do not mistake stale Windows-generated paired prompts for Colab input.
        prompt_hash_matches += 1
        if version == "vulnerable":
            source = PROMPTS_DIR / "c" / cve / names[ctx]
            assert hashlib.sha256(source.read_text(encoding="utf-8").strip().encode()).hexdigest() == actual_hash
            original_prompt_matches += 1
    affected = []
    for cve, record in resolved_records.items():
        function_rows = list(_function_rows(record))
        missing = sum(not f.get("fixed_code_found") for f, _, _ in function_rows)
        if missing:
            affected.append({"cve": cve, "fixed_code_missing_count": missing,
                             "target_function_count": len(function_rows)})
    affected_cves = {x["cve"] for x in affected}
    sensitivity = A.context_metrics([p for p in pairs if p["cve"] not in affected_cves])
    pilot_pairs = {(item["cve"], item["context"]) for item in cache.values()
                   if item["attempts"][-1].get("max_output_tokens", 400) == 400}
    strict_pairs = [p for p in pairs if (p["cve"], p["context"]) not in pilot_pairs]
    caps = {}
    for ctx in A.CONTEXTS:
        caps[ctx] = sum(item["context"] == ctx and item["attempts"][-1].get("max_output_tokens", 400) == 400
                        for item in cache.values())
    quality = {"expected_prompt_keys": len(expected_keys), "prompt_sha256_matches": prompt_hash_matches,
               "vulnerable_prompts_identical_to_authors": original_prompt_matches,
               "fixed_incomplete_cves": [{k: row[k] for k in ("cve", "fixed_code_missing_count", "target_function_count")}
                                          for row in affected],
               "manual_spotcheck": "30 pairs prepared; all remain unreviewed",
               "pilot_final_rows_by_context": caps,
               "local_fixed_prompt_hash_mismatches": local_fixed_mismatches,
               "duplicate_raw_record_resolution": duplicate_sources,
               "pilot_pair_exclusion_sensitivity": A.context_metrics(strict_pairs),
               "strict_protocol_context_tests": A.context_tests(strict_pairs),
               "fixed_incomplete_exclusion_sensitivity": sensitivity}
    # Frozen compact label projection: retain hashes of the original upstream files.
    provenance = {"paper": "https://arxiv.org/html/2604.08417v1", "commit": commit,
                  "upstream": "https://github.com/kevinwsbr/sw-vuln/tree/" + commit,
                  "completed_utc": "2026-10-20T10:40:13.740270+00:00",
                  "source_notebook": "https://colab.research.google.com/drive/1LSpFai-QVSNe5ceGlM2ALT5mK1HdlWgh",
                  "upstream_output_sha256": {p.name: hashlib.sha256(p.read_bytes()).hexdigest()
                                              for p in sorted(SHIPPED_OUTPUTS.glob("*.json"))},
                  "result_file_sha256": {p.name: hashlib.sha256(p.read_bytes()).hexdigest()
                                         for p in sorted(final.glob("*")) if p.is_file()},
                  "note": "Original shipped outputs reproduce published tables; paired labels are new inference."
                          " Initial 263 rows were migrated into Colab, not recomputed there."
                          " 24 final labels retain parsed 400-token pilot attempts; 1412 final labels use 4096."}
    examples = []
    for category in ("P-C", "P-V", "P-B", "P-R"):
        pair = next(x for x in pairs if x["context"] == "CO" and x["pair_category"] == category)
        cve = pair["cve"]
        example = dict(pair)
        for version in ("vulnerable", "fixed"):
            example[version + "_response"] = cache[f"{cve}|CO|{version}"]["attempts"][-1]["text"]
        examples.append(example)
    payload = {"cache": cache, "summary": summary, "ledger": ledger, "paper": paper,
               "expected_keys": expected_keys, "quality": quality, "provenance": provenance, "examples": examples}
    archive = io.BytesIO()
    with zipfile.ZipFile(archive, "w", compression=zipfile.ZIP_DEFLATED) as package:
        for name, content in (("frozen_results.json", json.dumps(payload, ensure_ascii=False)),
                              ("cached_analysis.py", (ROOT / "repro" / "cached_analysis.py").read_text(encoding="utf-8"))):
            info = zipfile.ZipInfo(name, date_time=(2026, 10, 20, 0, 0, 0))
            package.writestr(info, content, compress_type=zipfile.ZIP_DEFLATED)
    raw = archive.getvalue()
    digest = hashlib.sha256(raw).hexdigest()
    encoded = base64.b64encode(raw).decode("ascii")
    cells = []
    def md(source):
        cells.append(nbf.v4.new_markdown_cell(source))
    def code(source):
        cells.append(nbf.v4.new_code_cell(source.strip()))
    md("""# 14-795 milestone: cached-results recording demo
**Siwei Tan · Justun Gao · Mengchao Ren — 20 October 2026**

## Goal / 录制说明
Recompute the original paper tables and inspect our completed **C-only vulnerable/fixed extension**.
This is an honest **cached-results replay**, not fresh model inference.

**使用：连接一个免费 CPU runtime → 代码执行程序 / Runtime → 全部运行 / Run all。**
No API key, Drive mount, run ID, git clone or package installation is required. All completed
results and the calculation code are embedded in this notebook. It neither reads your secrets
nor imports/executes the inference runner. Re-running it makes **zero additional model calls**.

The original run is complete: 1,436 predictions, 0 unparsed, cost estimate $4.7898 including
historical attempts and a 25% safety margin (not an Azure invoice). Do not rerun the old paid notebook.
""")
    md("## 1. Setup — load the frozen snapshot in memory")
    code(f'''#@title Load saved results — offline replay, no API calls
import base64, hashlib, io, json, types, zipfile
import pandas as pd
from IPython.display import display, Markdown

API_CALLS_ALLOWED = False
assert API_CALLS_ALLOWED is False
payload_bytes = base64.b64decode({encoded!r})
assert hashlib.sha256(payload_bytes).hexdigest() == {digest!r}
with zipfile.ZipFile(io.BytesIO(payload_bytes)) as bundle:
    frozen = json.loads(bundle.read("frozen_results.json"))
    analysis_source = bundle.read("cached_analysis.py").decode("utf-8")
analysis = types.ModuleType("cached_results_analysis")
exec(compile(analysis_source, "cached_analysis.py", "exec"), analysis.__dict__)
cache, summary, paper = frozen["cache"], frozen["summary"], frozen["paper"]
print("Mode: CACHED REPLAY | Additional model requests: 0 | API key: not needed")
print("Paper replication commit:", frozen["provenance"]["commit"])
print("Finished experiment (UTC):", frozen["provenance"]["completed_utc"])
print("Bundle SHA-256:", {digest!r})''')
    cells[-1].metadata["cellView"] = "form"
    md("""## 2. Checks — result integrity and definitions
Unit: **one CVE × context × version**, not one individual function. 343 C CVEs have
both original and recovered fixed-version prompts: CO=343, CC=196, CK=179 pairs,
718 context-specific pairs / 1,436 predictions. The same CVE can appear in several contexts.

CO = target code only; CC = code + callees; CK = code + callers.
The patched version is a **candidate negative**, not a manually certified vulnerability-free program.
""")
    code('''audit = analysis.audit(cache, summary, frozen["ledger"], frozen["expected_keys"])
pairs = analysis.pair_records(cache)
metrics = analysis.context_metrics(pairs)
display(pd.DataFrame([audit]).T.rename(columns={0: "value"}))
assert frozen["quality"]["prompt_sha256_matches"] == 1436
assert frozen["quality"]["vulnerable_prompts_identical_to_authors"] == 718
print("All 1436 prompt hashes match; all 718 vulnerable prompts match the authors' originals.")''')
    md("""## 3. Original-paper reproduction — not new API results
First, recompute Tables 4–7 from the authors' **shipped prediction labels**, frozen at
the cited commit. This verifies numerical reproduction; it does not mean we called four models again.
Accuracy tables exclude unparsed labels to match the original paper. Table 4 deliberately
reproduces the authors' published conventions; new paired tests below use exact McNemar + step-down Holm.
""")
    code('''reproduced = pd.DataFrame(analysis.paper_reproduction(paper))
assert len(reproduced) == 48 and reproduced["match"].all()
display(reproduced.groupby("table").agg(rows=("match", "size"), matching=("match", "sum")))
display(reproduced[(reproduced["table"] == "Table 6") & (reproduced["model"] == "GPT-4.1 Mini")]
        .dropna(axis=1, how="all").round(4))
print("48/48 published rows match to the paper's printed precision.")''')
    md("""## 4. Compare like with like — vulnerable recall on matched CVEs
The paper has only positive examples: **accuracy = recall**, precision=1 by construction,
and F1=2R/(1+R). Its F1 is **not directly comparable** with our balanced vulnerable/fixed F1.
The published C sets (356/204/189) also differ from our recoverable-patch sets (343/196/179).
Compare the old and new vulnerable predictions on the **same CVEs** below; do not attribute
their differences solely to adding negative examples, because these are separate API executions.
""")
    code('''matched_rows, shipped_tests = analysis.matched_paper_comparison(pairs, paper)
display(pd.DataFrame(matched_rows).round(4))
display(pd.DataFrame(shipped_tests).round(6))
print("Tests: exact McNemar on the same vulnerable CVEs; Holm family = three contexts.")''')
    md("""## 5. New result — false positives and paired discrimination
Ground truth assumption: vulnerable=1, recovered fixed=0. FPR=FP/(FP+TN),
balanced F1=2TP/(2TP+FP+FN), pair-correct rate=P(pred(vulnerable)=1 AND pred(fixed)=0).

P-C=(1,0), correct pair; P-V=(1,1), both flagged; P-B=(0,0), both cleared;
P-R=(0,1), reversed pair. These categories sum to the context's pair count.
""")
    code('''metric_table = pd.DataFrame(metrics)
display(metric_table[["context", "pairs", "recall", "precision", "fpr",
                      "F1_balanced", "accuracy_balanced", "pair_correct_rate"]].round(4))
display(metric_table[["context", "TP", "FN", "FP", "TN"]])
display(metric_table[["context", "P-C", "P-V", "P-B", "P-R"]])
display(pd.DataFrame([{"baseline": "Always predict vulnerable (balanced labels)",
                       "recall": 1.0, "fpr": 1.0, "accuracy_balanced": .5,
                       "F1_balanced": 2/3, "pair_correct_rate": 0.0}]).round(4))
print("F1 alone is not enough: an always-vulnerable predictor has F1=0.667 but pair correctness=0.")''')
    md("""## 6. Does context help? — shared-CVE comparisons only
Context sets are different. Compare CO/CC/CK only on their shared CVEs, with one
CVE as the paired unit. Two prespecified test families (3 tests each): vulnerable recall
and pair correctness. Exact McNemar, Holm-adjusted p-values; exploratory single-run results.
""")
    code('''context_test_rows = analysis.context_tests(pairs)
display(pd.DataFrame(context_test_rows).round(6))''')
    md("""## 7. Quality caveats and sensitivity
**Do not hide these in the video:** 30 manual review pairs remain unreviewed.
Two target functions have no recovered fixed code; the builder retains their original
code inside candidate-negative prompts. The table identifies affected CVEs, followed by
an exclusion sensitivity analysis. This weak-label issue prevents a definitive claim
that every flagged fixed version is a genuine false alarm.

24 final parsed labels from the initial 400-token pilot were retained; the remaining 1,412
final labels use 4,096. All history stays in the $4.7898 estimate. Azure reports only the
deployment name, so an exact immutable model-version match to the paper is not established.
The initial 263 predictions were migrated from the earlier run; the remainder resumed in Colab.

The raw dataset also contains duplicate CVE JSON records. The old builder selected the last
record in filesystem enumeration order; eight local fixed-prompt hashes differ from the
actual Colab inputs (three CVEs). Here each Colab prompt hash is reconstructed from a matching
source record, and the chosen file is frozen below. No predictions are replaced or regenerated.
""")
    code('''display(pd.DataFrame(frozen["quality"]["fixed_incomplete_cves"]))
excluded = {x["cve"] for x in frozen["quality"]["fixed_incomplete_cves"]}
sensitivity = analysis.context_metrics([p for p in pairs if p["cve"] not in excluded])
display(pd.DataFrame(sensitivity)[["context", "pairs", "recall", "fpr", "F1_balanced", "pair_correct_rate"]].round(4))
print("Final labels retained from 400-token pilot by context:", frozen["quality"]["pilot_final_rows_by_context"])
print("Manual-review status:", frozen["quality"]["manual_spotcheck"])
print("Sensitivity excluding any pair with a retained 400-token label:")
display(pd.DataFrame(frozen["quality"]["pilot_pair_exclusion_sensitivity"])
        [["context", "pairs", "recall", "fpr", "F1_balanced", "pair_correct_rate"]].round(4))
print("Duplicate-record source resolution (CVE + selected raw JSON file):")
display(pd.DataFrame(frozen["quality"]["duplicate_raw_record_resolution"])
        [["cve", "chosen_file", "matching_files"]])''')
    md("## 8. Inspect saved examples — explanations are model output, not verified ground truth")
    code('''for example in frozen["examples"]:
    display(Markdown(f"### {example['cve']} / CO / {example['pair_category']}"))
    for version in ("vulnerable", "fixed"):
        print(version, "prediction:", example[version + "_prediction"])
        print(example[version + "_response"][-900:])
        print()''')
    md("""## 9. Takeaways / 视频讲解重点
1. **Original tables reproduced**: 48/48 numerical rows match from the shipped labels.
2. **New experiment adds missing negatives**: fixed-version false-alarm rates are substantial;
   only a minority of pairs are correctly distinguished. Original positive-only F1 could not measure this.
3. **No direct F1 subtraction**: tasks and populations differ. Use matched-vulnerable recall,
   balanced metrics, and shared-CVE context tests as separate evidence.
4. **Share with caveats**: one model, C only, single run, candidate negatives need manual review,
   retained pilot labels and non-immutable deployment identity. This is not proof about all LLMs.

### Why did the old result cell fail?
After Colab disconnected, its temporary `/content` filesystem and Python variables were reset.
The original display cell used relative `open("results/headline_f1.md")`, which is generated
by an earlier analysis cell, not the Drive checkpoint. Running that display cell first (execution
count `[1]`) raised `FileNotFoundError`. After that, `paired_summary` / `pd` would also be undefined.
This notebook instead loads every required input in section 1 and computes tables in memory.
If you reconnect, simply use **Run all**; no paid run, Drive restoration or agent start is involved.

### Recording script (about 5 minutes)
- 0:00 — goal, paper citation, clearly say “cached results; no new API calls”.
- 0:30 — Run all on a CPU runtime; show 1,436-row integrity checks and 48/48 original-table matches.
- 1:30 — distinguish original recall/F1 from the balanced extension; show matched CVEs.
- 2:30 — explain FPR and four pair outcomes; show the actual metric table.
- 3:30 — shared-CVE context tests, one or two saved examples, and caveats.
- 4:30 — cost estimate, persisted provenance, and reproducibility conclusion.

### Sources / provenance
- [Paper v1, Sections 3.2–3.4, Tables 4–7, and validity threats](https://arxiv.org/html/2604.08417v1)
- [Pinned replication package](https://github.com/kevinwsbr/sw-vuln/tree/46796d168daf865331b1ca15d763d2e6746bf5a5)
- [Completed inference notebook](https://colab.research.google.com/drive/1LSpFai-QVSNe5ceGlM2ALT5mK1HdlWgh)
- [Frozen final metrics](https://drive.google.com/file/d/1j3yMbjT0ESwZMJzdmTu-ulgPTF_6u5Am/view)

The bundle verifies SHA-256 on load and records the upstream and result file hashes below.
""")
    code('''display(pd.DataFrame([{ "source_file": name, "sha256": digest }
                      for name, digest in frozen["provenance"]["result_file_sha256"].items()]))
assert API_CALLS_ALLOWED is False
print("REPLAY COMPLETE — additional model calls: 0; no credentials were read.")''')
    nb = nbf.v4.new_notebook(cells=cells, metadata={
        "colab": {"provenance": [], "name": "14795_cached_results_video.ipynb"},
        "kernelspec": {"display_name": "Python 3", "language": "python", "name": "python3"},
        "language_info": {"name": "python"}})
    for i, cell in enumerate(nb.cells):
        cell.id = f"replay-{i:02d}"
    nbf.validate(nb)
    dest = ROOT / "notebooks" / "milestone_colab_cached_video.ipynb"
    nbf.write(nb, dest)
    results = ROOT / "results"
    for name, rows in (("paired_context_metrics_final.csv", metrics), ("paired_matched_paper_comparison.csv", matched),
                       ("paired_matched_tests.csv", matched_tests), ("paired_context_tests.csv", context_tests),
                       ("paired_negative_sensitivity.csv", sensitivity), ("paper_reproduction_final.csv", reproduction)):
        write_csv(results / name, rows)
    report = {"audit": audit, "quality": quality, "context_metrics": metrics,
              "matched_comparison": matched, "matched_tests": matched_tests,
              "context_tests": context_tests, "provenance": provenance,
              "validation": "Share with caveats; calculations checked, fixed-label manual review incomplete."}
    (results / "paired_cached_analysis.json").write_text(json.dumps(report, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
    print(json.dumps({"notebook": str(dest), "notebook_bytes": dest.stat().st_size,
                      "audit": audit, "metrics": metrics, "matched": matched,
                      "context_tests": context_tests, "quality": quality}, indent=2))


if __name__ == "__main__":
    build()
