"""Consistency checks behind docs/discrepancy_log.md.

    python -m repro.checks
"""
import json
from collections import Counter

import pandas as pd

from . import paper_values as P
from .data import cve_languages, load_all_outputs, shipped_language_map
from .metrics import accuracy
from .paths import PROMPTS_DIR, RESULTS_DIR, SHIPPED_OUTPUTS
from .tables import mcnemar_table

SHIPPED_MODEL_NAMES = {"Gemini 3.0 Flash": "Gemini 3 Flash"}


def coverage(outputs, langs):
    """How many CVEs exist per language and how many each model answered."""
    prompt_counts = {d.name: sum(1 for x in d.iterdir() if x.is_dir()) for d in PROMPTS_DIR.iterdir() if d.is_dir()}
    evaluated = Counter(langs.get(c, "unknown") for c in outputs["Claude Haiku 4.5"])
    return prompt_counts, dict(evaluated)


def language_map_agreement(langs):
    shipped = shipped_language_map()
    disagree = {c: (l, shipped.get(c)) for c, l in langs.items() if shipped.get(c) != l}
    return disagree


def unparsed_counts(outputs):
    """None labels per model x context, split into 'context not generated' vs 'no CLASSIFICATION parsed'."""
    haiku = outputs["Claude Haiku 4.5"]
    rows = []
    for model in P.MODELS:
        for ctx in P.CONTEXTS:
            nones = [c for c, r in outputs[model].items() if r[ctx] is None]
            # A context exists for a CVE iff its prompt file exists.
            no_prompt = 0
            for c in nones:
                files = {"CO": "prompt_vuln.txt", "CC": "prompt_vuln_callees.txt", "CK": "prompt_vuln_callers.txt"}
                if not any((PROMPTS_DIR / f / c / files[ctx]).exists() for f in ("c", "cpp", "python")):
                    no_prompt += 1
            rows.append(dict(model=model, context=ctx, none=len(nones), no_prompt=no_prompt, unparsed=len(nones) - no_prompt))
    return pd.DataFrame(rows)


def none_as_wrong(outputs, langs):
    """Sensitivity: accuracy if an unparsed answer counts as a miss (our protocol from the proposal)."""
    rows = []
    files = {"CO": "prompt_vuln.txt", "CC": "prompt_vuln_callees.txt", "CK": "prompt_vuln_callers.txt"}
    for model in P.MODELS:
        for ctx in P.CONTEXTS:
            labels = []
            for c, r in outputs[model].items():
                folder = {"C": "c", "C++": "cpp", "Python": "python"}[langs[c]]
                if not (PROMPTS_DIR / folder / c / files[ctx]).exists():
                    continue
                labels.append(r[ctx] if r[ctx] is not None else 0)
            a = accuracy(labels)
            paper = P.TABLE5[(model, ctx)]
            rows.append(dict(model=model, context=ctx, N_paper=paper[0], acc_paper=paper[2],
                             N_prompts=a.n, acc_none_as_wrong=round(a.accuracy, 4), F1_none_as_wrong=round(a.f1, 4)))
    return pd.DataFrame(rows)


def language_mcnemar_vs_shipped(outputs, langs):
    """Recompute per-language McNemar and diff it against the shipped mcnemar_by_language.json."""
    shipped = json.loads((SHIPPED_OUTPUTS / "mcnemar_by_language.json").read_text(encoding="utf-8"))
    ours = {}
    for lang in ("C", "C++", "Python"):
        t = mcnemar_table(outputs, langs, lang)
        for _, r in t.iterrows():
            ours[(lang, r.model, r.comparison)] = r
    rows = []
    for s in shipped:
        model = SHIPPED_MODEL_NAMES.get(s["model"], s["model"])
        key = (s["language"], model, s["comparison"].replace(" vs ", "-"))
        o = ours.get(key)
        if o is None:
            rows.append(dict(language=key[0], model=model, comparison=key[2], issue="not recomputed"))
            continue
        diffs = []
        for f_s, f_o, tol in [("n", "N", 0), ("b", "b", 0), ("c", "c", 0), ("chi2", "chi2", 1e-6),
                              ("p_value", "p", 1e-6), ("phi", "phi", 1e-6), ("alpha_corrected", "alpha", 1e-9)]:
            sv, ov = s[f_s], o[f_o]
            if sv is None or (isinstance(sv, float) and sv != sv):
                continue
            if abs(float(sv) - float(ov)) > tol:
                diffs.append(f"{f_s}: shipped {sv:.4g} vs ours {ov:.4g}")
        if bool(s["is_significant"]) != bool(o.sig):
            diffs.append(f"sig: shipped {s['is_significant']} vs ours {o.sig}")
        rows.append(dict(language=key[0], model=model, comparison=key[2], n=o.N,
                         p=round(o.p, 4), sig=bool(o.sig), issue="; ".join(diffs) or "match"))
    return pd.DataFrame(rows)


def main():
    pd.set_option("display.width", 200, "display.max_columns", 30, "display.max_colwidth", 120)
    outputs = load_all_outputs()
    langs = cve_languages()

    prompts, evaluated = coverage(outputs, langs)
    print("Prompt folders per language:", prompts)
    print("CVEs present in the model output files:", evaluated, "total", sum(evaluated.values()))
    print("Language map disagreements (prompt folder vs cve_languages.json):", language_map_agreement(langs) or "none")

    u = unparsed_counts(outputs)
    print("\nNone labels per model x context:\n", u.to_string(index=False))
    s = none_as_wrong(outputs, langs)
    print("\nSensitivity, unparsed answer = miss:\n", s.to_string(index=False))
    lm = language_mcnemar_vs_shipped(outputs, langs)
    print("\nPer-language McNemar vs shipped mcnemar_by_language.json:\n", lm.to_string(index=False))

    RESULTS_DIR.mkdir(exist_ok=True)
    u.to_csv(RESULTS_DIR / "unparsed_counts.csv", index=False)
    s.to_csv(RESULTS_DIR / "sensitivity_none_as_wrong.csv", index=False)
    lm.to_csv(RESULTS_DIR / "mcnemar_by_language_check.csv", index=False)


if __name__ == "__main__":
    main()
