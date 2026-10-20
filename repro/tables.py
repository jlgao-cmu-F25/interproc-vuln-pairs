"""Recompute Tables 4-7 from the shipped outputs and compare them with the paper.

    python -m repro.tables

Writes results/table{4,5,6,7}_ours_vs_paper.csv, results/headline_f1.md,
results/mismatches.csv and prints a summary.
"""
import pandas as pd

from . import paper_values as P
from .data import LANGUAGE_DIRS, cve_languages, load_all_outputs
from .metrics import accuracy, holm, mcnemar
from .paths import RESULTS_DIR

# Tolerances: the paper prints 4 decimals for rates and 3 for chi2/phi.
TOL_4DP = 0.5e-4 + 1e-9
TOL_3DP = 0.5e-3 + 1e-9


def accuracy_table(outputs, langs, language=None):
    rows = []
    for model in P.MODELS:
        for ctx in P.CONTEXTS:
            labels = [rec[ctx] for cve, rec in outputs[model].items() if language is None or langs.get(cve) == language]
            a = accuracy(labels)
            rows.append(dict(model=model, context=ctx, N=a.n, TP=a.tp, accuracy=a.accuracy, F1=a.f1))
    return pd.DataFrame(rows)


def mcnemar_table(outputs, langs=None, language=None):
    rows, tests = [], []
    for model in P.MODELS:
        for c1, c2 in P.COMPARISONS:
            pairs = [
                (rec[c1], rec[c2])
                for cve, rec in outputs[model].items()
                if rec[c1] is not None and rec[c2] is not None and (language is None or langs.get(cve) == language)
            ]
            t = mcnemar(pairs)
            tests.append(t)
            rows.append(dict(model=model, comparison=f"{c1}-{c2}"))
    holm(tests)
    for row, t in zip(rows, tests):
        row.update(N=t.n, a=t.a, b=t.b, c=t.c, d=t.d, chi2=t.chi2, p=t.p, alpha=t.alpha, sig=t.sig,
                   acc1=t.acc1, acc2=t.acc2, phi=t.phi, effect=t.effect)
    return pd.DataFrame(rows)


def compare_accuracy(ours, paper, table):
    rows, mismatches = [], []
    for _, r in ours.iterrows():
        pn, ptp, pacc, pf1 = paper[(r.model, r.context)]
        row = dict(model=r.model, context=r.context,
                   N_paper=pn, N_ours=r.N, TP_paper=ptp, TP_ours=r.TP,
                   acc_paper=pacc, acc_ours=round(r.accuracy, 4), F1_paper=pf1, F1_ours=round(r.F1, 4))
        checks = {
            "N": r.N == pn,
            "TP": r.TP == ptp,
            "accuracy": abs(r.accuracy - pacc) <= TOL_4DP,
            "F1": abs(r.F1 - pf1) <= TOL_4DP,
        }
        row["match"] = all(checks.values())
        rows.append(row)
        for field, ok in checks.items():
            if not ok:
                pv, ov = {"N": (pn, r.N), "TP": (ptp, r.TP), "accuracy": (pacc, r.accuracy), "F1": (pf1, r.F1)}[field]
                mismatches.append(dict(table=table, model=r.model, cell=r.context, field=field, paper=pv, ours=ov))
    return pd.DataFrame(rows), mismatches


def compare_mcnemar(ours):
    rows, mismatches = [], []
    for _, r in ours.iterrows():
        p = P.TABLE4[(r.model, r.comparison)]
        checks = {
            "N": (p["n"], r.N, r.N == p["n"]),
            "chi2": (p["chi2"], r.chi2, abs(r.chi2 - p["chi2"]) <= TOL_3DP),
            "p": (p["p"], r.p, abs(r.p - p["p"]) <= TOL_4DP),
            "alpha": (p["alpha"], r.alpha, abs(r.alpha - p["alpha"]) <= TOL_4DP),
            "sig": (p["sig"], r.sig, bool(r.sig) == p["sig"]),
            "acc1": (p["acc1"], r.acc1, abs(r.acc1 - p["acc1"]) <= TOL_4DP),
            "acc2": (p["acc2"], r.acc2, abs(r.acc2 - p["acc2"]) <= TOL_4DP),
            "phi": (p["phi"], r.phi, abs(r.phi - p["phi"]) <= TOL_3DP),
            "effect": (p["effect"], r.effect, r.effect == p["effect"]),
        }
        row = dict(model=r.model, comparison=r.comparison)
        for k, (pv, ov, _) in checks.items():
            row[f"{k}_paper"] = pv
            row[f"{k}_ours"] = round(ov, 4) if isinstance(ov, float) else ov
        row["match"] = all(ok for _, _, ok in checks.values())
        rows.append(row)
        for k, (pv, ov, ok) in checks.items():
            if not ok:
                mismatches.append(dict(table="Table 4 (McNemar)", model=r.model, cell=r.comparison, field=k, paper=pv, ours=ov))
    return pd.DataFrame(rows), mismatches


def headline(ours5):
    """The CO F1 table promised for the milestone demo (paper rounds to 3 decimals)."""
    lines = ["| Model | F1 (paper) | F1 (ours) | Match |", "|---|---|---|---|"]
    for model in P.MODELS:
        pf1 = P.TABLE5[(model, "CO")][3]
        of1 = ours5[(ours5.model == model) & (ours5.context == "CO")].F1.iloc[0]
        ok = abs(of1 - pf1) <= TOL_4DP
        lines.append(f"| {model} | {pf1:.3f} | {of1:.3f} | {'yes' if ok else 'NO'} |")
    return "\n".join(lines) + "\n"


def run(write=True):
    outputs = load_all_outputs()
    langs = cve_languages()
    results, mismatches = {}, []

    for name, (paper, language) in P.ACCURACY_TABLES.items():
        ours = accuracy_table(outputs, langs, language)
        cmp, mm = compare_accuracy(ours, paper, name)
        results[name] = cmp
        mismatches += mm

    t4 = mcnemar_table(outputs)
    cmp4, mm4 = compare_mcnemar(t4)
    results["Table 4 (McNemar)"] = cmp4
    mismatches += mm4

    # C++ is not tabulated in the paper (Sec. 4.2); reported descriptively.
    results["C++ (not in paper)"] = accuracy_table(outputs, langs, "C++")
    mm_df = pd.DataFrame(mismatches, columns=["table", "model", "cell", "field", "paper", "ours"])

    if write:
        RESULTS_DIR.mkdir(exist_ok=True)
        results["Table 4 (McNemar)"].to_csv(RESULTS_DIR / "table4_ours_vs_paper.csv", index=False)
        results["Table 5 (all)"].to_csv(RESULTS_DIR / "table5_ours_vs_paper.csv", index=False)
        results["Table 6 (C)"].to_csv(RESULTS_DIR / "table6_ours_vs_paper.csv", index=False)
        results["Table 7 (Python)"].to_csv(RESULTS_DIR / "table7_ours_vs_paper.csv", index=False)
        results["C++ (not in paper)"].round(4).to_csv(RESULTS_DIR / "cpp_ours.csv", index=False)
        t4.round(4).to_csv(RESULTS_DIR / "table4_full_contingency.csv", index=False)
        mm_df.to_csv(RESULTS_DIR / "mismatches.csv", index=False)
        (RESULTS_DIR / "headline_f1.md").write_text(headline(accuracy_table(outputs, langs)), encoding="utf-8")
    return results, mm_df


def main():
    pd.set_option("display.width", 200, "display.max_columns", 40)
    results, mm = run()
    for name, df in results.items():
        print(f"\n=== {name} ===")
        print(df.to_string(index=False))
    total = sum(len(df) for name, df in results.items() if "match" in df)
    bad = sum((~df.match).sum() for name, df in results.items() if "match" in df)
    print(f"\n{total - bad}/{total} table rows match the paper; {len(mm)} mismatching cells (see results/mismatches.csv)")
    if len(mm):
        print(mm.to_string(index=False))


if __name__ == "__main__":
    main()
