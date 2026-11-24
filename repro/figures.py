"""Static figures for the final analysis (notebook + slides), from results/final/*.csv.

    python -m repro.figures            # writes results/final/figures/*.png

Colours: validated categorical slots (blue, orange, aqua) on a #fcfcfb surface,
plus a neutral grey for the residual category. Every bar carries a value label,
so identity never depends on colour alone.
"""
import csv
from pathlib import Path

from . import paper_values as P
from .paths import RESULTS_DIR

FINAL = RESULTS_DIR / "final"
OUT = FINAL / "figures"
MODELS = ("Claude Haiku 4.5", "Gemini 3 Flash", "GPT-5 Mini", "GPT-4.1 Mini")
CONTEXTS = ("CO", "CC", "CK")
SURFACE, INK, INK2, GRID = "#fcfcfb", "#0b0b0b", "#52514e", "#e4e3df"
BLUE, ORANGE, AQUA, GREY = "#2a78d6", "#eb6834", "#1baf7a", "#a8a7a0"


def _read(path):
    with open(path, encoding="utf-8-sig") as handle:
        return list(csv.DictReader(handle))


def load_rq1():
    """{(model, context): metrics}; GPT-4.1 Mini from the milestone aggregates (no CIs)."""
    rows = {(r["model"], r["context"]): {k: _num(v) for k, v in r.items()} for r in _read(FINAL / "rq1_paired_metrics.csv")}
    for r in _read(RESULTS_DIR / "paired_context_metrics_final.csv"):
        n = int(r["pairs"])
        rows[("GPT-4.1 Mini", r["context"])] = {
            "model": "GPT-4.1 Mini", "context": r["context"], "pairs": n,
            "recall": float(r["recall"]), "precision": float(r["precision"]), "fpr": float(r["fpr"]),
            "P-C_rate": int(r["P-C"]) / n, "P-V_rate": int(r["P-V"]) / n,
            "P-B_rate": int(r["P-B"]) / n, "P-R_rate": int(r["P-R"]) / n,
            "TP": int(r["TP"]), "FN": int(r["FN"]), "FP": int(r["FP"]), "TN": int(r["TN"]),
            "F1_paired": float(r["F1_balanced"]),
            "paper_C_F1": P.TABLE6[("GPT-4.1 Mini", r["context"])][3]}
    return rows


def _num(value):
    try:
        return float(value)
    except (TypeError, ValueError):
        return value


def _style(ax):
    ax.set_facecolor(SURFACE)
    for side in ("top", "right"):
        ax.spines[side].set_visible(False)
    for side in ("left", "bottom"):
        ax.spines[side].set_color(GRID)
    ax.tick_params(colors=INK2, labelsize=10, length=0)
    ax.yaxis.grid(True, color=GRID, linewidth=0.8)
    ax.set_axisbelow(True)


def _figure(width, height):
    import matplotlib
    matplotlib.use("Agg")
    import matplotlib.pyplot as plt
    plt.rcParams.update({"font.family": "sans-serif", "font.sans-serif": ["Arial", "Liberation Sans", "Helvetica", "DejaVu Sans"], "font.size": 11})
    return plt


def fig_headline(rows, path):
    """CO: the paper's vulnerable-only F1 next to what the fixed version reveals."""
    plt = _figure(10, 4.6)
    fig, ax = plt.subplots(figsize=(10, 4.6), facecolor=SURFACE)
    _style(ax)
    series = (("Paper F1 (vulnerable code only)", "paper_C_F1", BLUE),
              ("False-alarm rate on fixed code", "fpr", ORANGE),
              ("Both versions right (P-C)", "P-C_rate", AQUA))
    width = 0.26
    for i, (label, key, colour) in enumerate(series):
        xs = [m + (i - 1) * (width + 0.02) for m in range(len(MODELS))]
        values = [rows[(model, "CO")][key] for model in MODELS]
        bars = ax.bar(xs, values, width - 0.02, color=colour, label=label, linewidth=0)
        for bar, value in zip(bars, values):
            ax.text(bar.get_x() + bar.get_width() / 2, value + 0.015, f"{value:.0%}" if key != "paper_C_F1" else f"{value:.2f}",
                    ha="center", va="bottom", fontsize=9.5, color=INK)
    ax.set_xticks(range(len(MODELS)), MODELS, fontsize=11, color=INK)
    ax.set_ylim(0, 1.12)
    ax.set_yticks([0, 0.25, 0.5, 0.75, 1.0], ["0", "25%", "50%", "75%", "100%"])
    ax.legend(loc="upper center", bbox_to_anchor=(0.5, -0.1), ncol=3, frameon=False, fontsize=10, labelcolor=INK2)
    fig.tight_layout()
    fig.savefig(path, dpi=200, facecolor=SURFACE)
    plt.close(fig)


def fig_context(rows, path):
    """False-alarm rate on fixed code by context, one panel per model, 95% bootstrap CIs."""
    plt = _figure(10, 3.6)
    fig, axes = plt.subplots(1, 4, figsize=(10, 3.6), sharey=True, facecolor=SURFACE)
    for ax, model in zip(axes, MODELS):
        _style(ax)
        values = [rows[(model, c)]["fpr"] for c in CONTEXTS]
        lo = [rows[(model, c)].get("fpr_lo") for c in CONTEXTS]
        hi = [rows[(model, c)].get("fpr_hi") for c in CONTEXTS]
        if lo[0] is not None:
            ax.errorbar(range(3), values, yerr=[[v - l for v, l in zip(values, lo)], [h - v for v, h in zip(values, hi)]],
                        fmt="none", ecolor=GREY, elinewidth=1.5, capsize=0)
        ax.plot(range(3), values, color=BLUE, linewidth=2, marker="o", markersize=8,
                markeredgecolor=SURFACE, markeredgewidth=2)
        for x, (v, h) in enumerate(zip(values, hi)):
            top = h if h is not None else v
            ax.text(x, top + 0.02, f"{v:.0%}", va="bottom", ha="center", fontsize=9.5, color=INK)
        ax.set_xticks(range(3), CONTEXTS, color=INK)
        ax.set_xlim(-0.4, 2.6)
        ax.set_title(model + ("*" if lo[0] is None else ""), fontsize=11, color=INK)
    axes[0].set_ylim(0.3, 1.06)
    axes[0].set_yticks([0.4, 0.6, 0.8, 1.0], ["40%", "60%", "80%", "100%"])
    fig.tight_layout()
    fig.savefig(path, dpi=200, facecolor=SURFACE)
    plt.close(fig)


def fig_outcomes(rows, path):
    """CO pair outcomes per model: both right / both flagged / both cleared / reversed."""
    plt = _figure(10, 3.4)
    fig, ax = plt.subplots(figsize=(10, 3.4), facecolor=SURFACE)
    _style(ax)
    ax.yaxis.grid(False)
    ax.xaxis.grid(True, color=GRID, linewidth=0.8)
    cats = (("Both right (P-C)", "P-C_rate", BLUE), ("Both flagged (P-V)", "P-V_rate", ORANGE),
            ("Both cleared (P-B)", "P-B_rate", AQUA), ("Reversed (P-R)", "P-R_rate", GREY))
    order = list(reversed(MODELS))
    left = [0.0] * len(order)
    for label, key, colour in cats:
        values = [rows[(m, "CO")][key] for m in order]
        ax.barh(range(len(order)), values, left=left, color=colour, label=label, edgecolor=SURFACE, linewidth=1.5, height=0.62)
        for y, (v, l) in enumerate(zip(values, left)):
            if v >= 0.06:
                ax.text(l + v / 2, y, f"{v:.0%}", ha="center", va="center", fontsize=9.5,
                        color="white" if colour in (BLUE,) else INK)
        left = [l + v for l, v in zip(left, values)]
    ax.set_yticks(range(len(order)), order, color=INK)
    ax.set_xlim(0, 1)
    ax.set_xticks([0, 0.25, 0.5, 0.75, 1], ["0", "25%", "50%", "75%", "100%"])
    ax.legend(loc="upper center", bbox_to_anchor=(0.45, -0.12), ncol=4, frameon=False, fontsize=10, labelcolor=INK2)
    fig.tight_layout()
    fig.savefig(path, dpi=200, facecolor=SURFACE)
    plt.close(fig)


def fig_labels(path):
    """Manual labels of 8 sampled CO false alarms per model."""
    rows = _read(FINAL / "false_alarm_labels.csv")
    models = [m for m in MODELS if any(r["model"] == m for r in rows)]
    cats = (("Points at the patched lines, calls fix insufficient", "patched_code_fix_insufficient", ORANGE),
            ("Specific claim about other code", "specific_other_code", BLUE),
            ("Generic / speculative", "generic_speculative", GREY))
    plt = _figure(10, 2.8)
    fig, ax = plt.subplots(figsize=(10, 2.8), facecolor=SURFACE)
    _style(ax)
    ax.yaxis.grid(False)
    order = list(reversed(models))
    left = [0] * len(order)
    for label, key, colour in cats:
        values = [sum(r["model"] == m and r["label"] == key for r in rows) for m in order]
        ax.barh(range(len(order)), values, left=left, color=colour, label=label, edgecolor=SURFACE, linewidth=2, height=0.6)
        for y, (v, l) in enumerate(zip(values, left)):
            if v:
                ax.text(l + v / 2, y, str(v), ha="center", va="center", fontsize=10,
                        color="white" if colour == BLUE else INK)
        left = [l + v for l, v in zip(left, values)]
    ax.set_yticks(range(len(order)), order, color=INK)
    ax.set_xticks(range(0, 9, 2))
    ax.set_xlim(0, 8)
    ax.legend(loc="upper center", bbox_to_anchor=(0.45, -0.16), ncol=3, frameon=False, fontsize=9.5, labelcolor=INK2)
    fig.tight_layout()
    fig.savefig(path, dpi=200, facecolor=SURFACE)
    plt.close(fig)


def build():
    OUT.mkdir(parents=True, exist_ok=True)
    rows = load_rq1()
    fig_headline(rows, OUT / "rq1_headline_co.png")
    fig_context(rows, OUT / "rq2_fpr_by_context.png")
    fig_outcomes(rows, OUT / "pair_outcomes_co.png")
    fig_labels(OUT / "false_alarm_labels.png")
    return sorted(p.name for p in OUT.glob("*.png"))


if __name__ == "__main__":
    print(build())
