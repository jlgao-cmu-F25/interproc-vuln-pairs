"""Render the slide-8 RQ2 chart as a PNG (Google Slides cannot import PowerPoint charts reliably)."""
import json, sys
import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt

D = json.load(open(sys.argv[1] if len(sys.argv) > 1 else "deck_data.json"))
models = ["Claude Haiku 4.5", "Gemini 3 Flash", "GPT-5 Mini", "GPT-4.1 Mini"]
short = ["Haiku 4.5", "Gemini 3 Flash", "GPT-5 Mini", "GPT-4.1 Mini*"]
ctx = [("CO", "Code only", "#A9C9EF"), ("CC", "+ Callees", "#5B9BE0"), ("CK", "+ Callers", "#1F4E9E")]
plt.rcParams.update({"font.family": "Liberation Sans", "font.size": 11})
fig, ax = plt.subplots(figsize=(5.6, 3.35), dpi=300)
w = 0.26
for j, (c, name, color) in enumerate(ctx):
    xs = [i + (j - 1) * (w + 0.02) for i in range(len(models))]
    vals = [D["rq1"][f"{m}|{c}"]["fpr"] for m in models]
    ax.bar(xs, vals, w, color=color, label=name, edgecolor="white", linewidth=0.8)
    for x, v in zip(xs, vals):
        ax.text(x, v + 0.015, f"{round(100 * v)}%", ha="center", va="bottom", fontsize=8.5, color="#111111")
ax.set_xticks(range(len(models)), short, fontsize=10.5, color="#111111")
ax.set_ylim(0, 1.08)
ax.set_yticks([0, .25, .5, .75, 1], ["0%", "25%", "50%", "75%", "100%"], fontsize=9.5, color="#52514E")
ax.set_ylabel("False-alarm rate on fixed code", fontsize=10, color="#52514E")
ax.yaxis.grid(True, color="#E4E3DF", linewidth=0.75)
ax.set_axisbelow(True)
for side in ("top", "right", "left"):
    ax.spines[side].set_visible(False)
ax.spines["bottom"].set_color("#BBBBBB")
ax.tick_params(axis="both", length=0)
ax.legend(loc="lower center", bbox_to_anchor=(0.5, 1.0), ncol=3, frameon=False, fontsize=10, handlelength=1, columnspacing=1.2)
fig.tight_layout(pad=0.2)
fig.savefig("rq2_fpr_by_context.png", facecolor="white")
