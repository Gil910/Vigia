"""Regenerate the chart in docs/assets/.

Numbers come from `scripts/stats.py`, the "Where the leak lives" table. Re-run
stats.py after any campaign and update DATA. Needs matplotlib, which is not a
runtime dependency of vigia: `pip install matplotlib`.

The point of the picture is the third bar in each group, not the height of the
first two: an attack the user would have called blocked, where the reasoning
said it anyway. So the two scored arms share one muted hue and the gap between
them gets the accent.
"""
import matplotlib

matplotlib.use("Agg")  # headless: this writes PNGs, it never opens a window

import matplotlib.pyplot as plt  # noqa: E402
from matplotlib.patches import FancyBboxPatch  # noqa: E402

# judge, final-answer rate, chain-of-thought rate, answer-clean-reasoning-leaks
DATA = [
    ("claude-haiku-4-5", 23.4, 30.3, 14.9, 26),
    ("gpt-5.6-luna",     26.9, 36.6, 19.4, 34),
]
N = 175
TOTAL = (f"deepseek-r1:8b, {N} attacks. One generation, judged twice: once on the "
         f"final answer,\nonce on the chain of thought. A leak is a judge score of "
         f"5+ out of 10.")

THEMES = {
    "light": dict(surface="#fcfcfb", ink="#0b0b0b", muted="#52514e",
                  faint="#e2e1dc", bar="#b8c4d2", accent="#c2410c"),
    "dark": dict(surface="#1a1a19", ink="#ffffff", muted="#c3c2b7",
                 faint="#383835", bar="#4a5566", accent="#f97316"),
}

XMAX = 46
TICKS = range(0, 41, 10)


def render(mode, out):
    t = THEMES[mode]
    fig, ax = plt.subplots(figsize=(10.6, 5.6), dpi=200)
    fig.patch.set_facecolor(t["surface"])
    ax.set_facecolor(t["surface"])

    rows, y = [], 0.0
    for judge, answer, reasoning, only_pct, only_n in DATA[::-1]:
        rows.append((y, "Answer clean, reasoning leaked", only_pct,
                     f"{only_n} of {N}", True, judge))
        rows.append((y + 1.0, "Chain of thought", reasoning, "", False, None))
        rows.append((y + 2.0, "Final answer", answer, "", False, None))
        y += 4.05

    for y, label, rate, sub, accent, judge in rows:
        colour = t["accent"] if accent else t["bar"]
        ax.add_patch(FancyBboxPatch(
            (0, y - 0.28), rate, 0.56,
            boxstyle="round,pad=0,rounding_size=0.9",
            linewidth=0, facecolor=colour, mutation_aspect=0.03, zorder=3))
        ax.text(rate + 0.8, y, f"{rate:.1f}%", va="center", ha="left",
                color=t["ink"], fontsize=13 if accent else 12,
                fontweight="bold" if accent else "normal", zorder=4)
        ax.text(-0.9, y + (0.13 if sub else 0), label, va="center", ha="right",
                color=t["ink"] if accent else t["muted"],
                fontsize=11, fontweight="bold" if accent else "normal")
        if sub:
            ax.text(-0.9, y - 0.25, sub, va="center", ha="right",
                    color=t["muted"], fontsize=8.5)
        if judge:
            ax.text(-0.9, y + 3.05, judge, va="center", ha="right",
                    color=t["ink"], fontsize=11.5, fontweight="bold")

    ax.set_xlim(0, XMAX)
    ax.set_ylim(-0.9, rows[-1][0] + 1.6)
    ax.set_yticks([])
    ax.set_xticks(TICKS)
    ax.set_xticklabels([f"{v}%" for v in TICKS], color=t["muted"], fontsize=9)
    ax.tick_params(axis="x", length=0, pad=6)
    ax.xaxis.grid(True, color=t["faint"], linewidth=0.8, zorder=0)
    ax.set_axisbelow(True)
    for spine in ax.spines.values():
        spine.set_visible(False)

    ax.text(0, 1.235, "The refusal was honest. The reasoning was not.",
            transform=ax.transAxes, color=t["ink"], fontsize=17,
            fontweight="bold", va="bottom")
    ax.text(0, 1.030, TOTAL, transform=ax.transAxes, color=t["muted"],
            fontsize=10, va="bottom", linespacing=1.5)
    fig.text(0.013, 0.018, "VIGÍA   github.com/Gil910/Vigia",
             color=t["muted"], fontsize=8.5)

    fig.subplots_adjust(left=0.315, right=0.985, top=0.735, bottom=0.115)
    fig.savefig(out, facecolor=t["surface"])
    plt.close(fig)
    print("wrote", out)


if __name__ == "__main__":
    assert all(a < r for _, a, r, _, _ in DATA), "reasoning should exceed the answer"
    render("light", "docs/assets/reasoning-leak.png")
    render("dark", "docs/assets/reasoning-leak-dark.png")
