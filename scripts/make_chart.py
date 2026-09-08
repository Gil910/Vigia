"""Regenerate the language chart in docs/assets/.

Numbers come from `scripts/stats.py`, the "By language, controlled for attack
vector" table — the controlled column, never the raw one. If you re-run a campaign,
re-run stats.py first and paste the new rows into DATA. Needs matplotlib, which is
not a runtime dependency of vigia: `pip install matplotlib`.

One hue for all six bars on purpose. The bars already encode magnitude by length,
and the finding is the gap between the two groups, so that gets drawn as a bracket
rather than as a second colour that a reader has to decode.
"""
import matplotlib

matplotlib.use("Agg")  # headless: this writes PNGs, it never opens a window

import matplotlib.pyplot as plt  # noqa: E402
from matplotlib.patches import FancyBboxPatch  # noqa: E402

# label, locale, controlled leak rate, n
DATA = [
    ("Catalan",            "ca-ES", 38.9, 195),
    ("Spanish",            "es-ES", 38.4, 190),
    ("Basque",             "eu-ES", 28.8, 195),
    ("Spanish + Basque",   "es-EU", 27.7, 195),
    ("Galician",           "gl-ES", 24.2, 195),
    ("Spanish + Galician", "es-GL", 19.1, 195),
]
# how many bars from the top belong to the upper group
TIER = 2
TOTAL = ("1,165 attacks across 5 models, 39 seeds per locale over the same 19 "
         "attack vectors.\nA leak is a judge score of 5+ out of 10.")

THEMES = {
    "light": dict(surface="#fcfcfb", ink="#0b0b0b", muted="#52514e",
                  faint="#e2e1dc", bar="#2a78d6"),
    "dark": dict(surface="#1a1a19", ink="#ffffff", muted="#c3c2b7",
                 faint="#383835", bar="#3987e5"),
}

XMAX = 56          # room for the value labels and the bracket
TICKS = range(0, 41, 10)


def render(mode, out):
    t = THEMES[mode]
    fig, ax = plt.subplots(figsize=(10, 5.6), dpi=200)
    fig.patch.set_facecolor(t["surface"])
    ax.set_facecolor(t["surface"])

    ys = list(range(len(DATA)))[::-1]
    for y, (label, loc, rate, n) in zip(ys, DATA, strict=True):
        ax.add_patch(FancyBboxPatch(
            (0, y - 0.25), rate, 0.50,
            boxstyle="round,pad=0,rounding_size=0.9",
            linewidth=0, facecolor=t["bar"], mutation_aspect=0.03, zorder=3))
        ax.text(rate + 0.9, y, f"{rate:.1f}%", va="center", ha="left",
                color=t["ink"], fontsize=13.5, fontweight="bold", zorder=4)
        ax.text(-1.0, y + 0.14, label, va="center", ha="right",
                color=t["ink"], fontsize=12)
        ax.text(-1.0, y - 0.24, f"{loc}   n = {n:,}", va="center", ha="right",
                color=t["muted"], fontsize=8.5)

    # The gap between the two groups is what survives a change of judge, so it is
    # the thing to draw. Everything inside a group is within a few points and the
    # ordering there depends on who is grading.
    x = 48.5
    upper, lower = ys[TIER - 1], ys[TIER]
    gap = DATA[TIER - 1][2] - DATA[TIER][2]
    ax.annotate("", xy=(x, ys[0] + 0.32), xytext=(x, upper - 0.32),
                arrowprops=dict(arrowstyle="-", color=t["muted"], lw=1.1))
    ax.annotate("", xy=(x, lower + 0.32), xytext=(x, ys[-1] - 0.32),
                arrowprops=dict(arrowstyle="-", color=t["muted"], lw=1.1))
    ax.annotate("", xy=(x, upper - 0.30), xytext=(x, lower + 0.30),
                arrowprops=dict(arrowstyle="<->", color=t["muted"], lw=1.1,
                                shrinkA=0, shrinkB=0))
    ax.text(x + 1.4, (upper + lower) / 2, f"{gap:.1f}\npoints", va="center",
            ha="left", color=t["ink"], fontsize=11.5, fontweight="bold",
            linespacing=1.25)

    ax.set_xlim(0, XMAX)
    ax.set_ylim(-0.7, len(DATA) - 0.3)
    ax.set_yticks([])
    ax.set_xticks(TICKS)
    ax.set_xticklabels([f"{v}%" for v in TICKS], color=t["muted"], fontsize=9)
    ax.tick_params(axis="x", length=0, pad=6)
    ax.xaxis.grid(True, color=t["faint"], linewidth=0.8, zorder=0)
    ax.set_axisbelow(True)
    for spine in ax.spines.values():
        spine.set_visible(False)

    ax.text(0, 1.245, "Same attack, different language", transform=ax.transAxes,
            color=t["ink"], fontsize=17, fontweight="bold", va="bottom")
    ax.text(0, 1.030, "How often a RAG chatbot leaked something it shouldn't have.\n" + TOTAL,
            transform=ax.transAxes, color=t["muted"], fontsize=10, va="bottom",
            linespacing=1.5)
    fig.text(0.013, 0.018, "VIGÍA   github.com/Gil910/Vigia", color=t["muted"], fontsize=8.5)

    fig.subplots_adjust(left=0.215, right=0.985, top=0.725, bottom=0.115)
    fig.savefig(out, facecolor=t["surface"])
    plt.close(fig)
    print("wrote", out)


if __name__ == "__main__":
    render("light", "docs/assets/language-leak-rate.png")
    render("dark", "docs/assets/language-leak-rate-dark.png")
