"""Regenerate the language chart in docs/assets/.

Numbers come from `scripts/stats.py`, the "By language" table. If you re-run a
campaign, re-run stats.py first and paste the new rows into DATA. Needs matplotlib,
which is not a runtime dependency of vigia: `pip install matplotlib`.
"""
import matplotlib

matplotlib.use("Agg")  # headless: this writes PNGs, it never opens a window

import matplotlib.pyplot as plt  # noqa: E402
from matplotlib.patches import FancyBboxPatch  # noqa: E402

# label, locale, leak rate, n
DATA = [
    ("Catalan",            "ca-ES", 70.0,   80),
    ("Spanish",            "es-ES", 45.8, 1431),
    ("Spanish + Basque",   "es-EU", 28.0,  314),
    ("Spanish + Galician", "es-GL", 24.2,  314),
    ("Basque",             "eu-ES", 24.1,  315),
    ("Galician",           "gl-ES", 23.8,  315),
]
TOTAL = "2,769 evaluated attacks across 5 models. A leak is a judge score of 5+ out of 10."

THEMES = {
    "light": dict(surface="#fcfcfb", ink="#0b0b0b", muted="#52514e",
                  faint="#e2e1dc", bar="#2a78d6", bar_dim="#9ec5f4"),
    "dark": dict(surface="#1a1a19", ink="#ffffff", muted="#c3c2b7",
                 faint="#383835", bar="#3987e5", bar_dim="#256abf"),
}


def render(mode, out):
    t = THEMES[mode]
    fig, ax = plt.subplots(figsize=(10, 5.6), dpi=200)
    fig.patch.set_facecolor(t["surface"])
    ax.set_facecolor(t["surface"])

    ys = list(range(len(DATA)))[::-1]
    for y, (label, loc, rate, n) in zip(ys, DATA, strict=True):
        colour = t["bar_dim"] if loc == "es-ES" else t["bar"]
        ax.add_patch(FancyBboxPatch(
            (0, y - 0.25), rate, 0.50,
            boxstyle="round,pad=0,rounding_size=0.9",
            linewidth=0, facecolor=colour, mutation_aspect=0.055, zorder=3))
        ax.text(rate + 1.6, y, f"{rate:.1f}%", va="center", ha="left",
                color=t["ink"], fontsize=13.5, fontweight="bold", zorder=4)
        ax.text(-1.8, y + 0.14, label, va="center", ha="right",
                color=t["ink"], fontsize=12)
        ax.text(-1.8, y - 0.24, f"{loc}   n = {n:,}", va="center", ha="right",
                color=t["muted"], fontsize=8.5)

    # the gap between the top two bars is the finding, so draw it
    top, base = ys[0], ys[1]
    delta = round(DATA[0][2] - DATA[1][2])
    ax.annotate("", xy=(84, top), xytext=(84, base),
                arrowprops=dict(arrowstyle="<->", color=t["muted"], lw=1.1,
                                shrinkA=0, shrinkB=0))
    ax.text(86.5, (top + base) / 2, f"+{delta}\npoints", va="center", ha="left",
            color=t["ink"], fontsize=11.5, fontweight="bold", linespacing=1.25)

    ax.set_xlim(0, 103)
    ax.set_ylim(-0.7, len(DATA) - 0.3)
    ax.set_yticks([])
    ax.set_xticks(range(0, 81, 20))
    ax.set_xticklabels([f"{v}%" for v in range(0, 81, 20)], color=t["muted"], fontsize=9)
    ax.tick_params(axis="x", length=0, pad=6)
    ax.xaxis.grid(True, color=t["faint"], linewidth=0.8, zorder=0)
    ax.set_axisbelow(True)
    for spine in ax.spines.values():
        spine.set_visible(False)

    ax.text(0, 1.135, "Same attack, different language", transform=ax.transAxes,
            color=t["ink"], fontsize=17, fontweight="bold", va="bottom")
    ax.text(0, 1.035, "How often a RAG chatbot leaked something it shouldn't have.\n" + TOTAL,
            transform=ax.transAxes, color=t["muted"], fontsize=10, va="bottom", linespacing=1.5)
    fig.text(0.013, 0.018, "VIGÍA   github.com/Gil910/Vigia", color=t["muted"], fontsize=8.5)

    fig.subplots_adjust(left=0.215, right=0.985, top=0.775, bottom=0.115)
    fig.savefig(out, facecolor=t["surface"])
    plt.close(fig)
    print("wrote", out)


if __name__ == "__main__":
    render("light", "docs/assets/language-leak-rate.png")
    render("dark", "docs/assets/language-leak-rate-dark.png")
