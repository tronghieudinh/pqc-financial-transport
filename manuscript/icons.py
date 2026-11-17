"""Vector icons shared by the figure scripts: a gateway rack (server) and a card terminal (client)."""
from matplotlib.patches import FancyBboxPatch, Rectangle, Circle

GRID = "#dcdbd6"


def draw_icon(ia, kind, color):
    """draw the icon into the (equal-aspect, axis-off) inset axes `ia`"""
    ia.set_xlim(0, 1); ia.set_ylim(0, 1); ia.set_aspect("equal", adjustable="box"); ia.axis("off")
    fill = "#fff"
    if kind == "server":
        for k in range(3):
            y = 0.04 + k * 0.32
            ia.add_patch(FancyBboxPatch((0.08, y), 0.84, 0.26, boxstyle="round,pad=0,rounding_size=0.04", fc=fill, ec=color, lw=1.2))
            ia.add_patch(Circle((0.22, y + 0.13), 0.04, fc=color, ec="none"))
            ia.add_patch(Circle((0.34, y + 0.13), 0.04, fc=GRID, ec="none"))
            ia.plot([0.52, 0.84], [y + 0.13, y + 0.13], color=color, lw=1.0)
    else:
        ia.add_patch(FancyBboxPatch((0.2, 0.02), 0.6, 0.96, boxstyle="round,pad=0,rounding_size=0.06", fc=fill, ec=color, lw=1.2))
        ia.add_patch(Rectangle((0.28, 0.64), 0.44, 0.26, fc=color, ec="none", alpha=0.25))
        ia.add_patch(Rectangle((0.28, 0.64), 0.44, 0.26, fc="none", ec=color, lw=0.9))
        for r in range(3):
            for c in range(3):
                ia.add_patch(Circle((0.35 + 0.15 * c, 0.50 - 0.13 * r), 0.03, fc=color, ec="none"))
        ia.add_patch(Rectangle((0.32, 0.07), 0.36, 0.05, fc=color, ec="none", alpha=0.6))
