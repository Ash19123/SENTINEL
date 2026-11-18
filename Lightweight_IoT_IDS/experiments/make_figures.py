"""
Figures for the report and talk, drawn from experiments/results/results.json.

    python experiments/make_figures.py [results_dir]
"""

import json
import math
import sys
from pathlib import Path

import numpy as np
from PIL import Image, ImageDraw, ImageFont

BASE = Path(__file__).resolve().parent.parent
RES = Path(sys.argv[1]) if len(sys.argv) > 1 else BASE / "experiments" / "results"
R = json.loads((RES / "results.json").read_text())
FONTS = Path(r"C:\Windows\Fonts")
BUDGET = 6
DET = "hybrid"


def F(n, s):
    return ImageFont.truetype(str(FONTS / n), s)


TR, TB = "times.ttf", "timesbd.ttf"
INK, GRID = (0, 0, 0), (225, 225, 225)
BLUE, VIOLET, RED, GREY = (30, 110, 200), (120, 90, 200), (210, 50, 60), (110, 110, 110)


def center(d, cx, cy, text, font, fill=INK):
    d.text((cx - d.textlength(text, font=font) / 2, cy - font.size / 2 - 2), text, font=font, fill=fill)


def inf(x):
    return x is None or (isinstance(x, float) and not math.isfinite(x))


held = [e for e in R["held_out"] if e["detector"] == DET and e["budget"] == BUDGET and e.get("feasible")]
live = R["live_rule"][DET]
live_if = R["live_rule"]["if"]


# ---------------------------------------------------------------- 1: median TTD by configuration, fixed vs CUSUM
def fig_bars():
    cfgs = [(5, 5), (5, 1), (3, 1), (2, 1), (1, 0.5)]
    im = Image.new("RGB", (2000, 1050), "white")
    d = ImageDraw.Draw(im)
    center(d, 1000, 45, "Time to detect by window length and decision rate (held-out, real ESP32)", F(TB, 38))
    x0, y0, x1, y1 = 170, 130, 1920, 800
    ymax = 14
    d.rectangle((x0, y0, x1, y1), outline=INK, width=3)
    for v in range(0, ymax + 1, 2):
        y = y1 - (y1 - y0) * v / ymax
        d.line([(x0, y), (x1, y)], fill=GRID, width=2)
        d.text((x0 - 55, y - 16), str(v), font=F(TR, 28), fill=INK)
    d.text((18, 400), "Median\nseconds", font=F(TR, 28), fill=INK)
    gw = (x1 - x0) / len(cfgs)
    for i, (w, h) in enumerate(cfgs):
        for j, (rule, col) in enumerate((("fixed", BLUE), ("cusum", VIOLET))):
            e = next((x for x in held if x["window"] == w and x["hop"] == h and x["rule"] == rule), None)
            bx = x0 + gw * i + gw * 0.17 + j * gw * 0.34
            bw = gw * 0.3
            if not e or inf(e["median"]):
                continue
            top = y1 - (y1 - y0) * min(e["median"], ymax) / ymax
            d.rectangle((bx, top, bx + bw, y1), fill=col)
            lo, hi = e["median_ci"]
            for v in (lo, hi):
                yy = y1 - (y1 - y0) * min(v, ymax) / ymax
                d.line([(bx + bw / 2 - 12, yy), (bx + bw / 2 + 12, yy)], fill=INK, width=3)
            d.line([(bx + bw / 2, y1 - (y1 - y0) * min(lo, ymax) / ymax), (bx + bw / 2, y1 - (y1 - y0) * min(hi, ymax) / ymax)], fill=INK, width=3)
            hi_y = y1 - (y1 - y0) * min(hi, ymax) / ymax
            center(d, bx + bw / 2, min(top, hi_y) - 24, f"{e['median']:.1f}", F(TB, 28))
            center(d, bx + bw / 2, y1 + 78, f"{e['fa_per_hour']:.1f}/h", F(TR, 24), GREY)
        center(d, x0 + gw * (i + 0.5), y1 + 36, f"window {w:g} s, decide every {h:g} s", F(TR, 28))
    d.text((x0, y1 + 118), "false alarms per hour shown under each bar; whiskers = 95% bootstrap interval of the median",
           font=F(TR, 26), fill=GREY)
    d.rectangle((1450, 150, 1480, 180), fill=BLUE); d.text((1495, 148), "k windows in a row", font=F(TR, 28), fill=INK)
    d.rectangle((1450, 200, 1480, 230), fill=VIOLET); d.text((1495, 198), "sequential (CUSUM)", font=F(TR, 28), fill=INK)
    im.save(RES / "fig_ttd_bars.png")


# ---------------------------------------------------------------- 2: CDF of time to detect
def fig_cdf():
    series = [("current live rule (5 s windows, 2 in a row)", live["ttd"], RED)]
    full = [e for e in held if e["detected"] == e["n"]]   # settings that caught every burst
    bf = min([e for e in full if e["rule"] == "fixed"], key=lambda e: e["median"], default=None)
    bc = min([e for e in full if e["rule"] == "cusum"], key=lambda e: e["median"], default=None)
    if bf:
        series.append((f"best k-in-a-row: {bf['window']:g} s windows, every {bf['hop']:g} s", bf["ttd"], BLUE))
    if bc:
        series.append((f"best CUSUM: {bc['window']:g} s windows, every {bc['hop']:g} s", bc["ttd"], VIOLET))
    im = Image.new("RGB", (2000, 950), "white")
    d = ImageDraw.Draw(im)
    center(d, 1000, 45, "How quickly bursts are detected (held-out, real ESP32)", F(TB, 38))
    x0, y0, x1, y1 = 170, 120, 1900, 760
    xmax = 16
    d.rectangle((x0, y0, x1, y1), outline=INK, width=3)
    for v in range(0, xmax + 1, 2):
        x = x0 + (x1 - x0) * v / xmax
        d.line([(x, y0), (x, y1)], fill=GRID, width=2)
        center(d, x, y1 + 30, str(v), F(TR, 28))
    for k in range(0, 101, 20):
        y = y1 - (y1 - y0) * k / 100
        d.line([(x0, y), (x1, y)], fill=GRID, width=2)
        d.text((x0 - 85, y - 16), f"{k}%", font=F(TR, 28), fill=INK)
    center(d, (x0 + x1) / 2, y1 + 80, "Time to detect (seconds after the burst starts)", F(TR, 30))
    d.text((12, 380), "Bursts\ndetected", font=F(TR, 28), fill=INK)
    for n, (name, vals, col) in enumerate(series):
        v = np.sort(np.array([x for x in vals if not inf(x)], dtype=float))
        pts = [(x0, y1)]
        for i, t in enumerate(v):
            x = x0 + (x1 - x0) * min(t, xmax) / xmax
            pts += [(x, y1 - (y1 - y0) * i / len(vals)), (x, y1 - (y1 - y0) * (i + 1) / len(vals))]
        pts.append((x1, pts[-1][1]))
        d.line(pts, fill=col, width=5)
        d.rectangle((1050, 560 + n * 50, 1085, 590 + n * 50), fill=col)
        d.text((1100, 556 + n * 50), name, font=F(TR, 28), fill=INK)
    im.save(RES / "fig_ttd_cdf.png")


# ---------------------------------------------------------------- 3: detector comparison (the finding)
def fig_detectors():
    runs = list(live_if["per_run"].keys())
    im = Image.new("RGB", (2000, 850), "white")
    d = ImageDraw.Draw(im)
    center(d, 1000, 45, "Bursts detected by the live rule, per recording", F(TB, 38))
    x0, y0, x1, y1 = 170, 120, 1900, 640
    d.rectangle((x0, y0, x1, y1), outline=INK, width=3)
    for k in range(0, 101, 25):
        y = y1 - (y1 - y0) * k / 100
        d.line([(x0, y), (x1, y)], fill=GRID, width=2)
        d.text((x0 - 85, y - 16), f"{k}%", font=F(TR, 28), fill=INK)
    gw = (x1 - x0) / len(runs)
    for i, rn in enumerate(runs):
        for j, (det, col, lab) in enumerate((("if", RED, "Isolation Forest alone"), ("hybrid", BLUE, "Isolation Forest + range check"))):
            v = R["live_rule"][det]["per_run"][rn]
            rate = v["detected"] / v["n"]
            bx = x0 + gw * i + gw * 0.17 + j * gw * 0.34
            bw = gw * 0.3
            top = y1 - (y1 - y0) * rate
            d.rectangle((bx, top, bx + bw, y1), fill=col)
            center(d, bx + bw / 2, top - 24 if rate > 0 else y1 - 24, f"{v['detected']}/{v['n']}", F(TB, 34))
        center(d, x0 + gw * (i + 0.5), y1 + 40, f"recording {rn[-1]}", F(TR, 32))
    d.rectangle((1250, 150, 1285, 180), fill=RED); d.text((1300, 146), "Isolation Forest alone", font=F(TR, 30), fill=INK)
    d.rectangle((1250, 200, 1285, 230), fill=BLUE); d.text((1300, 196), "Isolation Forest + range check", font=F(TR, 30), fill=INK)
    d.text((x0, y1 + 100), "Same device, same method, trained on each recording's own first 4 minutes of normal traffic.",
           font=F(TR, 28), fill=GREY)
    im.save(RES / "fig_detectors.png")


fig_bars(); fig_cdf(); fig_detectors()
print("figures written to", RES)
