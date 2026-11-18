"""
Offline study: how fast can the detector react, and what does speed cost in false alarms?

Replays the packets recorded by run_trials.py through many configurations:
    window length W  x  hop H (how often a decision is made)  x  confirmation rule
and measures, against the exact ground truth of the commanded bursts:
    time-to-detect (TTD): from the first burst packet on the wire to the first alert
    false alarms per hour on normal traffic

Rules (all operate on the model's per-window flags, same Isolation Forest as the live system):
    fixed(k)   alert when k consecutive windows are flagged (the live system uses k = 2)
    cusum(h)   Bernoulli CUSUM / sequential probability ratio statistic: every flagged window adds
               ln(p1/p0), every normal window subtracts; alert when the sum reaches h

Protocol (no tuning on the data a number is reported on):
    each run gets its own model, trained on its first 4 minutes of normal traffic;
    parameters (k or h) are chosen on one run under a false-alarm budget and reported on the other;
    both directions are pooled.

    python experiments/evaluate_rules.py --a experiments/data/runA --b experiments/data/runB
"""

import argparse
import json
import math
import sys
from pathlib import Path

import numpy as np
import pandas as pd
from sklearn.ensemble import IsolationForest
from sklearn.pipeline import Pipeline
from sklearn.preprocessing import StandardScaler

BASE = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(BASE / "ai_engine"))
from confirm_rules import BernoulliCusum, FixedK  # noqa: E402
from traffic_features import parse_tshark_line  # noqa: E402

CONFIGS = [(5, 5), (5, 1), (3, 1), (2, 1), (2, 0.5), (1, 0.5)]   # (window s, hop s)
K_GRID = list(range(1, 13))
H_GRID = [round(x, 2) for x in np.arange(0.5, 20.01, 0.5)]
P1 = 0.9              # assumed flag rate inside a burst (CUSUM alternative hypothesis)
CAL_S = 300           # seconds after the baseline used to estimate the normal flag rate p0
ONSET_GAP = 0.45      # a burst shows as new connections less than this many seconds apart
MERGE_S = 10          # alerts closer than this count as one event
RECOVER_S = 15        # seconds after a burst excluded from false-alarm counting
BUDGETS = [6, 12]     # false alarms per hour
LIVE = ("fixed", 2, (5, 5))   # the rule the live system has used so far
DETECTORS = ["hybrid", "if"]   # hybrid = Isolation Forest + range check; if = Isolation Forest alone
ENV_R = 2.0           # range check: flag a feature above ENV_R x its largest baseline value


class Run:
    def __init__(self, path):
        self.path = Path(path)
        self.name = self.path.name
        gt = json.load(open(self.path / "ground_truth.json"))
        rows = [r for r in map(parse_tshark_line, open(self.path / "packets.csv", encoding="utf-8")) if r]
        rows.sort(key=lambda r: r[0])
        self.t = np.array([r[0] for r in rows])
        ln = np.array([r[1] for r in rows], dtype=float)
        syn = [r for r in rows if "[SYN]" in r[8]]
        self.dev = syn[0][2]
        sd = np.array([r[2] == self.dev for r in rows])
        dd = np.array([r[3] == self.dev for r in rows])
        self.cs_src = np.concatenate([[0], np.cumsum(ln * sd)])
        self.cs_dst = np.concatenate([[0], np.cumsum(ln * dd)])
        flows, fid = {}, []
        for r in rows:
            fid.append(flows.setdefault(tuple(sorted([(r[2], r[5]), (r[3], r[6])])), len(flows)))
        self.fid = np.array(fid)
        self.syn_t = np.array([r[0] for r in syn])
        self.t0, self.base_end, self.val_end = gt["t0"], gt["baseline_end"], gt["val_end"]
        self.end = gt.get("end", float(self.t[-1]))
        self.outages = [o for o in gt.get("outages", []) if o["end"] - o["start"] >= 5]   # shorter blips are read races
        self.bursts = self._bursts(gt["bursts"])
        self.n_packets = len(rows)

    def _bursts(self, cmds):
        out, s = [], self.syn_t
        for b in cmds:
            i = int(np.searchsorted(s, b["started"] - 0.5))
            onset = None
            while i < len(s) - 1 and s[i] < b["until"]:
                if s[i + 1] - s[i] < ONSET_GAP:
                    onset = s[i]
                    break
                i += 1
            if onset is None:
                continue
            seg = s[(s >= onset) & (s <= b["until"] + 5)]
            gaps = np.diff(seg, prepend=seg[0] - 1)
            end = seg[gaps < ONSET_GAP][-1]
            out.append(dict(cmd=b["started"], onset=float(onset), end=float(end)))
        return out

    def features(self, a, b):
        i, j = np.searchsorted(self.t, [a, b], side="left")
        if j == i:
            return [0, 0, 0, 0, b - a]
        return [j - i, self.cs_src[j] - self.cs_src[i], self.cs_dst[j] - self.cs_dst[i],
                np.unique(self.fid[i:j]).size, b - a]


def fit_model(run, w):
    d = np.arange(run.t0 + w, run.base_end + 1e-9, w)
    x = np.array([run.features(t - w, t) for t in d])
    pipe = Pipeline([("s", StandardScaler()),
                     ("f", IsolationForest(n_estimators=200, contamination=0.05, random_state=42))]).fit(x)
    return (pipe, x[:, :4].max(axis=0) * ENV_R), len(d)


def score_windows(run, model, w, h):
    pipe, ub = model
    d = np.arange(run.t0 + w, run.end + 1e-9, h)
    x = np.array([run.features(t - w, t) for t in d])
    f_if = pipe.predict(x) == -1
    f_env = (x[:, :4] > ub).any(axis=1)
    return d, {"if": f_if, "hybrid": f_if | f_env}


def alerts_fixed(flags, k):
    r = FixedK(k)
    return [i for i, f in enumerate(flags) if r.update(bool(f))]


def alerts_cusum(flags, h, p0):
    r = BernoulliCusum(h, p0=p0, p1=P1)
    return [i for i, f in enumerate(flags) if r.update(bool(f))]


def normal_mask(run, d, w):
    """True for decision times that count as 'normal' for false-alarm purposes."""
    ok = d > run.base_end + CAL_S
    for b in run.bursts:
        ok &= ~((d >= b["onset"] - w - 1) & (d <= b["end"] + w + RECOVER_S))
    for o in run.outages:
        ok &= ~((d >= o["start"] - w) & (d <= o["end"] + w))
    return ok


def evaluate(run, d, w, h, alert_idx):
    times = d[alert_idx]
    ttd = []
    for b in run.bursts:
        hit = times[(times >= b["onset"]) & (times <= b["end"] + 10)]
        ttd.append(float(hit[0] - b["onset"]) if len(hit) else math.inf)
    ok = normal_mask(run, d, w)
    hours = ok.sum() * h / 3600
    fa, last = 0, -1e9
    for i in alert_idx:
        if ok[i]:
            if d[i] - last > MERGE_S:
                fa += 1
            last = d[i]
    return dict(ttd=ttd, fa=fa, hours=float(hours))


def sweep(run, w, h, model):
    d, fl = score_windows(run, model, w, h)
    cal = (d > run.base_end) & (d <= run.base_end + CAL_S)
    nm = normal_mask(run, d, w)
    inb = np.zeros(len(d), bool)
    for b in run.bursts:
        inb |= (d >= b["onset"] + w) & (d <= b["end"])
    out, p0s, infos = {}, {}, {}
    for det, flags in fl.items():
        p0 = float(np.clip(flags[cal].mean() if cal.any() else 0.05, 0.01, 0.30))
        out[det] = {"fixed": {k: evaluate(run, d, w, h, alerts_fixed(flags, k)) for k in K_GRID},
                    "cusum": {hh: evaluate(run, d, w, h, alerts_cusum(flags, hh, p0)) for hh in H_GRID}}
        p0s[det] = p0
        infos[det] = dict(windows=len(d), flag_rate_normal=float(flags[nm].mean()) if nm.any() else math.nan,
                          flag_rate_in_burst=float(flags[inb].mean()) if inb.any() else math.nan)
    return out, p0s, infos


def med(x):
    x = np.array(x, dtype=float)
    return float(np.median(x)) if len(x) else math.nan


def summarize_ttd(ttd):
    a = np.array(ttd, dtype=float)
    det = np.isfinite(a)
    return dict(n=int(len(a)), detected=int(det.sum()), detect_rate=float(det.mean()) if len(a) else math.nan,
                median=med(a), p90=float(np.percentile(a, 90)) if len(a) else math.nan,
                mean_detected=float(a[det].mean()) if det.any() else math.nan)


def choose(res_tune, family, budget, runs_hours):
    """Pick the parameter with the lowest median TTD under the false-alarm budget (on the tuning run)."""
    best = None
    for p, r in res_tune[family].items():
        det = np.isfinite(r["ttd"]).mean() if r["ttd"] else 0
        if r["fa"] > budget * r["hours"] or det < 0.9:
            continue
        key = (med(r["ttd"]), r["fa"], -float(p))
        if best is None or key < best[0]:
            best = (key, p)
    return None if best is None else best[1]


def boot_ci(x, n=2000, seed=0):
    a = np.array([v for v in x], dtype=float)
    if len(a) == 0:
        return (math.nan, math.nan)
    rng = np.random.default_rng(seed)
    meds = [np.median(rng.choice(a, len(a))) for _ in range(n)]
    lo, hi = np.percentile(meds, [2.5, 97.5])
    return (float(lo), float(hi))


def poisson_ci(k, hours):
    if hours <= 0:
        return (math.nan, math.nan)
    from scipy.stats import chi2
    lo = chi2.ppf(0.025, 2 * k) / 2 / hours if k > 0 else 0.0
    hi = chi2.ppf(0.975, 2 * (k + 1)) / 2 / hours
    return (float(lo), float(hi))


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--a", required=True)
    ap.add_argument("--b", required=True)
    ap.add_argument("--soak", help="a long normal-only recording (no bursts) used to measure false alarms precisely")
    ap.add_argument("--out", default=str(BASE / "experiments" / "results"))
    args = ap.parse_args()
    out = Path(args.out)
    out.mkdir(parents=True, exist_ok=True)
    runs = [Run(args.a), Run(args.b)]
    soak = Run(args.soak) if args.soak else None
    allruns = runs + ([soak] if soak else [])
    for r in allruns:
        print(f"{r.name}: {r.n_packets} packets, {len(r.bursts)} bursts, device {r.dev}, "
              f"{(r.end - r.t0) / 60:.1f} min, outages {len(r.outages)}")

    models, sweeps, meta = {}, {}, {}
    for r in allruns:
        for (w, h) in CONFIGS:
            if (r.name, w) not in models:
                models[(r.name, w)] = fit_model(r, w)
            m, ntrain = models[(r.name, w)]
            sweeps[(r.name, w, h)], p0s, infos = sweep(r, w, h, m)
            for det in DETECTORS:
                meta[f"{r.name}|{w}|{h}|{det}"] = dict(p0=p0s[det], train_windows=ntrain, **infos[det])
            print(f"  {r.name} W={w} H={h}: " + "; ".join(
                f"{det}: normal flags {infos[det]['flag_rate_normal']:.3f}, in-burst flags "
                f"{infos[det]['flag_rate_in_burst']:.2f}" for det in DETECTORS))

    curves, held, live = [], [], {}
    for det in DETECTORS:
        # ---- operating curves, pooled over all recordings
        for (w, h) in CONFIGS:
            for fam, grid in (("fixed", K_GRID), ("cusum", H_GRID)):
                for p in grid:
                    ttd, fa, hours = [], 0, 0.0
                    for r in allruns:
                        e = sweeps[(r.name, w, h)][det][fam][p]
                        ttd += e["ttd"]; fa += e["fa"]; hours += e["hours"]
                    curves.append(dict(detector=det, window=w, hop=h, rule=fam, param=p,
                                       fa_per_hour=fa / hours if hours else math.nan, fa_events=fa,
                                       normal_hours=hours, **summarize_ttd(ttd)))
        # ---- held-out operating points
        for budget in BUDGETS:
            for (w, h) in CONFIGS:
                for fam in ("fixed", "cusum"):
                    ttd, fa, hours, chosen, ok = [], 0, 0.0, [], True
                    for tune, test in ((runs[0], runs[1]), (runs[1], runs[0])):
                        p = choose(sweeps[(tune.name, w, h)][det], fam, budget, None)
                        if p is None:
                            ok = False
                            break
                        e = sweeps[(test.name, w, h)][det][fam][p]
                        ttd += e["ttd"]; fa += e["fa"]; hours += e["hours"]; chosen.append(p)
                        if soak:
                            e2 = sweeps[(soak.name, w, h)][det][fam][p]
                            fa += e2["fa"]; hours += e2["hours"]
                    if not ok:
                        held.append(dict(detector=det, budget=budget, window=w, hop=h, rule=fam, feasible=False))
                        continue
                    lo, hi = boot_ci([t for t in ttd if np.isfinite(t)])
                    flo, fhi = poisson_ci(fa, hours)
                    held.append(dict(detector=det, budget=budget, window=w, hop=h, rule=fam, feasible=True,
                                     chosen=chosen, fa_events=fa, normal_hours=hours, fa_per_hour=fa / hours,
                                     fa_ci=[flo, fhi], median_ci=[lo, hi], ttd=ttd, **summarize_ttd(ttd)))
        # ---- the live rule as deployed so far (fixed k=2, 5 s windows), no tuning
        w, h = LIVE[2]
        ttd, fa, hours, per_run = [], 0, 0.0, {}
        for r in allruns:
            e = sweeps[(r.name, w, h)][det]["fixed"][LIVE[1]]
            ttd += e["ttd"]; fa += e["fa"]; hours += e["hours"]
            if r.bursts:
                per_run[r.name] = summarize_ttd(e["ttd"])
        live[det] = dict(window=w, hop=h, rule="fixed", param=LIVE[1], fa_events=fa, normal_hours=hours,
                         fa_per_hour=fa / hours, ttd=ttd, per_run=per_run,
                         median_ci=list(boot_ci([t for t in ttd if np.isfinite(t)])),
                         fa_ci=list(poisson_ci(fa, hours)), **summarize_ttd(ttd))
    pd.DataFrame(curves).to_csv(out / "curves.csv", index=False)

    result = dict(runs=[dict(name=r.name, packets=r.n_packets, bursts=len(r.bursts), minutes=(r.end - r.t0) / 60,
                             device=r.dev, outages=len(r.outages), soak=(r is soak)) for r in allruns],
                  config=dict(configs=CONFIGS, p1=P1, cal_s=CAL_S, budgets=BUDGETS, detectors=DETECTORS, env_ratio=ENV_R),
                  meta=meta, live_rule=live, held_out=held, curves=curves)
    (out / "results.json").write_text(json.dumps(result, indent=1))

    lines = ["Held-out results (rule parameters chosen on the other recording; both directions pooled)\n"]
    for det in DETECTORS:
        L = live[det]
        lines.append(f"[{det}] LIVE RULE (5 s windows, 2 in a row): detected {L['detected']}/{L['n']} bursts, "
                     f"median TTD {L['median']:.1f}s, false alarms {L['fa_per_hour']:.1f}/h over {L['normal_hours']:.2f} h")
        for rn, v in L["per_run"].items():
            lines.append(f"      {rn}: detected {v['detected']}/{v['n']}, median {v['median']:.1f}s")
    for det in DETECTORS:
        for budget in BUDGETS:
            lines.append(f"\n[{det}] budget <= {budget} false alarms/hour")
            lines.append(f"{'W':>3} {'hop':>4} {'rule':>6} {'param':>12} {'median TTD':>11} {'p90':>6} {'det':>7} {'FA/h':>6}")
            for e in sorted([x for x in held if x["detector"] == det and x["budget"] == budget and x["feasible"]],
                            key=lambda x: (x["median"] if x["median"] == x["median"] else 1e9)):
                lines.append(f"{e['window']:>3} {e['hop']:>4} {e['rule']:>6} {str([float(c) for c in e['chosen']]):>12} "
                             f"{e['median']:>10.1f}s {e['p90']:>5.1f} {e['detected']:>3}/{e['n']:<3} {e['fa_per_hour']:>6.1f}")
    (out / "summary.txt").write_text("\n".join(lines))
    print("\n".join(lines))


if __name__ == "__main__":
    main()
