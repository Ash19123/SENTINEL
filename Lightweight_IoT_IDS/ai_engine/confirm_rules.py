"""
Confirmation rules: turn a stream of per-window flags (the model's 'unusual / normal') into alerts.

A single flagged window is only suspicious. A rule decides when the evidence is enough to alert,
trading time-to-detect against false alarms.

    FixedK(k)            alert when k consecutive windows are flagged (the original live rule, k = 2)
    BernoulliCusum(h)    sequential probability-ratio statistic (CUSUM): each flagged window adds
                         ln(p1/p0) to a running sum, each normal window subtracts; alert when the
                         sum reaches h. p0 = normal flag rate, p1 = flag rate during an anomaly.

Both rules are used identically by the live detector and the offline study (experiments/evaluate_rules.py).
update(flag) returns True exactly when a new alert starts; .active says whether an alert is in force.
"""

import math


class FixedK:
    def __init__(self, k=2):
        self.k, self.c, self.active = int(k), 0, False

    def update(self, flag):
        self.c = self.c + 1 if flag else 0
        was, self.active = self.active, self.c >= self.k
        return self.active and not was

    def reset(self):
        self.c, self.active = 0, False

    @property
    def value(self):
        return float(self.c)


class BernoulliCusum:
    def __init__(self, h=4.0, p0=0.05, p1=0.9):
        self.h = float(h)
        self.up = math.log(p1 / p0)                 # evidence added by a flagged window
        self.dn = math.log((1 - p1) / (1 - p0))     # evidence removed by a normal window (negative)
        self.s, self.active, self.cap = 0.0, False, 2 * self.h

    def update(self, flag):
        self.s = min(self.cap, max(0.0, self.s + (self.up if flag else self.dn)))
        was = self.active
        if not self.active and self.s >= self.h:
            self.active = True
        elif self.active and self.s < self.h / 2:   # hysteresis: clears once the evidence has mostly drained
            self.active = False
        return self.active and not was

    def reset(self):
        self.s, self.active = 0.0, False

    @property
    def value(self):
        return self.s


def make_rule(name, param, p0=0.05):
    if name == "fixed":
        return FixedK(param)
    if name == "cusum":
        return BernoulliCusum(param, p0=p0)
    raise ValueError(f"unknown rule: {name}")
