"""SENTINEL: live dashboard for the Lightweight IoT Intrusion & Anomaly Detector."""

import json
import os
import sys
import time
from datetime import datetime
from pathlib import Path

import numpy as np
import pandas as pd
import plotly.graph_objects as go
import streamlit as st
import streamlit.components.v1 as components

BASE = Path(__file__).resolve().parent.parent
# SENTINEL_LOGS points the dashboard at a recorded session; SENTINEL_REPLAY=1 judges the
# device online as of that session's last analysis instead of the wall clock.
LOGS = Path(os.environ.get("SENTINEL_LOGS", BASE / "logs"))
REPLAY = os.environ.get("SENTINEL_REPLAY") == "1"
sys.path.insert(0, str(BASE / "ai_engine"))

# ------------------------------------------------------------------ palette
BG, CARD = "#080D18", "#111B2B"
CYAN, OK, BAD, VIOLET = "#35D6F2", "#35D39A", "#FF5364", "#9B8CFF"
TEXT, MUTED = "#E8EEF8", "#8A99B3"
AMBER = "#F5B544"
GRID = "rgba(255,255,255,.07)"

PAGES = ["Overview", "Traffic", "Threat Detection", "Presence", "Research", "Model Insights"]   # lecture order; the Devices page is no longer shown

st.set_page_config(page_title="SENTINEL", page_icon="🛡️", layout="wide",
                   initial_sidebar_state="collapsed")


def H(s):
    """Collapse indented HTML so Markdown never turns it into a code block."""
    return "".join(line.strip() for line in s.splitlines())


st.markdown(H(f"""
<style>
.stApp {{background:{BG};}}
header[data-testid="stHeader"] {{background:transparent;}}
.block-container {{padding-top:1rem; max-width:1500px;}}
html, body, [class*="css"] {{font-family:'Inter','Segoe UI',system-ui,sans-serif;}}
h1,h2,h3,h4 {{color:{TEXT}; letter-spacing:-.01em;}}

.topbar {{display:flex; justify-content:space-between; align-items:center; padding:12px 20px;
  border:1px solid rgba(255,255,255,.07); border-radius:16px; background:{CARD}; margin-bottom:12px;}}
.brand {{display:flex; align-items:center; gap:12px; font-weight:800; letter-spacing:.18em; font-size:1.15rem;}}
.brand small {{font-weight:500; letter-spacing:.02em; color:{MUTED}; font-size:.8rem; margin-left:6px;}}
.meta {{display:flex; gap:22px; align-items:center; color:{MUTED}; font-size:.85rem;}}
.dot {{display:inline-block; width:9px; height:9px; border-radius:50%; margin-right:8px;}}
.dot.ok {{background:{OK}; box-shadow:0 0 10px {OK};}}
.dot.bad {{background:{BAD}; box-shadow:0 0 10px {BAD}; animation:pulse 1s infinite;}}
.dot.warn {{background:{AMBER}; box-shadow:0 0 10px {AMBER};}}
@keyframes pulse {{50% {{opacity:.35;}}}}

div[role="radiogroup"] {{gap:6px; flex-wrap:wrap;}}
div[role="radiogroup"] label {{background:{CARD}; border:1px solid rgba(255,255,255,.08); padding:8px 18px;
  border-radius:999px; cursor:pointer; transition:.15s;}}
div[role="radiogroup"] label:hover {{border-color:{CYAN}; box-shadow:0 0 14px rgba(53,214,242,.18);}}
div[role="radiogroup"] label > div:first-child {{display:none;}}
div[role="radiogroup"] label:has(input:checked) {{background:rgba(53,214,242,.14); border-color:{CYAN};}}
div[role="radiogroup"] label:has(input:checked) p {{color:{CYAN}; font-weight:700;}}

.hero {{border-radius:20px; padding:26px 32px; margin:14px 0 16px 0; display:flex; justify-content:space-between;
  align-items:center; border:1px solid rgba(255,255,255,.08);}}
.hero.ok {{background:linear-gradient(120deg,rgba(53,211,154,.16),rgba(17,27,43,.9)); box-shadow:0 0 40px rgba(53,211,154,.10);}}
.hero.bad {{background:linear-gradient(120deg,rgba(255,83,100,.24),rgba(17,27,43,.9)); box-shadow:0 0 48px rgba(255,83,100,.25);}}
.hero.wait {{background:linear-gradient(120deg,rgba(53,214,242,.14),rgba(17,27,43,.9));}}
.hero.warn {{background:linear-gradient(120deg,rgba(245,181,68,.16),rgba(17,27,43,.9));}}
.hero .k {{font-size:.78rem; letter-spacing:.16em; color:{MUTED}; text-transform:uppercase;}}
.hero .v {{font-size:2.4rem; font-weight:800; line-height:1.15;}}
.hero .s {{color:{MUTED}; margin-top:4px;}}
.hero.ok .v {{color:{OK};}} .hero.bad .v {{color:{BAD};}} .hero.wait .v {{color:{CYAN};}} .hero.warn .v {{color:{AMBER};}}
.badge {{padding:10px 22px; border-radius:999px; font-weight:700; letter-spacing:.1em; font-size:.9rem;}}
.hero.ok .badge {{background:rgba(53,211,154,.15); color:{OK}; border:1px solid {OK};}}
.hero.bad .badge {{background:rgba(255,83,100,.15); color:{BAD}; border:1px solid {BAD}; animation:pulse 1s infinite;}}
.hero.wait .badge {{background:rgba(53,214,242,.12); color:{CYAN}; border:1px solid {CYAN};}}
.hero.warn .badge {{background:rgba(245,181,68,.12); color:{AMBER}; border:1px solid {AMBER};}}

.kpi {{background:{CARD}; border:1px solid rgba(255,255,255,.07); border-radius:16px; padding:16px 20px; transition:.18s;}}
.kpi:hover {{border-color:rgba(53,214,242,.5); box-shadow:0 0 22px rgba(53,214,242,.12); transform:translateY(-2px);}}
.kpi .l {{font-size:.74rem; letter-spacing:.12em; text-transform:uppercase; color:{MUTED};}}
.kpi .n {{font-size:2rem; font-weight:800; line-height:1.25;}}
.kpi .d {{font-size:.8rem; color:{MUTED};}}

.panel {{background:{CARD}; border:1px solid rgba(255,255,255,.07); border-radius:16px; padding:18px 22px; margin:10px 0;}}
.panel h4 {{margin:0 0 6px 0;}}
.sec {{margin:26px 0 4px 0; color:{MUTED}; font-size:.75rem; letter-spacing:.2em; text-transform:uppercase;}}
.note {{color:{MUTED}; font-size:.85rem;}}
.sev {{display:inline-block; padding:2px 12px; border-radius:999px; font-size:.78rem; font-weight:700;}}
.sev.High {{background:rgba(255,83,100,.18); color:{BAD};}}
.sev.Medium {{background:rgba(245,181,68,.18); color:{AMBER};}}
.sev.Low {{background:rgba(155,140,255,.18); color:{VIOLET};}}

div.stButton > button {{border-radius:12px; border:1px solid {BAD}; background:rgba(255,83,100,.12);
  color:{BAD}; font-weight:700; padding:.55rem 1.4rem; transition:.15s;}}
div.stButton > button:hover {{background:{BAD}; color:#fff; box-shadow:0 0 22px rgba(255,83,100,.5);}}
div.stDownloadButton > button {{border-radius:12px; border:1px solid {CYAN}; background:rgba(53,214,242,.1); color:{CYAN};}}
</style>
"""), unsafe_allow_html=True)


# ------------------------------------------------------------------ helpers
def rj(name, default=None):
    try:
        return json.loads((LOGS / name).read_text())
    except (OSError, ValueError):
        return {} if default is None else default


def rc(path):
    try:
        return pd.read_csv(path)
    except (OSError, ValueError, pd.errors.EmptyDataError):
        return pd.DataFrame()


def kpi(col, label, value, sub="", color=TEXT):
    col.markdown(H(f'<div class="kpi"><div class="l">{label}</div>'
                   f'<div class="n" style="color:{color}">{value}</div><div class="d">{sub}</div></div>'),
                 unsafe_allow_html=True)


def style(fig, h=300, title=None):
    fig.update_layout(
        height=h, margin=dict(l=6, r=6, t=46 if title else 12, b=6),
        paper_bgcolor="rgba(0,0,0,0)", plot_bgcolor="rgba(0,0,0,0)",
        font=dict(color=TEXT, size=12), hovermode="x unified",
        title=dict(text=title, font=dict(size=15, color=TEXT), x=0.01) if title else None,
        legend=dict(orientation="h", y=1.14, x=0.01, font=dict(color=MUTED)),
        xaxis=dict(gridcolor=GRID, zeroline=False), yaxis=dict(gridcolor=GRID, zeroline=False))
    if fig.data and fig.data[0].type == "pie":  # donut: legend underneath so it never covers the title
        fig.update_layout(legend=dict(orientation="h", y=-0.04, x=0.5, xanchor="center", font=dict(color=MUTED)))
    return fig


def ago(ts):
    if not ts:
        return "never"
    d = max(time.time() - ts, 0)
    return f"{d:.0f} s ago" if d < 120 else f"{d / 60:.0f} min ago"


def baseline_mean():
    b = rc(BASE / "datasets" / "esp32_normal.csv")
    return float(b["packet_count"].mean()) if len(b) else None


def severity(packets, base):
    r = packets / base if base else 1
    return "High" if r >= 8 else "Medium" if r >= 3 else "Low"


def load_state():
    s = {
        "phase": rj("phase.json", {"phase": "starting"}),
        "stats": rj("stats.json"),
        "dev": rj("device_status.json"),
        "cmd": rj("attack_cmd.json"),
        "cmds": rc(LOGS / "commands.csv"),
        "live": rc(LOGS / "live_log.csv"),
        "pk": rc(LOGS / "packets_recent.csv"),
        "sim": bool(rj("mode.json").get("simulated")),
    }
    d = s["dev"]
    ref = s["stats"].get("last_analysis", time.time()) if REPLAY else time.time()
    s["online"] = bool(d) and abs(ref - d.get("last_seen", 0)) < 8
    s["live"] = s["live"].reset_index(drop=True)
    s["last"] = s["live"].iloc[-1] if len(s["live"]) else None
    s["attacking"] = (not REPLAY) and time.time() < s["cmd"].get("until", 0)
    return s


def status_of(s):
    """-> (css class, headline, sub text, badge)"""
    if s["phase"]["phase"] == "learning":
        return "wait", "Learning baseline", "Capturing normal traffic to build the model.", "LEARNING"
    if not s["online"]:
        return ("warn", "Device offline" if s["dev"] else "Waiting for device",
                "No heartbeat from the ESP32. Check power and Wi-Fi.", "NO SIGNAL")
    if s["last"] is None:
        return "wait", "Analysing", "First traffic window is being processed.", "STARTING"
    if s["last"]["status"] == "anomaly":
        return ("bad", "Potential anomaly", "Traffic differs sharply from the learned baseline. "
                "Isolation Forest flags unusual behaviour; it does not confirm an attack.", "ALERT")
    return "ok", "Normal", "Device traffic matches the learned baseline.", "SECURE"


# ------------------------------------------------------------------ network map
def topology(s, height=360):
    dev, online = s["dev"], s["online"]
    anomaly = s["last"] is not None and s["last"]["status"] == "anomaly"
    burst = bool(dev.get("flooding")) and online
    hot = anomaly or burst
    sensor_ok = online and dev.get("sensor_ok")
    col_main = BAD if hot else CYAN
    dur = 0.7 if hot else 2.2
    ip = dev.get("ip", "—")
    dht_txt = (f'{dev["temperature"]:.1f}°C · {dev["humidity"]:.0f}%' if sensor_ok else "no valid signal")
    pk = int(s["last"]["packet_count"]) if s["last"] is not None else 0

    nodes = {  # id: (x, y, glyph, title, detail, colour)
        "dht": (90, 190, "DHT", "Simulated sensor" if s["sim"] else "DHT22 sensor", dht_txt, OK if sensor_ok else MUTED),
        "esp": (280, 190, "ESP", "Simulated device" if s["sim"] else "ESP32 node", ip if online else "offline", (BAD if hot else CYAN) if online else MUTED),
        "ap": (470, 190, "AP", "Loopback (this laptop)" if s["sim"] else "Wi-Fi hotspot", (f'{dev["rssi"]} dBm' if dev.get("rssi") is not None else "no signal data") if online else "—", col_main if online else MUTED),
        "gw": (660, 90, "GW", "Laptop gateway", ":8000 receiver", col_main if online else MUTED),
        "ws": (660, 290, "WS", "Wireshark tap", f"{pk} pkts / window", VIOLET),
        "if": (850, 290, "IF", "Isolation Forest", "potential anomaly" if anomaly else "scoring", BAD if anomaly else VIOLET),
        "ui": (850, 90, "UI", "SENTINEL", "dashboard", CYAN),
    }
    edges = [  # a, b, colour, active, dashed
        ("dht", "esp", OK, bool(sensor_ok), not sensor_ok),
        ("esp", "ap", col_main, online, False),
        ("ap", "gw", col_main, online, False),
        ("ap", "ws", VIOLET, online, True),
        ("ws", "if", VIOLET, online, False),
        ("if", "ui", BAD if anomaly else VIOLET, online, False),
        ("gw", "ui", CYAN, online, False),
    ]
    svg = []
    for a, b, c, active, dashed in edges:
        x1, y1, x2, y2 = nodes[a][0], nodes[a][1], nodes[b][0], nodes[b][1]
        svg.append(f'<line x1="{x1}" y1="{y1}" x2="{x2}" y2="{y2}" stroke="{c if active else "#2a3650"}" '
                   f'stroke-width="2" opacity=".6" {"stroke-dasharray=\"6 6\"" if dashed else ""}/>')
        if active:
            for i in range(3 if hot else 2):
                svg.append(f'<circle r="3.5" fill="{c}" filter="url(#glow)"><animateMotion '
                           f'dur="{dur}s" begin="{i * dur / (3 if hot else 2):.2f}s" repeatCount="indefinite" '
                           f'path="M{x1} {y1} L{x2} {y2}"/></circle>')
    for x, y, g, t, d, c in nodes.values():
        svg.append(f'<circle cx="{x}" cy="{y}" r="30" fill="#0c1424" stroke="{c}" stroke-width="2" filter="url(#glow)"/>'
                   f'<text x="{x}" y="{y + 5}" text-anchor="middle" fill="{c}" font-size="14" font-weight="700">{g}</text>'
                   f'<text x="{x}" y="{y + 52}" text-anchor="middle" fill="{TEXT}" font-size="13" font-weight="600">{t}</text>'
                   f'<text x="{x}" y="{y + 69}" text-anchor="middle" fill="{MUTED}" font-size="11.5">{d}</text>')
    html = f"""
    <html><body style="margin:0;background:{CARD};border-radius:16px;overflow:hidden">
    <svg viewBox="0 0 940 {height}" width="100%" height="{height}" xmlns="http://www.w3.org/2000/svg"
         font-family="Inter,Segoe UI,sans-serif">
      <defs>
        <filter id="glow" x="-50%" y="-50%" width="200%" height="200%">
          <feGaussianBlur stdDeviation="3" result="b"/><feMerge><feMergeNode in="b"/><feMergeNode in="SourceGraphic"/></feMerge>
        </filter>
        <pattern id="dots" width="16" height="16" patternUnits="userSpaceOnUse">
          <circle cx="2" cy="2" r="1.1" fill="#1f2b44"/></pattern>
      </defs>
      <rect width="940" height="{height}" fill="url(#dots)"/>
      <text x="20" y="28" fill="{MUTED}" font-size="11" letter-spacing="3">LIVE NETWORK MAP</text>
      <text x="920" y="28" text-anchor="end" fill="{BAD if hot else OK if online else MUTED}" font-size="11"
            letter-spacing="2">{"TRAFFIC BURST" if hot else "TRANSMITTING" if online else "NO SIGNAL"}</text>
      {''.join(svg)}
    </svg></body></html>"""
    components.html(html, height=height + 4)


# ------------------------------------------------------------------ anomaly generator
def attack_panel(s, key):
    cmd = s["cmd"]
    left = max(cmd.get("until", 0) - time.time(), 0)
    st.markdown(H('<div class="panel"><h4>Anomaly generator</h4><div class="note">Commands the ESP32 to send a '
                  'burst of abnormal traffic (a connection flood) for a limited time. Wireshark captures it, '
                  'the Isolation Forest scores it and the ESP32 flashes Red 1 when it is flagged.</div></div>'),
                unsafe_allow_html=True)
    c1, c2, c3 = st.columns([1.2, 1, 2])
    dur = c1.slider("Duration (s)", 10, 30, 25, key=f"dur_{key}", help="Capped at 30 s to protect the hardware.")
    c2.write("")
    if c2.button("Generate anomaly", key=f"gen_{key}", disabled=not s["online"] or left > 0):
        now = time.time()
        (LOGS / "attack_cmd.json").write_text(json.dumps({"started": now, "until": now + dur}))
        hist = LOGS / "commands.csv"
        with open(hist, "a", newline="") as fh:
            if not hist.exists() or hist.stat().st_size == 0:
                fh.write("started,until\n")
            fh.write(f"{now:.3f},{now + dur:.3f}\n")
        st.toast("Anomaly injection started", icon="⚡")
    if left > 0:
        c3.progress(min(left / max(cmd["until"] - cmd["started"], 1), 1.0),
                    text=f"Injecting abnormal traffic from the ESP32, {left:.0f} s remaining")
    elif not s["online"]:
        c3.caption("Unavailable: the ESP32 is offline.")
    else:
        c3.caption(f"Ready. The ESP32 floods the gateway; the time to detect depends on the alert rule "
                   f"({s['stats'].get('rule_name', '2-in-a-row')}, {s['stats'].get('window_seconds', 5):g} s windows).")


def ttd_rows(s):
    """Time from each Generate-anomaly command to the first alert (the dashboard times every burst)."""
    live, cm = s["live"], s["cmds"]
    if cm.empty or live.empty or "ts" not in live.columns:
        return pd.DataFrame()
    rows = []
    for c in cm.itertuples():
        hit = live[(live["status"] == "anomaly") & (live["ts"] >= c.started - 0.5) & (live["ts"] <= c.until + 30)]
        done = len(hit) > 0
        pending = (not done) and time.time() < c.until + 20
        rows.append({"Command": datetime.fromtimestamp(c.started).strftime("%H:%M:%S"),
                     "Burst (s)": round(c.until - c.started),
                     "Time to detect (s)": round(float(hit["ts"].iloc[0] - c.started), 1) if done else None,
                     "Result": "detected" if done else ("waiting" if pending else "missed")})
    return pd.DataFrame(rows)


def ttd_panel(s):
    df = ttd_rows(s)
    st.markdown('<div class="sec">Time to detect</div>', unsafe_allow_html=True)
    stt = s["stats"]
    rule = stt.get("rule_name", "2-in-a-row")
    if df.empty:
        st.caption("Every Generate anomaly press is timed here: seconds from the command to the first alert. "
                   f"Current rule: {rule}, {stt.get('window_seconds', 5):g} s windows.")
        return
    got = df.dropna(subset=["Time to detect (s)"])
    c = st.columns(4)
    kpi(c[0], "Last time to detect", f'{got["Time to detect (s)"].iloc[-1]:.1f} s' if len(got) else "n/a", "command to first alert", CYAN)
    kpi(c[1], "Median", f'{got["Time to detect (s)"].median():.1f} s' if len(got) else "n/a", f"over {len(got)} detected bursts")
    kpi(c[2], "Bursts timed", len(df), "this session")
    kpi(c[3], "Detected", f"{len(got)} / {int((df['Result'] != 'waiting').sum())}", "", OK if len(got) else TEXT)
    st.dataframe(df.iloc[::-1].head(8), use_container_width=True, hide_index=True)
    hop = stt.get("hop_seconds", stt.get("window_seconds", 5))
    st.caption(f"Measured from the moment the command is issued, so it includes the device picking the command up "
               f"(up to about 2 s). Rule: {rule}; {stt.get('window_seconds', 5):g} s windows, a decision every {hop:g} s.")


# ------------------------------------------------------------------ pages
def recording_banner():
    rec = rj("recording.json")
    if not rec or time.time() - rec.get("updated", 0) > 10:
        return
    el = time.time() - rec["t0"] if rec.get("t0") else 0
    est = rec.get("est_total_s", 1)
    burst = "BURST" in rec["phase"]
    col = BAD if burst else VIOLET
    st.markdown(H(f'<div class="panel" style="border-color:{col}"><h4 style="color:{col}">'
                  f'Recording experiment: {rec["run"]}</h4><div class="note">{rec["phase"]} &middot; '
                  f'bursts so far: {rec["bursts_done"]}/{rec["bursts_total"]} &middot; elapsed {int(el // 60)}:{int(el % 60):02d}'
                  f' of about {int(est // 60)} min. The ESP32 is sending real traffic; every burst is timed against ground truth.'
                  f'</div></div>'), unsafe_allow_html=True)
    st.progress(min(el / est, 1.0))


def page_overview(s):
    recording_banner()
    cls, head, sub, badge = status_of(s)
    ts = datetime.fromtimestamp(s["stats"]["last_analysis"]).strftime("%H:%M:%S") if s["stats"] else "—"
    st.markdown(H(f'<div class="hero {cls}"><div><div class="k">Security state</div><div class="v">{head}</div>'
                  f'<div class="s">{sub}</div></div><div class="badge">{badge}</div></div>'), unsafe_allow_html=True)
    if s["phase"]["phase"] == "learning":
        tot = max(s["phase"].get("total", 1), 1)
        st.progress(min(s["phase"].get("done", 0) / tot, 1.0),
                    text=f"Baseline {s['phase'].get('done', 0)} / {tot} windows. Leave the ESP32 alone.")
    stt = s["stats"]
    c = st.columns(4)
    kpi(c[0], "Captured packets", f'{stt.get("total_packets", 0):,}', "Wireshark, this session", CYAN)
    kpi(c[1], "Traffic windows", stt.get("windows", 0), f'{stt.get("window_seconds", 5)} s each')
    kpi(c[2], "Detection status", head.split()[0], f"Last analysis {ts}",
        BAD if cls == "bad" else OK if cls == "ok" else AMBER if cls == "warn" else CYAN)
    kpi(c[3], "Flagged windows", stt.get("flagged", 0), "potential anomalies", BAD if stt.get("flagged") else TEXT)
    st.markdown('<div class="sec">Network intelligence</div>', unsafe_allow_html=True)
    topology(s)
    st.markdown('<div class="sec">Live traffic</div>', unsafe_allow_html=True)
    a, b = st.columns([2, 1])
    live = s["live"].tail(80)
    if len(live):
        fig = go.Figure(go.Scatter(x=live["time"], y=live["packet_count"], fill="tozeroy",
                                   line=dict(color=CYAN, width=2), fillcolor="rgba(53,214,242,.16)",
                                   name="Packets"))
        fl = live[live["status"] == "anomaly"]
        fig.add_trace(go.Scatter(x=fl["time"], y=fl["packet_count"], mode="markers", name="Flagged",
                                 marker=dict(color=BAD, size=10, line=dict(color="#fff", width=1))))
        a.plotly_chart(style(fig, 300, "Packets per time window"), use_container_width=True)
        counts = live["status"].value_counts()
        b.plotly_chart(style(go.Figure(go.Pie(
            labels=["Normal" if k == "normal" else "Suspicious" if k == "anomaly" else "Idle" for k in counts.index],
            values=counts.values, hole=.65, marker=dict(colors=[OK if k == "normal" else BAD if k == "anomaly" else MUTED
                                                                  for k in counts.index]))), 300, "Normal vs suspicious"),
                       use_container_width=True)
    else:
        st.info("Charts appear once live detection has produced its first window.")
    attack_panel(s, "ov")


def page_traffic(s):
    live, pk = s["live"].tail(120), s["pk"]
    st.markdown('<div class="sec">Traffic analytics</div>', unsafe_allow_html=True)
    if len(live):
        a, b = st.columns(2)
        a.plotly_chart(style(go.Figure(go.Scatter(x=live["time"], y=live["packet_count"], fill="tozeroy",
                        line=dict(color=CYAN), fillcolor="rgba(53,214,242,.16)")), 300, "Packets per window"),
                       use_container_width=True)
        b.plotly_chart(style(go.Figure([
            go.Scatter(x=live["time"], y=live["bytes_received"], name="Incoming to device", line=dict(color=VIOLET)),
            go.Scatter(x=live["time"], y=live["bytes_sent"], name="Outgoing from device", line=dict(color=CYAN))]),
            300, "Incoming vs outgoing bytes"), use_container_width=True)
        c, d = st.columns(2)
        c.plotly_chart(style(go.Figure(go.Bar(x=live["time"], y=live["connection_count"], marker_color=VIOLET)),
                             280, "Connections per window"), use_container_width=True)
        if len(pk):
            pc = pk["Protocol"].value_counts()
            d.plotly_chart(style(go.Figure(go.Pie(labels=pc.index, values=pc.values, hole=.6,
                           marker=dict(colors=[CYAN, VIOLET, OK, AMBER, BAD, MUTED]))), 280, "Traffic distribution"),
                           use_container_width=True)
    else:
        st.info("Waiting for live traffic windows.")
    if len(pk):
        st.plotly_chart(style(go.Figure(go.Histogram(x=pk["Length"], nbinsx=30, marker_color=CYAN)), 260,
                              "Packet-size distribution (bytes)"), use_container_width=True)
        st.markdown('<div class="sec">Wireshark packet feed</div>', unsafe_allow_html=True)
        q = st.text_input("Filter", "", placeholder="e.g. SYN, HTTP, 8000", key="pkfilter")
        view = pk.iloc[::-1]
        if q:
            view = view[view.apply(lambda r: q.lower() in " ".join(map(str, r)).lower(), axis=1)]
        st.dataframe(view, use_container_width=True, height=420, hide_index=True)
        st.caption("Live capture of the device's packets via tshark (newest first, last 200).")


def page_threat(s):
    live = s["live"]
    base = baseline_mean()
    flagged = live[live["status"] == "anomaly"].copy() if len(live) else pd.DataFrame()
    if len(flagged):
        flagged.insert(0, "Window ID", flagged.index + 1)
        flagged["Severity"] = [severity(p, base) for p in flagged["packet_count"]]
        flagged["Classification"] = "Potential anomaly"
    st.markdown('<div class="sec">Security operations</div>', unsafe_allow_html=True)
    attack_panel(s, "td")
    ttd_panel(s)
    c = st.columns(4)
    kpi(c[0], "Anomaly windows", len(flagged), "potential anomalies", BAD if len(flagged) else TEXT)
    kpi(c[1], "Normal windows", int((live["status"] == "normal").sum()) if len(live) else 0, "", OK)
    kpi(c[2], "Latest score", f'{s["last"]["anomaly_score"]:+.3f}' if s["last"] is not None else "—",
        "higher = more unusual")
    sev = flagged["Severity"].value_counts() if len(flagged) else pd.Series(dtype=int)
    c[3].markdown(H('<div class="kpi"><div class="l">Severity</div><div class="n" style="font-size:1.1rem;padding-top:8px">'
                    + "".join(f'<span class="sev {k}">{k} {int(sev.get(k, 0))}</span> ' for k in ("High", "Medium", "Low"))
                    + '</div><div class="d">by traffic volume vs baseline</div></div>'), unsafe_allow_html=True)
    if len(live):
        a, b = st.columns(2)
        fig = go.Figure()
        for st_name, colr in (("normal", OK), ("anomaly", BAD)):
            d = live[live["status"] == st_name]
            if len(d):
                fig.add_trace(go.Histogram(x=d["anomaly_score"], name="Normal" if st_name == "normal" else "Suspicious",
                                           marker_color=colr, opacity=.85, nbinsx=24))
        fig.update_layout(barmode="overlay")
        a.plotly_chart(style(fig, 280, "Anomaly score distribution"), use_container_width=True)
        pts = go.Figure(go.Scatter(x=live["time"], y=live["anomaly_score"], mode="lines+markers",
                                   line=dict(color=VIOLET), marker=dict(color=[BAD if x == "anomaly" else VIOLET
                                                                               for x in live["status"]], size=7)))
        b.plotly_chart(style(pts, 280, "Anomaly score over time"), use_container_width=True)

    st.markdown('<div class="sec">Investigation</div>', unsafe_allow_html=True)
    if len(flagged):
        cols = ["Window ID", "time", "packet_count", "bytes_sent", "bytes_received", "connection_count",
                "anomaly_score", "Severity", "Classification"]
        st.dataframe(flagged[cols].iloc[::-1], use_container_width=True, hide_index=True, height=260)
        wid = st.selectbox("Inspect window", list(flagged["Window ID"].iloc[::-1]), key="inspect")
        r = flagged[flagged["Window ID"] == wid].iloc[0]
        st.dataframe(pd.DataFrame({"Parameter": ["Window ID", "Time", "Packets", "Bytes sent", "Bytes received",
                                                 "Connections", "Anomaly score", "Severity", "Classification"],
                                   "Value": [int(r["Window ID"]), r["time"], int(r["packet_count"]),
                                             int(r["bytes_sent"]), int(r["bytes_received"]),
                                             int(r["connection_count"]), f'{r["anomaly_score"]:+.4f}',
                                             r["Severity"], r["Classification"]]}),
                     hide_index=True, use_container_width=True)
        st.download_button("Export suspicious traffic records (CSV)", flagged[cols].to_csv(index=False).encode(),
                           "suspicious_windows.csv", "text/csv")
    else:
        st.info("No suspicious windows yet. Press Generate anomaly to see the detection end to end.")
    st.markdown('<div class="note">Isolation Forest identifies unusual behaviour. A flagged window is a '
                '<b>potential anomaly</b>, not a confirmed cyberattack.</div>', unsafe_allow_html=True)

    st.markdown('<div class="sec">Historical analysis</div>', unsafe_allow_html=True)
    up = st.file_uploader("Upload a traffic-features CSV (packet_count, bytes_sent, bytes_received, "
                          "connection_count, duration_seconds)", type="csv", key="hist")
    if up is not None:
        try:
            from anomaly_detector import detect_anomalies
            df = pd.read_csv(up)
            res = pd.concat([df.reset_index(drop=True), detect_anomalies(df).reset_index(drop=True)], axis=1)
            res["classification"] = res["status"]
            st.metric("Potential anomalies", int((res["prediction"] == -1).sum()), f"of {len(res)} windows")
            st.dataframe(res, use_container_width=True, hide_index=True)
        except Exception as e:  # noqa: BLE001
            st.error(f"Could not analyse that file: {e}")


def page_devices(s):
    d, online = s["dev"], s["online"]
    st.markdown('<div class="sec">IoT infrastructure</div>', unsafe_allow_html=True)
    c = st.columns(4)
    kpi(c[0], "ESP32 connectivity", "Online" if online else "Offline", f'last packet {ago(d.get("last_seen"))}',
        OK if online else BAD)
    kpi(c[1], "Device IP", d.get("ip", "—") if online else "—", "learned from heartbeat", CYAN)
    kpi(c[2], "Wi-Fi signal", f'{d["rssi"]} dBm' if online and d.get("rssi") else "—", "RSSI at the ESP32")
    mode = "Burst" if online and d.get("flooding") else "Normal" if online else "—"
    kpi(c[3], "Transmission", mode, f'{d.get("requests", 0):,} requests received', BAD if mode == "Burst" else OK)
    st.write("")
    topology(s)
    st.markdown('<div class="sec">DHT22 sensor</div>', unsafe_allow_html=True)
    if online and d.get("sensor_ok"):
        a, b, c3 = st.columns(3)
        kpi(a, "Temperature", f'{d["temperature"]:.1f} °C', "simulated" if s["sim"] else "live from the DHT22", OK)
        kpi(b, "Humidity", f'{d["humidity"]:.0f} %', "simulated" if s["sim"] else "live from the DHT22", OK)
        kpi(c3, "Reading age", ago(d.get("sensor_time")), "")
        sl = rc(LOGS / "sensor_log.csv").tail(120)
        if len(sl):
            st.plotly_chart(style(go.Figure([
                go.Scatter(x=sl["time"], y=sl["temperature"], name="Temperature °C", line=dict(color=AMBER)),
                go.Scatter(x=sl["time"], y=sl["humidity"], name="Humidity %", line=dict(color=CYAN))]),
                280, "DHT22 telemetry"), use_container_width=True)
    else:
        st.markdown(H(f'<div class="panel"><h4 style="color:{AMBER}">No valid DHT22 reading</h4>'
                      '<div class="note">The ESP32 is online but the sensor is not returning data, so no '
                      'temperature or humidity is shown (values are never faked). Check: data pin to GPIO 4, '
                      'power to 3.3 V, ground to GND, and a 10 kΩ pull-up between data and 3.3 V on a bare '
                      '4-pin sensor. Network detection is unaffected.</div></div>'), unsafe_allow_html=True)


def page_model(s):
    st.markdown('<div class="sec">Model intelligence</div>', unsafe_allow_html=True)
    mp = BASE / "models" / "isolation_forest.joblib"
    base = rc(BASE / "datasets" / "esp32_normal.csv")
    c = st.columns(4)
    kpi(c[0], "Algorithm", "Isolation Forest", "200 trees, unsupervised", VIOLET)
    kpi(c[1], "Training windows", len(base), "normal ESP32 traffic via Wireshark")
    kpi(c[2], "Trained", datetime.fromtimestamp(mp.stat().st_mtime).strftime("%d %b %H:%M") if mp.exists() else "—",
        "contamination 0.05")
    st_ = s["stats"]
    kpi(c[3], "Alert rule", st_.get("rule_name", "2-in-a-row"),
        f"{st_.get('window_seconds', 5):g} s windows, decision every {st_.get('hop_seconds', st_.get('window_seconds', 5)):g} s", CYAN)

    st.markdown('<div class="sec">Live session evaluation</div>', unsafe_allow_html=True)
    live = s["live"]
    if len(live) and "injected" in live.columns and live["injected"].sum() > 0:
        y = live["injected"].astype(int)
        p = (live["status"] == "anomaly").astype(int)
        tp, fp = int(((y == 1) & (p == 1)).sum()), int(((y == 0) & (p == 1)).sum())
        fn, tn = int(((y == 1) & (p == 0)).sum()), int(((y == 0) & (p == 0)).sum())
        metrics_block(tp, fp, fn, tn, live, y)
        st.caption("Ground truth = windows during which 'Generate anomaly' was active. The 2-window "
                   "confirmation rule adds a short lag, which counts as missed windows.")
    else:
        st.info("Press Generate anomaly on the Threat Detection page. The windows it produces become labelled "
                "ground truth and this section computes precision, recall and F1 from your own session.")

    st.markdown('<div class="sec">Offline evaluation (synthetic demo dataset)</div>', unsafe_allow_html=True)
    ev = rc(LOGS / "model_evaluation.csv")
    if len(ev):
        r = ev.iloc[0]
        metrics_block(int(r["true_positives"]), int(r["false_positives"]), int(r["false_negatives"]),
                      int(r["true_negatives"]), None, None, offline=r)
        st.caption("From logs/model_evaluation.csv: the original model scored on the labelled synthetic dataset. "
                   "Kept separate from live traffic; it does not describe the current ESP32 model.")


def metrics_block(tp, fp, fn, tn, live, y, offline=None):
    tot = tp + fp + fn + tn
    if offline is not None:
        acc, pre, rec, f1, fpr, auc = (offline["accuracy"], offline["precision"], offline["recall"],
                                       offline["f1_score"], offline["false_positive_rate"], offline["roc_auc"])
    else:
        acc = (tp + tn) / tot if tot else 0
        pre = tp / (tp + fp) if tp + fp else 0
        rec = tp / (tp + fn) if tp + fn else 0
        f1 = 2 * pre * rec / (pre + rec) if pre + rec else 0
        fpr = fp / (fp + tn) if fp + tn else 0
        auc = None
        if y is not None and y.nunique() == 2:
            from sklearn.metrics import roc_auc_score
            auc = roc_auc_score(y, live["anomaly_score"])
    m = st.columns(6)
    for col, (lbl, v) in zip(m, [("Accuracy", acc), ("Precision", pre), ("Recall", rec), ("F1-score", f1),
                                 ("ROC-AUC", auc), ("False-positive rate", fpr)]):
        kpi(col, lbl, f"{v:.1%}" if v is not None and lbl != "ROC-AUC" else f"{v:.3f}" if v is not None else "n/a")
    z = [[tn, fp], [fn, tp]]
    fig = go.Figure(go.Heatmap(z=z, x=["Pred normal", "Pred anomaly"], y=["Actual normal", "Actual anomaly"],
                               text=z, texttemplate="%{text}", textfont=dict(size=22),
                               colorscale=[[0, CARD], [1, CYAN]], showscale=False))
    fig.update_layout(yaxis_autorange="reversed")
    st.plotly_chart(style(fig, 280, "Confusion matrix"), use_container_width=True)


CFG_COLORS = [CYAN, VIOLET, OK, AMBER, BAD, "#7DD3FC"]


def page_research(s):
    path = BASE / "experiments" / "results" / "results.json"
    st.markdown('<div class="sec">Research: time to detect versus false alarms</div>', unsafe_allow_html=True)
    if not path.exists():
        st.info("No study results yet. Record two runs with experiments/run_trials.py and analyse them with "
                "experiments/evaluate_rules.py.")
        return
    R = json.loads(path.read_text())
    det = "hybrid"
    live, live_if = R["live_rule"][det], R["live_rule"]["if"]
    held = [e for e in R["held_out"] if e.get("detector") == det]
    curves = pd.DataFrame(R["curves"])
    curves = curves[curves["detector"] == det]
    runs = R["runs"]
    st.markdown(H(f'<div class="panel"><h4>Question</h4><div class="note">The detector first decided once per '
                  f'5-second window and alerted after two flagged windows. How much faster can it react, does a sequential (CUSUM) '
                  f'rule beat the fixed k-in-a-row rule, and what does that cost in false alarms? '
                  f'Measured on the real ESP32: {sum(r["bursts"] for r in runs)} commanded bursts in '
                  f'{len(runs)} independent recordings ({sum(r["minutes"] for r in runs):.0f} minutes, '
                  f'{sum(r["packets"] for r in runs):,} packets). Each burst starts at a random time with exact ground truth. '
                  f'Rules and parameters are chosen on one recording and reported on the other.</div></div>'),
                unsafe_allow_html=True)

    budget = st.radio("False-alarm budget", R["config"]["budgets"], horizontal=True, index=0,
                      format_func=lambda b: f"at most {b} per hour", key="budget")
    ok = [e for e in held if e["budget"] == budget and e.get("feasible")]
    best = min(ok, key=lambda e: (e["median"], e["fa_per_hour"])) if ok else None
    c = st.columns(4)
    kpi(c[0], "Earlier rule (decide every 5 s)", f'{live["median"]:.1f} s', f'median, 2-in-a-row, 5 s windows', TEXT)
    if best:
        gain = (1 - best["median"] / live["median"]) * 100 if live["median"] else 0
        kpi(c[1], "Best held-out rule", f'{best["median"]:.1f} s', f'W={best["window"]:g}s, hop {best["hop"]:g}s, {best["rule"]}', OK)
        kpi(c[2], "Faster by", f"{gain:.0f}%", f'false alarms {best["fa_per_hour"]:.1f}/h', OK if gain > 0 else AMBER)
        kpi(c[3], "Detected", f'{best["detected"]} / {best["n"]}', "held-out bursts")
    else:
        for col in c[1:]:
            kpi(col, "n/a", "—", "no rule met the budget")

    # plain verdict: sequential (CUSUM) rule against the fixed k-in-a-row rule, same window and decision interval
    pair = [(f, c2) for f in ok if f["rule"] == "fixed" for c2 in ok
            if c2["rule"] == "cusum" and (c2["window"], c2["hop"]) == (f["window"], f["hop"]) and f["window"] == 5 and f["hop"] == 1]
    if pair:
        f, c2 = pair[0]
        verdict = ("no faster than" if c2["median"] >= f["median"] else "faster than")
        st.markdown(H(f'<div class="panel"><h4>Sequential rule against the fixed rule</h4><div class="note">With 5 s windows decided every second, '
                      f'the sequential (CUSUM) rule detects in a median of <b>{c2["median"]:.1f} s</b> ({c2["fa_per_hour"]:.1f} false alarms per hour), '
                      f'which is {verdict} the fixed 2-in-a-row rule at <b>{f["median"]:.1f} s</b> ({f["fa_per_hour"]:.1f} per hour). '
                      f'These bursts are very large, so there is little subtle evidence to accumulate; a sequential rule may still help for weaker anomalies, '
                      f'which were not tested.</div></div>'), unsafe_allow_html=True)

    miss ={k: f"{v['detected']}/{v['n']}" for k, v in live_if["per_run"].items()}
    st.markdown(H(f'<div class="panel" style="border-color:{AMBER}"><h4 style="color:{AMBER}">Finding: the Isolation Forest alone is not enough</h4>'
                  f'<div class="note">With the Isolation Forest only, the live rule detected {live_if["detected"]} of {live_if["n"]} bursts '
                  f'({", ".join(f"{k}: {v}" for k, v in miss.items())}). A tree ensemble cannot extrapolate: every window far outside the '
                  f'training range gets the same score as the most extreme training window, and depending on the 4-minute baseline that '
                  f'score can look normal. The live detector therefore adds a range check (any feature above {R["config"]["env_ratio"]:g} x its '
                  f'baseline maximum). All results on this page use that hybrid detector.</div></div>'), unsafe_allow_html=True)

    # ---- operating curves
    fig = go.Figure()
    df = curves[(curves["detect_rate"] >= 0.9) & np.isfinite(curves["median"])] if len(curves) else curves
    for i, (w, h) in enumerate(sorted({(r["window"], r["hop"]) for r in curves.to_dict("records")})):
        for rule, dash in (("cusum", "solid"), ("fixed", "dot")):
            d = df[(df["window"] == w) & (df["hop"] == h) & (df["rule"] == rule)].sort_values("fa_per_hour")
            if d.empty:
                continue
            fig.add_trace(go.Scatter(x=d["fa_per_hour"], y=d["median"], mode="lines+markers",
                                     name=f"W={w:g}s hop {h:g}s, {rule}", line=dict(color=CFG_COLORS[i % 6], dash=dash),
                                     marker=dict(size=6), hovertemplate="%{x:.1f} false alarms/h<br>%{y:.1f} s median<extra></extra>"))
    fig.add_trace(go.Scatter(x=[live["fa_per_hour"]], y=[live["median"]], mode="markers", name="earlier rule (every 5 s)",
                             marker=dict(symbol="star", size=18, color="#ffffff", line=dict(color=BAD, width=2))))
    fig.update_xaxes(title="False alarms per hour (lower is better)")
    fig.update_yaxes(title="Median time to detect, seconds (lower is better)")
    st.plotly_chart(style(fig, 420, "Every configuration: speed against false alarms (solid = CUSUM, dotted = k in a row)"),
                    use_container_width=True)

    # ---- held-out table
    st.markdown('<div class="sec">Held-out results at the chosen budget</div>', unsafe_allow_html=True)
    rows = []
    for e in sorted(ok, key=lambda e: e["median"]):
        rows.append({"Window (s)": e["window"], "Hop (s)": e["hop"], "Rule": e["rule"],
                     "Chosen parameter": " / ".join(str(x) for x in e["chosen"]),
                     "Median TTD (s)": round(e["median"], 1),
                     "95% CI": f'{e["median_ci"][0]:.1f} to {e["median_ci"][1]:.1f}',
                     "p90 (s)": round(e["p90"], 1), "Detected": f'{e["detected"]}/{e["n"]}',
                     "False alarms / h": round(e["fa_per_hour"], 1)})
    rows.append({"Window (s)": live["window"], "Hop (s)": live["hop"], "Rule": "fixed (earlier, every 5 s)",
                 "Chosen parameter": "2", "Median TTD (s)": round(live["median"], 1),
                 "95% CI": f'{live["median_ci"][0]:.1f} to {live["median_ci"][1]:.1f}', "p90 (s)": round(live["p90"], 1),
                 "Detected": f'{live["detected"]}/{live["n"]}', "False alarms / h": round(live["fa_per_hour"], 1)})
    st.dataframe(pd.DataFrame(rows), use_container_width=True, hide_index=True)

    # ---- distribution
    if best:
        cdf = go.Figure()
        series = [("live rule (5 s, 2 in a row)", live["ttd"], "#ffffff")]
        bf = min([e for e in ok if e["rule"] == "fixed"], key=lambda e: e["median"], default=None)
        bc = min([e for e in ok if e["rule"] == "cusum"], key=lambda e: e["median"], default=None)
        if bf:
            series.append((f'best fixed: W={bf["window"]:g}s hop {bf["hop"]:g}s', bf["ttd"], VIOLET))
        if bc:
            series.append((f'best CUSUM: W={bc["window"]:g}s hop {bc["hop"]:g}s', bc["ttd"], CYAN))
        for name, vals, col in series:
            v = np.sort(np.array([x for x in vals if x is not None and np.isfinite(x)], dtype=float))
            if len(v):
                cdf.add_trace(go.Scatter(x=v, y=np.arange(1, len(v) + 1) / len(vals), mode="lines", name=name,
                                         line=dict(color=col, width=3, shape="hv")))
        cdf.update_xaxes(title="Time to detect (s)")
        cdf.update_yaxes(title="Share of bursts detected by then", tickformat=".0%", range=[0, 1.02])
        st.plotly_chart(style(cdf, 340, "Distribution of time to detect (held-out bursts)"), use_container_width=True)

    st.markdown('<div class="note">How to read this: the live system waits for 5-second windows and two flagged windows in a row. '
                'Shorter windows and more frequent decisions react sooner but see less traffic per decision, so they flag '
                'normal traffic more often. A sequential rule (CUSUM) accumulates evidence instead of counting a fixed run. '
                'Numbers come from the real ESP32 and a bounded number of bursts; confidence intervals are shown.</div>',
                unsafe_allow_html=True)


def page_presence(s):
    st.markdown('<div class="sec">Presence count (edge device)</div>', unsafe_allow_html=True)
    P = rj("presence_state.json")
    node = rj("presence_node.json")
    online = bool(node) and time.time() - node.get("last_seen", 0) < 10
    if not P:
        st.markdown(H('<div class="panel"><h4>Waiting for the presence node</h4><div class="note">Flash '
                      'esp32_presence_node.ino to the ESP32 (or run tools/simulate_presence.py) and keep gateway.py running. '
                      'The count appears here within a few seconds.</div></div>'), unsafe_allow_html=True)
        return
    sim = P.get("simulated")
    cfg = P["cfg"]
    c = st.columns(4)
    kpi(c[0], "Devices present", P["count"] if online else "—", "counted nearby, smoothed", OK if P["count"] else TEXT)
    kpi(c[1], "Heard right now", P["raw_count"], "before smoothing", CYAN)
    kpi(c[2], "Radio sees", P["heard"], f'{P["infrastructure"]} ignored as infrastructure')
    kpi(c[3], "Node", "Online" if online else "Offline", ("SIMULATED, " if sim else "") + f'last update {ago(node.get("last_seen"))}',
        OK if online else BAD)
    if sim:
        st.caption("Simulated node: the true number of people is known and drawn on the chart.")

    log = rc(LOGS / "presence_log.csv").tail(400)
    truth = rc(LOGS / "presence_truth.csv").tail(400)
    if len(log):
        fig = go.Figure()
        fig.add_trace(go.Scatter(x=pd.to_datetime(log["time"], unit="s"), y=log["raw_count"], name="Heard (raw)",
                                 line=dict(color=MUTED, width=1), mode="lines"))
        fig.add_trace(go.Scatter(x=pd.to_datetime(log["time"], unit="s"), y=log["count"], name="Estimate (smoothed)",
                                 line=dict(color=CYAN, width=3, shape="hv")))
        if len(truth):
            fig.add_trace(go.Scatter(x=pd.to_datetime(truth["time"], unit="s"), y=truth["true_count"], name="True count",
                                     line=dict(color=OK, width=2, dash="dot", shape="hv")))
        fig.update_yaxes(title="Devices", rangemode="tozero", dtick=1)
        st.plotly_chart(style(fig, 330, "Presence over time"), use_container_width=True)

    a, b = st.columns([3, 2])
    with a:
        st.markdown('<div class="sec">What the radio hears</div>', unsafe_allow_html=True)
        rows = pd.DataFrame(P["devices"])
        if len(rows):
            rows = rows.rename(columns={"h": "Device (hashed)", "r": "Signal dBm", "f": "Frames", "t": "Last heard (s)",
                                        "g": "Random address", "a": "On our network", "status": "Decision"})
            rows["On our network"] = rows["On our network"].map({1: "yes", 0: "no"})
            rows["Random address"] = rows["Random address"].map({1: "yes", 0: "no"})
            order = {"counted": 0, "too few frames": 1, "too far": 2, "other network": 3, "gone": 4, "infrastructure": 5}
            rows = rows.sort_values(by="Decision", key=lambda c: c.map(order))
            st.dataframe(rows, use_container_width=True, hide_index=True, height=280)
        st.caption("Addresses are hashed on the ESP32. The real addresses are never sent, stored or shown.")
    with b:
        st.markdown('<div class="sec">Controls</div>', unsafe_allow_html=True)
        if st.button("Learn the empty room", use_container_width=True, key="learn"):
            (LOGS / "presence_cmd.json").write_text(json.dumps({"calibrate": time.time()}))
            st.toast("Everything heard now is treated as infrastructure and ignored.")
        st.caption("Press once with nobody's phone or laptop in the room (the router, laptop and ESP32 stay). Needed after moving the setup.")
        rssi = st.slider("Counting range: weakest signal (dBm)", -90, -40, int(cfg["rssi_min"]), key="rssi_min")
        minf = st.slider("Frames needed before a device counts", 1, 10, int(cfg["min_frames"]), key="min_frames")
        everything = st.checkbox("Also count devices not on our network (noisy)", value=cfg.get("mode") == "all", key="mode_all")
        newcfg = {**cfg, "rssi_min": rssi, "min_frames": minf, "mode": "all" if everything else "network"}
        if newcfg != cfg:
            (LOGS / "presence_cfg.json").write_text(json.dumps(newcfg))
        st.caption("Stronger (closer to 0) range = only devices very close are counted.")
        with st.expander("Record the true count (accuracy test)"):
            truth_n = st.number_input("People actually in range now", 0, 50, 0, key="truth_n")
            if st.button("Save true count", key="truth_save"):
                f = LOGS / "presence_truth.csv"
                new = not f.exists() or f.stat().st_size == 0
                with open(f, "a", newline="") as fh:
                    if new:
                        fh.write("time,true_count,source" + chr(10))
                    fh.write(f"{time.time():.3f},{int(truth_n)},manual" + chr(10))
                st.toast("Saved.")

    st.markdown(H('<div class="note"><b>What this measures.</b> It counts devices that transmit near the ESP32, not people. '
                  'A sleeping phone, a person without a device or a device outside the range is not counted; '
                  'one person with two devices counts twice. Devices that are actively using the network are the '
                  'most reliable.</div>'), unsafe_allow_html=True)


# ------------------------------------------------------------------ layout
@st.fragment(run_every=2)
def topbar():
    s = load_state()
    cls = "ok" if s["online"] else "warn"
    if s["last"] is not None and s["last"]["status"] == "anomaly":
        cls = "bad"
    sim_badge = '<span style="color:#F5B544;font-weight:700">SIMULATED DEVICE</span>' if s["sim"] else ""
    label = {"ok": "NETWORK ONLINE", "warn": "DEVICE OFFLINE", "bad": "ANOMALY ACTIVE"}[cls]
    ts = datetime.fromtimestamp(s["stats"]["last_analysis"]).strftime("%H:%M:%S") if s["stats"] else "—"
    shield = (f'<svg width="30" height="30" viewBox="0 0 24 24" fill="none" stroke="{CYAN}" stroke-width="2">'
              '<path d="M12 2l8 3v6c0 5-3.5 9-8 11-4.5-2-8-6-8-11V5l8-3z"/><path d="M9 12l2 2 4-4"/></svg>')
    st.markdown(H(f'<div class="topbar"><div class="brand">{shield}SENTINEL<small>IoT Intrusion Detection</small></div>'
                  f'<div class="meta">{sim_badge}<span><span class="dot {cls}"></span>{label}</span>'
                  f'<span>Last analysis {ts}</span></div></div>'), unsafe_allow_html=True)


@st.fragment(run_every=2)
def body():
    s = load_state()
    {"Overview": page_overview, "Traffic": page_traffic, "Threat Detection": page_threat,
     "Devices": page_devices, "Model Insights": page_model, "Research": page_research, "Presence": page_presence}[st.session_state.get("nav", "Overview")](s)


if "nav" not in st.session_state and st.query_params.get("page") in PAGES:
    st.session_state["nav"] = st.query_params["page"]  # deep link: ?page=Traffic
topbar()
st.radio("Navigation", PAGES, horizontal=True, key="nav", label_visibility="collapsed")
body()
