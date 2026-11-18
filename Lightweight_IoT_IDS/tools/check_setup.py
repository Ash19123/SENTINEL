"""
Preflight check: is this laptop ready to run the SENTINEL demo?

    python tools/check_setup.py            checks the laptop-only demo and the ESP32 demo
    python tools/check_setup.py --hardware also checks the Wi-Fi band for the ESP32

Every line starts with [OK], [WARN] or [FAIL] and says how to fix a problem.
"""

import argparse
import importlib
import platform
import re
import shutil
import socket
import subprocess
import sys
from pathlib import Path

BASE = Path(__file__).resolve().parent.parent
ap = argparse.ArgumentParser()
ap.add_argument("--hardware", action="store_true", help="also check the Wi-Fi band for the ESP32")
args = ap.parse_args()

results = []


def report(level, msg, fix=""):
    results.append(level)
    print(f"[{level}] {msg}" + (f"\n       fix: {fix}" if fix and level != "OK" else ""))


# --- Python
v = sys.version_info
report("OK" if v >= (3, 9) else "FAIL", f"Python {v.major}.{v.minor}.{v.micro}",
       "Install Python 3.9 or newer from python.org and tick 'Add to PATH'.")
report("OK" if platform.system() == "Windows" else "WARN", f"Operating system: {platform.system()}",
       "The project was built and tested on Windows 10/11 only.")

# --- Python packages
for mod, pipname in [("pandas", "pandas"), ("sklearn", "scikit-learn"), ("joblib", "joblib"),
                     ("streamlit", "streamlit"), ("plotly", "plotly")]:
    try:
        m = importlib.import_module(mod)
        report("OK", f"{pipname} {getattr(m, '__version__', '')}".strip())
    except ImportError:
        report("FAIL", f"{pipname} is not installed", "pip install streamlit pandas scikit-learn plotly joblib")

# --- Wireshark / tshark
tshark = None
for c in (r"C:\Program Files\Wireshark\tshark.exe", r"C:\Program Files (x86)\Wireshark\tshark.exe"):
    if Path(c).exists():
        tshark = c
        break
tshark = tshark or shutil.which("tshark")
if not tshark:
    report("FAIL", "tshark (Wireshark) not found", "Install Wireshark from wireshark.org and keep the Npcap option ticked.")
else:
    try:
        ver = subprocess.run([tshark, "--version"], capture_output=True, text=True, timeout=20).stdout.splitlines()[0]
        report("OK", ver)
        out = subprocess.run([tshark, "-D"], capture_output=True, text=True, timeout=20, encoding="utf-8", errors="replace").stdout
        report("OK" if "Loopback" in out else "FAIL", "Npcap loopback adapter (needed for the laptop-only demo)"
               + ("" if "Loopback" in out else " not found"),
               "Re-run the Wireshark installer and repair Npcap (current Npcap includes loopback capture).")
        wifi = [l for l in out.splitlines() if re.search(r"wi-?fi|wireless|wlan", l, re.I)]
        if wifi:
            report("OK", "Wi-Fi capture adapter: " + wifi[0].split(" ", 1)[1].strip()[:70])
        else:
            report("WARN", "No Wi-Fi adapter name found in 'tshark -D'",
                   "For the ESP32 demo, run start with --interface \"<adapter name from tshark -D>\".")
        probe = subprocess.run([tshark, "-i", "\\Device\\NPF_Loopback", "-a", "duration:1"],
                               capture_output=True, text=True, timeout=30)
        ok = probe.returncode == 0
        report("OK" if ok else "FAIL", "Capturing packets works (permission to capture)",
               "Run the terminal as Administrator, or reinstall Npcap and allow non-administrators to capture.")
    except Exception as e:  # noqa: BLE001
        report("FAIL", f"tshark could not be run: {e}")

# --- ports
for port, what in ((8000, "gateway"), (8501, "dashboard")):
    s = socket.socket()
    s.settimeout(1)
    busy = s.connect_ex(("127.0.0.1", port)) == 0
    s.close()
    report("WARN" if busy else "OK", f"Port {port} ({what}) is " + ("already in use" if busy else "free"),
           "Close any earlier SENTINEL window or end the python.exe processes in Task Manager.")

# --- writable folders
try:
    (BASE / "logs").mkdir(exist_ok=True)
    t = BASE / "logs" / ".write_test"
    t.write_text("x")
    t.unlink()
    report("OK", f"Project folder is writable: {BASE}")
except OSError as e:
    report("FAIL", f"Cannot write to the project folder: {e}", "Copy the project to a folder you own, e.g. Documents.")

# --- laptop address / Wi-Fi band (ESP32 demo)
if platform.system() == "Windows":
    try:
        ip = subprocess.run(["powershell", "-NoProfile", "-Command",
                             "(Get-NetIPConfiguration | Where-Object {$_.InterfaceAlias -eq 'Wi-Fi'}).IPv4Address.IPAddress"],
                            capture_output=True, text=True, timeout=20).stdout.strip()
        band = subprocess.run(["netsh", "wlan", "show", "interfaces"], capture_output=True, text=True, timeout=20).stdout
        mband = re.search(r"Band\s*:\s*(\S+ ?GHz)", band)
        ssid = re.search(r"^\s*SSID\s*:\s*(.+)$", band, re.M)
        if ip:
            print(f"[INFO] Laptop Wi-Fi address (use as GATEWAY_IP in the ESP32 sketch): {ip}")
        if ssid:
            print(f"[INFO] Connected Wi-Fi network: {ssid.group(1).strip()}")
        if mband:
            is24 = "2.4" in mband.group(1)
            if args.hardware:
                report("OK" if is24 else "FAIL", f"Wi-Fi band: {mband.group(1)}",
                       "The ESP32 only works on 2.4 GHz. Switch the hotspot/router to 2.4 GHz and reconnect the laptop.")
            else:
                print(f"[INFO] Wi-Fi band: {mband.group(1)} (the ESP32 needs 2.4 GHz; the laptop-only demo does not)")
    except Exception:  # noqa: BLE001
        pass

print()
fails, warns = results.count("FAIL"), results.count("WARN")
if fails:
    print(f"RESULT: {fails} problem(s) to fix before the demo.")
elif warns:
    print(f"RESULT: ready, with {warns} warning(s) to look at.")
else:
    print("RESULT: ready. Start the demo with start_simulated.bat (no hardware) or start.bat (ESP32).")
sys.exit(1 if fails else 0)
