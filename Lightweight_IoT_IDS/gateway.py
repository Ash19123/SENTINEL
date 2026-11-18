"""
Gateway: the server the ESP32 sends its DHT22 telemetry to.

It does no detection itself. It
  * logs the sensor readings and publishes the device heartbeat (device_status.json),
  * records the ESP32's IP so wireshark_ids.py knows which device to watch,
  * replies to every POST with the latest verdict from wireshark_ids.py
    (the ESP32 shows it on its LEDs) and, when the dashboard's "Generate anomaly"
    button was pressed, an "attack" flag that makes the ESP32 send a burst of
    traffic for a limited time.
"""

import csv
import json
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

from presence_engine import PresenceCounter

BASE_DIR = Path(__file__).resolve().parent
LOGS = BASE_DIR / "logs"
SENSOR_LOG = LOGS / "sensor_log.csv"
DEVICE_IP_FILE = LOGS / "device_ip.txt"
DEVICE_STATUS = LOGS / "device_status.json"
VERDICT = LOGS / "verdict.json"
ATTACK_CMD = LOGS / "attack_cmd.json"
PORT = 8000
VERDICT_MAX_AGE = 30  # seconds before a verdict is considered stale

stats = {"requests": 0, "first_seen": None}
presence = None            # PresenceCounter, created in __main__
presence_lock = threading.Lock()


def read_json(path):
    try:
        return json.loads(path.read_text())
    except (OSError, ValueError):
        return {}


def current_status():
    v = read_json(VERDICT)
    if v and time.time() - v.get("time", 0) < VERDICT_MAX_AGE:
        return v["status"]
    return "unknown"


def attack_active():
    return time.time() < read_json(ATTACK_CMD).get("until", 0)


def valid(x):
    return isinstance(x, (int, float)) and not isinstance(x, bool)


def log_sensor(data):
    new = not SENSOR_LOG.exists()
    with open(SENSOR_LOG, "a", newline="") as f:
        w = csv.writer(f)
        if new:
            w.writerow(["time", "temperature", "humidity"])
        w.writerow([time.strftime("%H:%M:%S"), data["temperature"], data["humidity"]])


class Handler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.0"  # one TCP connection per request, like the ESP32

    def do_POST(self):
        body = self.rfile.read(int(self.headers.get("Content-Length", 0)))
        try:
            data = json.loads(body)
        except ValueError:
            data = {}

        if self.path.startswith("/presence"):      # presence-counter node (a second kind of device)
            with presence_lock:
                state = presence.update(data, simulated=bool(data.get("simulated")))
            (LOGS / "presence_node.json").write_text(json.dumps(
                {"ip": self.client_address[0], "last_seen": time.time(), "rssi": data.get("rssi"),
                 "simulated": bool(data.get("simulated"))}))
            reply = json.dumps({"count": state["count"], "present": state["present"]},
                               separators=(",", ":")).encode()
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(reply)))
            self.end_headers()
            self.wfile.write(reply)
            return

        ip = self.client_address[0]
        if not DEVICE_IP_FILE.exists() or DEVICE_IP_FILE.read_text() != ip:
            DEVICE_IP_FILE.write_text(ip)
            print(f"ESP32 detected at {ip}")

        stats["requests"] += 1
        stats["first_seen"] = stats["first_seen"] or time.time()
        sensor_ok = valid(data.get("temperature")) and valid(data.get("humidity"))
        if sensor_ok and not data.get("flood"):
            log_sensor(data)

        status = {
            "ip": ip, "last_seen": time.time(), "requests": stats["requests"],
            "first_seen": stats["first_seen"], "rssi": data.get("rssi"),
            "flooding": bool(data.get("flood")), "sensor_ok": sensor_ok,
        }
        if sensor_ok:
            status["temperature"], status["humidity"] = data["temperature"], data["humidity"]
            status["sensor_time"] = time.time()
        else:  # keep the last valid reading, if any, so the UI can show its age
            old = read_json(DEVICE_STATUS)
            for k in ("temperature", "humidity", "sensor_time"):
                if k in old:
                    status[k] = old[k]
        DEVICE_STATUS.write_text(json.dumps(status))

        reply = json.dumps({"status": current_status(), "attack": attack_active()},
                           separators=(",", ":")).encode()  # compact: the ESP32 matches text
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(reply)))
        self.end_headers()
        self.wfile.write(reply)

    def log_message(self, *a):
        pass


if __name__ == "__main__":
    LOGS.mkdir(exist_ok=True)
    DEVICE_IP_FILE.unlink(missing_ok=True)  # learn the device afresh each run
    DEVICE_STATUS.unlink(missing_ok=True)
    ATTACK_CMD.unlink(missing_ok=True)
    presence = PresenceCounter(LOGS)
    print(f"Gateway listening on port {PORT}")
    ThreadingHTTPServer(("0.0.0.0", PORT), Handler).serve_forever()
