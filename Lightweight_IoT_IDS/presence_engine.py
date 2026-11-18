"""
Presence counting: turns the ESP32's table of nearby Wi-Fi devices into a count.

The ESP32 listens passively on the Wi-Fi channel it is connected to and keeps, for every transmitter it
hears, a *hashed* address (the real MAC is never sent or stored), the average signal strength, how many
frames it has sent and how long ago it was last heard. This module decides which of those are "people's
devices" and counts them.

A device is counted when
  * it is not in the infrastructure list (the access point, the laptop, the ESP32 itself and anything else
    that was present when "Learn the empty room" was pressed),
  * in the default "network" mode it has been seen sending data to our own access point (devices of other
    networks on the same channel are ignored; "all" mode also counts unconnected devices, which is noisier),
  * its signal is at least `rssi_min` dBm (close enough to be in the room),
  * it has sent at least `min_frames` frames, so a single stray frame does not count, and
  * it was heard within the last `window_s` seconds.
The reported count is the median of the last few raw counts, which removes one-off glitches.

Limit, stated plainly: this counts *devices that transmit*, not people. Phones that are asleep, or people
with no device, are not counted, and one person with two devices counts twice.
"""

import json
import statistics
import time
from collections import deque
from pathlib import Path

DEFAULT_CFG = {"rssi_min": -75, "min_frames": 3, "window_s": 30, "smooth": 3, "mode": "network"}


class PresenceCounter:
    def __init__(self, logs: Path):
        self.logs = Path(logs)
        self.cfg_path = self.logs / "presence_cfg.json"
        self.cmd_path = self.logs / "presence_cmd.json"
        self.infra_path = self.logs / "presence_infra.json"
        self.state_path = self.logs / "presence_state.json"
        self.log_path = self.logs / "presence_log.csv"
        self.recent = deque(maxlen=15)
        self.handled = 0.0
        self.infra = set(self._read(self.infra_path, {}).get("hashes", []))

    @staticmethod
    def _read(path, default):
        try:
            return json.loads(Path(path).read_text())
        except (OSError, ValueError):
            return default

    def cfg(self):
        c = dict(DEFAULT_CFG)
        c.update(self._read(self.cfg_path, {}))
        return c

    def _commands(self, devices):
        cmd = self._read(self.cmd_path, {})
        if cmd.get("reset", 0) > self.handled:
            self.infra = set()
            self.infra_path.write_text(json.dumps({"hashes": [], "time": time.time()}))
            self.recent.clear()
        if cmd.get("calibrate", 0) > self.handled:
            self.infra = {d["h"] for d in devices}
            self.infra_path.write_text(json.dumps({"hashes": sorted(self.infra), "time": time.time()}))
            self.recent.clear()
        self.handled = max(self.handled, cmd.get("calibrate", 0), cmd.get("reset", 0))

    def update(self, snapshot, simulated=False):
        """snapshot: {"device": str, "boot": int, "devices": [{"h", "r", "f", "t", "g"}]}. Returns the new state."""
        now = time.time()
        devices = [d for d in snapshot.get("devices", []) if isinstance(d.get("h"), str)]
        self._commands(devices)
        cfg = self.cfg()
        rows, raw = [], 0
        for d in devices:
            rssi, frames, age = d.get("r", -100), d.get("f", 0), d.get("t", 999)
            if d["h"] in self.infra:
                status = "infrastructure"
            elif cfg.get("mode", "network") == "network" and not d.get("a", 0):
                status = "other network"
            elif age > cfg["window_s"]:
                status = "gone"
            elif rssi < cfg["rssi_min"]:
                status = "too far"
            elif frames < cfg["min_frames"]:
                status = "too few frames"
            else:
                status = "counted"
                raw += 1
            rows.append({"h": d["h"], "r": rssi, "f": frames, "t": age, "g": int(d.get("g", 0)), "a": int(d.get("a", 0)), "status": status})
        self.recent.append(raw)
        tail = list(self.recent)[-max(1, int(cfg["smooth"])):]
        count = int(round(statistics.median(tail)))
        state = {"time": now, "count": count, "raw_count": raw, "present": count > 0,
                 "heard": len(devices), "infrastructure": len(self.infra), "devices": rows,
                 "node": snapshot.get("device", "esp32-presence"), "boot": snapshot.get("boot"),
                 "simulated": bool(simulated), "cfg": cfg}
        self.state_path.write_text(json.dumps(state))
        with open(self.logs / "presence_trace.jsonl", "a") as tf:   # which devices were counted, moment by moment
            tf.write(json.dumps({"time": now, "count": count, "counted": [
                {k: r[k] for k in ("h", "r", "f", "t")} for r in rows if r["status"] == "counted"]}) + chr(10))
        new = not self.log_path.exists() or self.log_path.stat().st_size == 0
        with open(self.log_path, "a", newline="") as f:
            if new:
                f.write("time,count,raw_count,heard,simulated\n")
            f.write(f"{now:.3f},{count},{raw},{len(devices)},{int(bool(simulated))}\n")
        return state
