"""
Shared packet -> feature conversion, used by the live Wireshark IDS and the
offline PCAP tools.

Input rows come from tshark with these fields (one row per packet):
    time, length, src, dst, proto, sport, dport, protocol name, info
"""

import csv

import pandas as pd

TSHARK_FIELDS = [
    "frame.time_epoch", "frame.len", "ip.src", "ip.dst", "ip.proto",
    "tcp.srcport", "tcp.dstport", "udp.srcport", "udp.dstport",
    "_ws.col.protocol", "_ws.col.info",
]

PACKET_COLUMNS = ["time", "length", "src", "dst", "proto", "sport", "dport"]


def parse_tshark_line(line: str):
    """Turn one quoted-CSV tshark line into a packet row, or None."""
    try:
        parts = next(csv.reader([line.strip()]))
    except (StopIteration, csv.Error):
        return None
    if len(parts) < len(TSHARK_FIELDS):
        return None
    t, length, src, dst, proto, tsp, tdp, usp, udp, pname, info = parts[:11]
    if not t or not length or not src:
        return None
    sport, dport = (tsp, tdp) if tsp else (usp, udp)
    try:
        return (float(t), int(length), src, dst, proto, sport, dport, pname, info)
    except ValueError:
        return None


def window_features(packets, device_ip: str, window_seconds: float) -> dict:
    """
    Convert the packets of one time window into the 5 model features.

    bytes_sent      = bytes sent BY the device
    bytes_received  = bytes sent TO the device
    connection_count = distinct TCP/UDP flows
    """
    sent = received = 0
    flows = set()
    for _, length, src, dst, _, sport, dport, *_ in packets:
        if src == device_ip:
            sent += length
        if dst == device_ip:
            received += length
        if sport and dport:
            flows.add(tuple(sorted([(src, sport), (dst, dport)])))
    return {
        "packet_count": len(packets),
        "bytes_sent": sent,
        "bytes_received": received,
        "connection_count": len(flows),
        "duration_seconds": window_seconds,
    }


def packets_to_windows(packets, device_ip: str, window_seconds: float) -> pd.DataFrame:
    """Offline: split a list of packets into tumbling windows (by packet time)."""
    if not packets:
        return pd.DataFrame()
    packets = sorted(packets)
    start = packets[0][0]
    buckets = {}
    for p in packets:
        buckets.setdefault(int((p[0] - start) // window_seconds), []).append(p)
    rows = []
    for idx in sorted(buckets):
        feats = window_features(buckets[idx], device_ip, window_seconds)
        feats["window_start"] = round(start + idx * window_seconds, 3)
        rows.append(feats)
    return pd.DataFrame(rows)
