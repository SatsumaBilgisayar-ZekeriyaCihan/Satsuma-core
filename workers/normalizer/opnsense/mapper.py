"""
Satsuma Worker — OPNsense / filterlog mapper
Görev: OPNsense filterlog + system syslog satırlarını Satsuma Unified Event alanlarına eşlemek.
Yapmaz: Yorumlama, puanlama, karar.
"""
from __future__ import annotations

from datetime import datetime, timezone
from typing import Any, Dict, Optional
from uuid import uuid4

# Classic filterlog CSV-like fields (OPNsense / pfSense)
# Example:
# filterlog: 10,,,1000000103,igb0,match,block,in,4,0x0,,64,0,0,DF,17,udp,40,192.168.1.10,8.8.8.8,12345,53,20
def parse_filterlog(message: str) -> Optional[Dict[str, Any]]:
    """Parse a documented pf filterlog CSV record without greedy regex shifts.

    IPv4 and IPv6 have different protocol field offsets. Reject malformed
    records rather than guessing at a source address.
    """
    import csv
    import io
    import ipaddress

    marker = "filterlog:"
    index = message.find(marker)
    if index < 0:
        return None
    try:
        fields = next(csv.reader(io.StringIO(message[index + len(marker):].strip())))
    except (csv.Error, StopIteration):
        return None
    if len(fields) < 17 or fields[8] not in ("4", "6"):
        return None
    version = int(fields[8])
    # 9 common CSV fields. The protocol/IP fields differ by IP version.
    proto_index, proto_id_index, length_index, src_index = (
        (16, 15, 17, 18) if version == 4 else (12, 13, 14, 15)
    )
    dst_index = src_index + 1
    if len(fields) <= dst_index:
        return None
    try:
        src = ipaddress.ip_address(fields[src_index])
        dst = ipaddress.ip_address(fields[dst_index])
    except ValueError:
        return None
    if src.version != version or dst.version != version:
        return None
    proto = fields[proto_index].lower()
    sport, dport = None, None
    if proto in ("tcp", "udp") and len(fields) > dst_index + 2:
        raw_sport, raw_dport = fields[dst_index + 1:dst_index + 3]
        if raw_sport.isdecimal() and raw_dport.isdecimal():
            values = int(raw_sport), int(raw_dport)
            if all(0 <= port <= 65535 for port in values):
                sport, dport = values
    return {
        "rule": fields[0], "tracker": fields[3],
        "iface": fields[4], "reason": fields[5],
        "action": fields[6].lower(),
        "direction": fields[7].lower(),
        "ip_version": str(version),
        "proto": proto, "proto_id": fields[proto_id_index],
        "length": int(fields[length_index]) if fields[length_index].isdecimal() else None,
        "src_ip": str(src), "dst_ip": str(dst),
        "src_port": sport, "dst_port": dport,
    }


def map_syslog_line(
    line: str,
    *,
    source_host: str = "opnsense",
    received_ts: Optional[float] = None,
) -> Optional[Dict[str, Any]]:
    """Map one syslog / filterlog line into a minimal Satsuma-compatible event dict."""
    if not line or not line.strip():
        return None
    line = line.strip()
    ts = received_ts
    # crude syslog timestamp skip if present
    # keep original message for raw
    fl = parse_filterlog(line)
    event_id = str(uuid4())
    base = {
        "id": event_id,
        "timestamp": int(ts or datetime.now(timezone.utc).timestamp()),
        "source": {
            "collector_id": "opnsense",
            "host": source_host,
            "type": "firewall" if fl else "syslog",
        },
        "raw": {"message": line[:2000]},
    }
    if fl:
        base.update({
            "action": fl["action"],
            "category": "firewall",
            "network": {
                "src_ip": fl.get("src_ip"),
                "dst_ip": fl.get("dst_ip"),
                "src_port": fl.get("src_port"),
                "dst_port": fl.get("dst_port"),
                "protocol": fl.get("proto"),
                "iface": fl.get("iface"),
                "direction": fl.get("direction"),
            },
            "metadata": {
                "extensions": {
                    "opnsense.rule": fl.get("rule"),
                    "opnsense.tracker": fl.get("tracker"),
                    "opnsense.reason": fl.get("reason"),
                    "opnsense.length": fl.get("length"),
                }
            },
        })
        # severity hint only (normalizer does not decide)
        if fl["action"] in ("block", "reject"):
            base["severity_hint"] = "medium"
        else:
            base["severity_hint"] = "info"
    else:
        base.update({
            "action": "log",
            "category": "system",
            "message": line[:500],
        })
    return base


def map_batch(lines: list, source_host: str = "opnsense") -> list:
    out = []
    now = datetime.now(timezone.utc).timestamp()
    for line in lines:
        ev = map_syslog_line(line, source_host=source_host, received_ts=now)
        if ev:
            out.append(ev)
    return out
