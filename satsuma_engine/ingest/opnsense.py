"""OPNsense filterlog CSV/syslog ayrıştırıcı."""
from __future__ import annotations
import csv, io, json, re, sys
from datetime import datetime, timezone
from typing import Any, Iterable, TextIO

_SYSLOG_PREFIX = re.compile(r"^(?:<\d+>)?(?P<ts>\w{3}\s+\d+\s+\d{2}:\d{2}:\d{2})\s+(?P<host>\S+)\s+filterlog:\s*(?P<csv>.*)$")

def parse_filterlog_line(line: str, host: str = "opnsense") -> dict[str, Any] | None:
    line = line.strip()
    if not line:
        return None
    match = _SYSLOG_PREFIX.match(line)
    csv_text, syslog_host = (match.group("csv"), match.group("host")) if match else (line, host)
    try:
        fields = next(csv.reader(io.StringIO(csv_text)))
    except csv.Error:
        return None
    if len(fields) < 20:
        return None

    proto = fields[16] if len(fields) > 16 else ""
    body: dict[str, Any] = {
        "timestamp": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "host": syslog_host or host,
        "kind": "network",
        "category": "network",
        "action": "firewall_" + (fields[6] or "unknown"),
        "src_ip": fields[18] or None,
        "dest_ip": fields[19] or None,
        "proto": proto or None,
        "firewall": {
            "interface": fields[4] or None,
            "action": fields[6] or None,
            "direction": fields[7] or None,
            "tracker": fields[3] or None
        }
    }
    if proto in {"tcp", "udp"} and len(fields) > 21:
        body["src_port"] = fields[20]
        body["dest_port"] = fields[21]
    if fields[6] == "block":
        body["outcome"] = "denied"
    elif fields[6] == "pass":
        body["outcome"] = "allowed"
    return {"id": None, "source": "opnsense", "event": body}

def cmd_ingest_opnsense(args: Any) -> int:
    with open(args.input, encoding="utf-8") as fh:
        events = [ev for line in fh if (ev := parse_filterlog_line(line, host=args.host))]
    for i, ev in enumerate(events, 1):
        ev["id"] = f"opn-{i:05d}"
    out: TextIO = open(args.out, "w", encoding="utf-8") if args.out else sys.stdout
    try:
        for ev in events:
            out.write(json.dumps(ev, ensure_ascii=False) + "\n")
    finally:
        if args.out:
            out.close()
    print(f"{len(events)} OPNsense log kaydı dönüştürüldü.", file=sys.stderr)
    return 0
