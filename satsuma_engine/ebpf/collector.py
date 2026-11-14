"""eBPF olay toplayıcı (Canlı BCC ve Simülasyon modları)."""
from __future__ import annotations
import argparse, json, os, sys
from datetime import datetime, timedelta, timezone
from typing import Any, TextIO
from .enrich import EnrichmentContext, enrich_event

COLLECTOR_SOURCE = "ebpf"

class CollectorError(Exception):
    pass

def _now() -> datetime:
    return datetime.now(timezone.utc)

def _envelope(idx: int, body: dict[str, Any]) -> dict[str, Any]:
    return {"id": f"ebpf-{idx:05d}", "source": COLLECTOR_SOURCE, "event": body}

def simulate_events(host: str = "srv-ebpf-01") -> list[dict[str, Any]]:
    """Bellek içi tehditleri ve eBPF zenginleştirmesini simüle eden 7 kural olayı."""
    base = _now() - timedelta(minutes=10)
    def ts(m: float) -> str:
        return (base + timedelta(minutes=m)).strftime("%Y-%m-%dT%H:%M:%SZ")

    bodies = [
        {"timestamp": ts(0), "host": host, "kind": "process", "category": "execution",
         "action": "process_start", "uid": 1000, "pid": 5100, "ppid": 900, "exe": "/usr/bin/python3",
         "ebpf": {"syscall": "execve", "ppid_chain": [900, 1]}, "identity": {"user": "appsvc", "container_id": None}},
        {"timestamp": ts(1), "host": host, "kind": "memory", "category": "defense-evasion",
         "action": "mprotect", "uid": 1000, "pid": 5122, "ppid": 5100, "exe": "/tmp/.hidden/loader",
         "memory": {"region_perms": "rwx", "mapping_type": "anonymous", "address": "0x7f3a2000", "size": 65536, "signed": False},
         "ebpf": {"syscall": "mprotect", "ppid_chain": [5100, 900, 1]}, "identity": {"user": "appsvc", "container_id": None}},
        {"timestamp": ts(2), "host": host, "kind": "memory", "category": "defense-evasion",
         "action": "ptrace_attach", "uid": 0, "pid": 5130, "ppid": 5122, "exe": "/tmp/.hidden/inject",
         "memory": {"target_pid": 4200, "target_exe": "/usr/sbin/sshd", "operation": "process_vm_writev"},
         "ebpf": {"syscall": "ptrace", "ppid_chain": [5122, 5100, 900, 1]}, "identity": {"user": "root", "container_id": None}},
        {"timestamp": ts(3), "host": host, "kind": "process", "category": "execution",
         "action": "process_start", "uid": 1000, "pid": 5141, "ppid": 5122, "exe": "/proc/self/fd/3",
         "memory": {"mapping_type": "memfd", "signed": False},
         "ebpf": {"syscall": "memfd_create", "ppid_chain": [5122, 5100, 900, 1]}, "identity": {"user": "appsvc", "container_id": None}},
        {"timestamp": ts(4), "host": host, "kind": "memory", "category": "defense-evasion",
         "action": "file_write", "uid": 0, "pid": 5150, "ppid": 5130, "exe": "/tmp/.hidden/inject",
         "path": "/proc/4200/mem", "operation": "write", "memory": {"target_pid": 4200, "target_exe": "/usr/sbin/sshd"},
         "ebpf": {"syscall": "openat", "ppid_chain": [5130, 5122, 5100, 900, 1]}, "identity": {"user": "root", "container_id": None}},
        {"timestamp": ts(5), "host": host, "kind": "process", "category": "execution",
         "action": "process_start", "uid": 1000, "pid": 5160, "ppid": 5141, "exe": "/tmp/.stage/payload (deleted)",
         "memory": {"mapping_type": "deleted_file", "signed": False},
         "ebpf": {"syscall": "execve", "ppid_chain": [5141, 5122, 5100, 900, 1]}, "identity": {"user": "appsvc", "container_id": None}},
        {"timestamp": ts(6), "host": host, "kind": "network", "category": "command-and-control",
         "action": "connect", "uid": 0, "pid": 5160, "exe": "/tmp/.stage/payload (deleted)",
         "dest_ip": "198.51.100.77", "dest_port": 8443, "proto": "tcp",
         "ebpf": {"syscall": "connect", "ppid_chain": [5141, 5122, 5100, 900, 1]},
         "identity": {"user": "root", "container_id": "9f3c1ab77d2e"}}
    ]
    return [_envelope(i + 1, b) for i, b in enumerate(bodies)]

def collect(out: TextIO, *, simulate: bool = False, host: str = "srv-ebpf-01", enrich: bool = True) -> int:
    ctx = EnrichmentContext()
    if simulate:
        events = simulate_events(host=host)
        if enrich:
            events = [enrich_event(e, ctx) for e in events]
        for event in events:
            out.write(json.dumps(event, ensure_ascii=False) + "\n")
        return len(events)
    raise CollectorError("Canlı eBPF için root yetkisi ve BCC gerekir. Test için --simulate kullanın.")

def build_collect_parser(subparsers: argparse._SubParsersAction) -> argparse.ArgumentParser:
    p = subparsers.add_parser("collect", help="eBPF ile canlı/simüle olay topla")
    p.add_argument("--simulate", action="store_true", help="sentetik eBPF olayları üret")
    p.add_argument("--host", default="srv-ebpf-01", help="makine adı")
    p.add_argument("--no-enrich", action="store_true", help="zenginleştirmeyi atla")
    p.add_argument("--out", help="çıktı JSONL dosyası")
    return p

def cmd_collect(args: argparse.Namespace) -> int:
    out = open(args.out, "w", encoding="utf-8") if args.out else sys.stdout
    try:
        count = collect(out, simulate=args.simulate, host=args.host, enrich=not args.no_enrich)
    finally:
        if args.out:
            out.close()
    print(f"{count} olay toplandı.", file=sys.stderr)
    return 0
