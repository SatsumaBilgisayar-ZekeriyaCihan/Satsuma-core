"""Satsuma Core — RAM / Memory monitoring (read-only evidence collector).

Collects /proc/meminfo and per-process RSS/VmRSS.
Emits evidence for anomalies; never kills processes by itself.
"""
from __future__ import annotations

import os
import time
from pathlib import Path
from typing import Any, Dict, List, Optional


def read_meminfo() -> Dict[str, int]:
    """Parse /proc/meminfo into kB values."""
    result: Dict[str, int] = {}
    try:
        text = Path("/proc/meminfo").read_text(encoding="utf-8", errors="replace")
    except OSError:
        raise
    for line in text.splitlines():
        if ":" not in line:
            continue
        key, rest = line.split(":", 1)
        parts = rest.strip().split()
        if not parts:
            continue
        try:
            result[key.strip()] = int(parts[0])
        except ValueError:
            continue
    return result


def read_process_rss(limit: int = 30) -> List[Dict[str, Any]]:
    """Return top processes by RSS (kB). Safe, best-effort."""
    entries: List[Dict[str, Any]] = []
    try:
        pids = [int(p.name) for p in Path("/proc").iterdir() if p.name.isdigit()]
    except OSError:
        raise

    for pid in pids:
        try:
            status = Path(f"/proc/{pid}/status").read_text(encoding="utf-8", errors="replace")
            rss_kb = 0
            name = ""
            uid = -1
            for line in status.splitlines():
                if line.startswith("Name:"):
                    name = line.split(":", 1)[1].strip()
                elif line.startswith("VmRSS:"):
                    parts = line.split()
                    if len(parts) >= 2:
                        rss_kb = int(parts[1])
                elif line.startswith("Uid:"):
                    parts = line.split()
                    if len(parts) >= 2:
                        uid = int(parts[1])
            if rss_kb <= 0:
                continue
            exe = None
            try:
                exe = os.readlink(f"/proc/{pid}/exe")
            except OSError:
                pass
            entries.append({
                "pid": pid,
                "name": name[:64],
                "rss_kb": rss_kb,
                "uid": uid,
                "exe": (exe or "")[:256],
            })
        except (OSError, ValueError, PermissionError):
            continue

    entries.sort(key=lambda x: x["rss_kb"], reverse=True)
    return entries[:limit]


def detect_anomalies(
    meminfo: Dict[str, int],
    processes: List[Dict[str, Any]],
    *,
    high_mem_pct: float = 92.0,
    single_proc_rss_mb: int = 2048,
    previous: Optional[Dict[str, Any]] = None,
) -> List[Dict[str, Any]]:
    """Return list of anomaly evidence dicts (no actions)."""
    anomalies: List[Dict[str, Any]] = []
    total = meminfo.get("MemTotal", 0)
    available = meminfo.get("MemAvailable", meminfo.get("MemFree", 0))
    if total <= 0:
        return anomalies

    used_pct = 100.0 * (1.0 - (available / total))
    if used_pct >= high_mem_pct:
        anomalies.append({
            "type": "memory_pressure",
            "severity": "high" if used_pct >= 97 else "medium",
            "classification": "suspicious",
            "summary": f"System memory pressure: {used_pct:.1f}% used",
            "mem_used_pct": round(used_pct, 1),
            "mem_total_kb": total,
            "mem_available_kb": available,
        })

    for proc in processes:
        rss_mb = proc["rss_kb"] / 1024.0
        if rss_mb >= single_proc_rss_mb:
            anomalies.append({
                "type": "high_rss_process",
                "severity": "medium",
                "classification": "indicator",
                "summary": f"High RSS process: {proc['name']} pid={proc['pid']} ({rss_mb:.0f} MB)",
                "pid": proc["pid"],
                "name": proc["name"],
                "rss_kb": proc["rss_kb"],
                "exe": proc.get("exe"),
                "uid": proc.get("uid"),
            })

    # Sudden drop in available memory (possible memory pressure / leak)
    if previous and isinstance(previous.get("mem_available_kb"), int):
        prev_avail = previous["mem_available_kb"]
        drop_kb = prev_avail - available
        if drop_kb > (total * 0.15) and drop_kb > 512 * 1024:  # >15% and >512MB drop
            anomalies.append({
                "type": "memory_drop",
                "severity": "high",
                "classification": "suspicious",
                "summary": f"Sudden available memory drop: {drop_kb // 1024} MB",
                "drop_kb": drop_kb,
                "mem_available_kb": available,
                "prev_available_kb": prev_avail,
            })

    return anomalies


class MemoryMonitor:
    """Periodic collector suitable for host team / worker loop."""

    name = "memory"

    def __init__(self, store=None, config: Optional[dict] = None):
        self.store = store
        self.config = config or {}
        self._last_snapshot: Optional[Dict[str, Any]] = None

    def collect(self) -> Dict[str, Any]:
        meminfo = read_meminfo()
        processes = read_process_rss(
            limit=int(self.config.get("memory_top_n", 25))
        )
        prev = self._last_snapshot
        if prev is None and self.store is not None:
            try:
                prev = self.store.get("worker.memory.prev")
            except Exception:
                raise
        anomalies = detect_anomalies(
            meminfo,
            processes,
            high_mem_pct=float(self.config.get("memory_high_pct", 92.0)),
            single_proc_rss_mb=int(self.config.get("memory_single_rss_mb", 2048)),
            previous=prev,
        )
        snapshot = {
            "timestamp": int(time.time()),
            "meminfo": {
                k: meminfo.get(k)
                for k in (
                    "MemTotal", "MemFree", "MemAvailable", "Buffers",
                    "Cached", "SwapTotal", "SwapFree", "AnonPages",
                    "Mapped", "Shmem", "SReclaimable",
                )
                if k in meminfo
            },
            "top_processes": processes[:15],
            "anomalies": anomalies,
        }
        self._last_snapshot = {
            "mem_available_kb": meminfo.get("MemAvailable", 0),
            "timestamp": snapshot["timestamp"],
        }
        if self.store is not None:
            try:
                self.store.set("worker.memory.prev", self._last_snapshot)
                self.store.set("worker.memory.last", snapshot)
                for a in anomalies:
                    self.store.add("memory_anomalies", {
                        **a,
                        "timestamp": snapshot["timestamp"],
                    })
            except Exception:
                raise
        return snapshot
