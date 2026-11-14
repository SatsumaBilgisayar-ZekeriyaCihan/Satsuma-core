"""Satsuma Core — BPF program / map inventory and safe unload helpers.

Read-only inventory by default. Unload is only available via typed action
after broker + policy checks.
"""
from __future__ import annotations

import json
import os
import re
import shutil
import subprocess
import time
from pathlib import Path
from typing import Any, Dict, List, Optional


def _run_bpftool(args: List[str], timeout: int = 8) -> Optional[str]:
    bpftool = shutil.which("bpftool")
    if not bpftool:
        raise FileNotFoundError('bpftool unavailable; kernel BPF inventory not verified')
    try:
        r = subprocess.run(
            [bpftool, *args],
            capture_output=True,
            text=True,
            timeout=timeout,
            check=False,
        )
        if r.returncode != 0:
            raise RuntimeError('bpftool inventory failed: '+(r.stderr or '')[:200])
        return r.stdout
    except (OSError, subprocess.TimeoutExpired):
        raise


def list_programs() -> List[Dict[str, Any]]:
    """Return loaded BPF programs (best-effort via bpftool)."""
    out = _run_bpftool(["-j", "prog", "show"])
    if not out:
        raise RuntimeError('Empty bpftool program response')
    try:
        data = json.loads(out)
    except json.JSONDecodeError:
        raise
    programs = []
    if isinstance(data, list):
        for item in data:
            if not isinstance(item, dict):
                continue
            programs.append({
                "id": item.get("id"),
                "type": item.get("type") or item.get("prog_type"),
                "name": item.get("name") or "",
                "tag": item.get("tag") or "",
                "loaded_at": item.get("loaded_at"),
                "uid": item.get("uid"),
                "gpl_compatible": item.get("gpl_compatible"),
                "bytes_xlated": item.get("bytes_xlated"),
                "bytes_jited": item.get("bytes_jited"),
                "map_ids": item.get("map_ids") or [],
                "pinned": item.get("pinned") or [],
            })
    return programs


def list_maps() -> List[Dict[str, Any]]:
    out = _run_bpftool(["-j", "map", "show"])
    if not out:
        raise RuntimeError('Empty bpftool map response')
    try:
        data = json.loads(out)
    except json.JSONDecodeError:
        raise
    maps = []
    if isinstance(data, list):
        for item in data:
            if not isinstance(item, dict):
                continue
            maps.append({
                "id": item.get("id"),
                "type": item.get("type"),
                "name": item.get("name") or "",
                "flags": item.get("flags"),
                "bytes_key": item.get("bytes_key"),
                "bytes_value": item.get("bytes_value"),
                "max_entries": item.get("max_entries"),
                "pinned": item.get("pinned") or [],
            })
    return maps


def list_pins(base: str = "/sys/fs/bpf") -> List[str]:
    pins: List[str] = []
    root = Path(base)
    if not root.is_dir():
        return pins
    try:
        for p in root.rglob("*"):
            if p.is_file() or p.is_symlink():
                pins.append(str(p))
    except OSError:
        pass
    return pins[:500]


def _fallback_prog_list() -> List[Dict[str, Any]]:
    """Minimal inventory when bpftool is missing."""
    pins = list_pins()
    return []  # Pins alone cannot prove loaded program identities.


def inventory() -> Dict[str, Any]:
    try:
        progs = list_programs()
        maps = list_maps()
    except (OSError, ValueError, RuntimeError, subprocess.TimeoutExpired) as exc:
        return {'timestamp':time.time(),'status':'UNAVAILABLE','program_count':None,'map_count':None,
                'programs':[],'maps':[],'pins':list_pins(),'error':str(exc)[:300],
                'bpftool_available':shutil.which('bpftool') is not None}

    pins = list_pins()
    return {
        "timestamp": int(time.time()),
        "status": "COMPLETED",
        "bpftool_available": shutil.which("bpftool") is not None,
        "program_count": len(progs),
        "map_count": len(maps),
        "pin_count": len(pins),
        "programs": progs[:100],
        "maps": maps[:100],
        "pins": pins[:100],
    }


def unload_program(prog_id: int) -> Dict[str, Any]:
    """Unload a BPF program by id. Requires root + bpftool.

    Returns status dict. Caller must already have passed broker/policy checks.
    """
    if not isinstance(prog_id, int) or prog_id <= 0:
        return {"status": "invalid_id", "id": prog_id}
    bpftool = shutil.which("bpftool")
    if not bpftool:
        return {"status": "bpftool_missing", "id": prog_id}
    try:
        r = subprocess.run(
            [bpftool, "prog", "delete", "id", str(prog_id)],
            capture_output=True,
            text=True,
            timeout=10,
            check=False,
        )
        if r.returncode == 0:
            return {"status": "unloaded", "id": prog_id}
        return {
            "status": "failed",
            "id": prog_id,
            "stderr": (r.stderr or "")[:300],
            "returncode": r.returncode,
        }
    except (OSError, subprocess.TimeoutExpired) as exc:
        return {"status": "error", "id": prog_id, "error": str(exc)[:200]}


def remove_pin(path: str) -> Dict[str, Any]:
    """Remove a BPF pin under /sys/fs/bpf (resolved path, no symlink escape)."""
    if not isinstance(path, str) or "\x00" in path:
        return {"status": "invalid_path", "path": path}
    try:
        # Resolve symlinks; require final path still under /sys/fs/bpf/
        resolved = Path(path).resolve(strict=False)
        root = Path("/sys/fs/bpf").resolve()
        try:
            resolved.relative_to(root)
        except ValueError:
            return {"status": "invalid_path", "path": path, "resolved": str(resolved)}
        if not resolved.exists():
            return {"status": "not_found", "path": str(resolved)}
        if resolved.is_dir():
            return {"status": "refused_directory", "path": str(resolved)}
        resolved.unlink()
        return {"status": "removed", "path": str(resolved)}
    except OSError as exc:
        return {"status": "error", "path": path, "error": str(exc)[:200]}


class BpfInventoryWorker:
    name = "bpf_inventory"

    def __init__(self, store=None, config: Optional[dict] = None):
        self.store = store
        self.config = config or {}

    def collect(self) -> Dict[str, Any]:
        data = inventory()
        if self.store is not None:
            try:
                self.store.set("worker.bpf.last", data)
            except Exception:
                raise
        return data
