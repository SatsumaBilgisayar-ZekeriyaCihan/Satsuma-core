"""Satsuma Core action contract.

Rule YAML files are data, not executable code.  This module keeps the
translation from rule action names to the small, reviewable set of safe
broker operations explicit.  Unknown or unsupported actions fail closed and
are never treated as executable.

The collectors in this module are deliberately read-only.  They must not dump
process environments, process memory, credentials or arbitrary file contents.
"""
from __future__ import annotations

import json
import os
import re
import time
from pathlib import Path

# Public action contract used by the release documentation and broker.
SAFE_ACTIONS = (
    "record",
    "evidence",
    "auto_action",
    "bpf_inventory",
    "bpffs_inventory",
    "process_inventory",
    "network_inventory",
    "capability_inventory",
    "kernel_posture_snapshot",
    "correlation_request",
    # operator_review: ask_user legacy action'inin canonical karsiligi.
    # Destructive DEGILDIR; yalnizca kullanici onay kuyruguna (sentinel_requests)
    # bir istek yazar. Gercek kill/blok karari ayri response_policy gate'inden
    # ve kullanici onayindan gecer.
    "operator_review",
    # watch_file: file sensor tek basina bir dosyayi isaretlediginde (yanlis pozitif
    # olabilir) dosya karantinaya alinmaz; yakin takip listesine eklenir.
    # Destructive DEGILDIR; dosyayi degistirmez, yalnizca izler.
    "watch_file",
)

# Changes to this mapping must remain fail-closed: a value of MISSING means
# the contract name exists but no broker implementation is claimed.
ACTION_STATUS = {
    "record": "IMPLEMENTED",
    "evidence": "IMPLEMENTED",
    "auto_action": "IMPLEMENTED",
    "bpf_inventory": "IMPLEMENTED",
    "bpffs_inventory": "IMPLEMENTED",
    "process_inventory": "IMPLEMENTED",
    "network_inventory": "IMPLEMENTED",
    "capability_inventory": "IMPLEMENTED",
    "kernel_posture_snapshot": "IMPLEMENTED",
    "correlation_request": "IMPLEMENTED",
    "operator_review": "IMPLEMENTED",
    "watch_file": "IMPLEMENTED",
}

# Legacy names are kept as metadata aliases for the existing baseline rule set.
# They are not the preferred contract, but they must remain visible in an
# inventory rather than silently failing.
LEGACY_ACTION_ALIASES = {
    "log_only": "record",
    "ticket": "auto_action",
    "create_ticket": "auto_action",
    "ask_user": "operator_review",
    "kill_process": "process_kill",
    "block_ip": "network_isolate",
    "notify_admin": "notify",
    "quarantine_file": "file_quarantine",
}

# These names may appear in rules but must never be dispatched directly by a
# rule engine.  A separate destructive-response gate must authorize them.
UNSAFE_RULE_ACTION_ALIASES = {
    "process_kill",
    "network_isolate",
    "file_quarantine",
    "user_disable",
    "bpf_detach",
    "map_delete",
    "map_update",
    "xdp_detach",
    "tc_filter_delete",
    "session_terminate",
    "quarantine_file",
}

DESTRUCTIVE_ACTIONS = {
    "process_kill",
    "bpf_detach",
    "map_delete",
    "map_update",
    "xdp_detach",
    "tc_filter_delete",
    "network_isolate",
    "session_terminate",
    "file_quarantine",
    "user_disable",
}


def canonical_action(name: str) -> str:
    """Return the canonical action name for a rule/broker action token."""
    token = str(name or "").strip()
    return LEGACY_ACTION_ALIASES.get(token, token)


def is_safe_action(name: str) -> bool:
    return canonical_action(name) in SAFE_ACTIONS


def is_destructive_action(name: str) -> bool:
    return canonical_action(name) in DESTRUCTIVE_ACTIONS


def normalize_action_spec(value) -> list[str]:
    """Normalize the nested rule actions YAML into flat action tokens."""
    out: list[str] = []

    def walk(item) -> None:
        if isinstance(item, str):
            for token in re.split(r"[+,]", item):
                token = token.strip()
                if token and token not in out:
                    out.append(token)
        elif isinstance(item, dict):
            for nested in item.values():
                walk(nested)
        elif isinstance(item, (list, tuple, set)):
            for nested in item:
                walk(nested)

    walk(value)
    return out


def inventory_rules(rules) -> dict:
    """Build a deterministic action inventory from already-loaded rule dicts."""
    raw_counts: dict[str, int] = {}
    canonical_counts: dict[str, int] = {}
    contract: dict[str, dict] = {
        name: {
            "status": ACTION_STATUS.get(name, "MISSING"),
            "executable": ACTION_STATUS.get(name) == "IMPLEMENTED",
            "destructive": name in DESTRUCTIVE_ACTIONS,
        }
        for name in SAFE_ACTIONS
    }
    for rule in rules or []:
        actions = normalize_action_spec(rule.get("actions", []))
        for action in actions:
            raw_counts[action] = raw_counts.get(action, 0) + 1
            canonical = canonical_action(action)
            canonical_counts[canonical] = canonical_counts.get(canonical, 0) + 1
            if action not in LEGACY_ACTION_ALIASES and canonical not in contract:
                contract[canonical] = {
                    "status": "MISSING",
                    "executable": False,
                    "destructive": canonical in DESTRUCTIVE_ACTIONS,
                }
    return {
        "raw_counts": dict(sorted(raw_counts.items())),
        "canonical_counts": dict(sorted(canonical_counts.items())),
        "contract": contract,
        "unsafe_rule_actions": sorted(
            action for action in raw_counts if canonical_action(action) in DESTRUCTIVE_ACTIONS
        ),
        "legacy_metadata_actions": sorted(
            action for action in raw_counts if action in LEGACY_ACTION_ALIASES
        ),
        "missing_contract_actions": sorted(
            name for name, meta in contract.items() if meta.get("status") == "MISSING"
        ),
    }


# ---------------------------------------------------------------------------
# Safe, read-only collectors
# ---------------------------------------------------------------------------

def _read_text(path: str, max_bytes: int = 65536) -> str:
    try:
        with Path(path).open('rb') as stream:
            data = stream.read(max_bytes)
    except (OSError, PermissionError):
        raise
    return data[:max_bytes].decode("utf-8", "replace")


def bpf_inventory(limit: int = 512) -> list[dict]:
    """List BPF filesystem entries without following symlinks or reading maps."""
    root = Path("/sys/fs/bpf")
    out: list[dict] = []
    if not root.exists():
        return out
    stack = [root]
    while stack and len(out) < max(1, min(int(limit), 4096)):
        current = stack.pop()
        try:
            entries = list(current.iterdir())
        except (OSError, PermissionError):
            continue
        for entry in entries:
            if len(out) >= limit:
                break
            try:
                is_symlink = entry.is_symlink()
                is_dir = entry.is_dir()
            except OSError:
                continue
            if is_symlink:
                continue
            item = {"path": str(entry), "type": "dir" if is_dir else "file"}
            if not is_dir:
                try:
                    item["size"] = entry.stat().st_size
                except OSError:
                    pass
            out.append(item)
            if is_dir:
                stack.append(entry)
    return out


def bpffs_inventory() -> list[dict]:
    """Return only bpffs mount records from /proc/mounts (read-only)."""
    out: list[dict] = []
    for line in _read_text("/proc/mounts", 262144).splitlines():
        fields = line.split()
        if len(fields) >= 3 and fields[2] == "bpf":
            out.append({
                "source": fields[0],
                "mountpoint": fields[1],
                "type": fields[2],
                "options": fields[3] if len(fields) > 3 else "",
            })
    return out


def process_inventory(limit: int = 256) -> list[dict]:
    """Collect process metadata without cmdline/environment/secret dumping."""
    out: list[dict] = []
    proc = Path("/proc")
    try:
        pids = sorted(
            (p for p in proc.iterdir() if p.name.isdigit()),
            key=lambda p: int(p.name),
        )
    except (OSError, PermissionError):
        return out
    for p in pids[: max(1, min(int(limit), 4096))]:
        pid = int(p.name)
        item: dict = {"pid": pid}
        try:
            status = _read_text(str(p / "status"))
            for line in status.splitlines():
                if line.startswith("Name:"):
                    item["name"] = line.split(":", 1)[1].strip()
                elif line.startswith("Uid:"):
                    item["uid"] = line.split()[1]
                elif line.startswith("Gid:"):
                    item["gid"] = line.split()[1]
                elif line.startswith("PPid:"):
                    item["ppid"] = int(line.split()[1])
        except (ValueError, IndexError):
            pass
        try:
            item["exe"] = os.readlink(str(p / "exe"))
        except OSError:
            pass
        out.append(item)
    return out


def network_inventory(limit: int = 2048) -> dict:
    """Collect socket/interface metadata, never payloads or credentials."""
    result: dict = {"interfaces": [], "tcp": [], "udp": [], "ipv6": []}
    for line in _read_text("/proc/net/dev", 262144).splitlines()[2:]:
        if ":" not in line:
            continue
        name, rest = line.split(":", 1)
        fields = rest.split()
        if len(fields) >= 16:
            result["interfaces"].append({
                "name": name.strip(),
                "rx_bytes": int(fields[0]),
                "tx_bytes": int(fields[8]),
            })
    for proto in ("tcp", "udp"):
        path = f"/proc/net/{proto}"
        for line in _read_text(path, 262144).splitlines()[1:]:
            if len(result[proto]) >= limit:
                break
            fields = line.split()
            if len(fields) >= 10:
                result[proto].append({
                    "local": fields[1],
                    "remote": fields[2],
                    "state": fields[3],
                    "uid": fields[7],
                })
    for line in _read_text("/proc/net/if_inet6", 262144).splitlines():
        fields = line.split()
        if len(fields) >= 6:
            result["ipv6"].append({"address": fields[0], "iface": fields[5]})
    return result


def capability_inventory(pid: int | None = None) -> dict:
    """Read capability sets from /proc/<pid>/status for one process."""
    target = int(pid or os.getpid())
    status = _read_text(f"/proc/{target}/status")
    caps: dict[str, str] = {}
    for line in status.splitlines():
        if line.startswith(("CapInh:", "CapPrm:", "CapEff:", "CapBnd:", "CapAmb:")):
            key, value = line.split(":", 1)
            caps[key] = value.strip()
    return {"pid": target, "capabilities": caps}


def kernel_posture_snapshot() -> dict:
    """Small read-only sysctl snapshot; no kernel memory or module contents."""
    keys = (
        "kernel.kptr_restrict",
        "kernel.dmesg_restrict",
        "kernel.perf_event_paranoid",
        "kernel.unprivileged_bpf_disabled",
        "net.ipv4.ip_forward",
        "net.ipv4.conf.all.rp_filter",
    )
    out: dict[str, str] = {}
    for key in keys:
        path = "/proc/sys/" + key.replace(".", "/")
        value = _read_text(path, 4096).strip()
        if value:
            out[key] = value
    return {"timestamp": int(time.time()), "sysctls": out}


def full_process_inventory(limit: int = 256) -> list[dict]:
    return process_inventory(limit=limit)


# ---------------------------------------------------------------------------
# Minimal safe action broker
# ---------------------------------------------------------------------------

class SafeActionBroker:
    """Dispatch only non-destructive, allow-listed actions.

    Destructive names return ``blocked_destructive`` and must be routed through
    :mod:`satsuma.response_policy` by the response dispatcher.
    """

    def __init__(self, store, config=None):
        self.store = store
        self.config = config or {}

    @staticmethod
    def _evidence_metadata(context: dict) -> dict:
        """Keep safe process/evidence metadata; never dump memory or secrets."""
        finding = context.get("finding") if isinstance(context.get("finding"), dict) else {}
        event = context.get("event") if isinstance(context.get("event"), dict) else finding.get("event") or {}
        allowed = (
            "rule_id", "rule_name", "classification", "severity", "confidence",
            "category", "finding_id", "type", "timestamp", "summary",
        )
        out = {key: finding.get(key) for key in allowed if finding.get(key) is not None}
        out["event"] = {
            key: event.get(key)
            for key in ("id", "raw_id", "pid", "ppid", "uid", "euid", "exe", "cwd")
            if event.get(key) is not None
        }
        out["scope"] = "metadata_only"
        out["memory_dump"] = False
        out["credential_dump"] = False
        return out

    @staticmethod
    def _call_with_timeout(fn, timeout: float):
        import concurrent.futures

        executor = concurrent.futures.ThreadPoolExecutor(max_workers=1)
        future = executor.submit(fn)
        try:
            return future.result(timeout=timeout)
        except concurrent.futures.TimeoutError as exc:
            future.cancel()
            raise TimeoutError(f"collector timeout after {timeout:g}s") from exc
        finally:
            executor.shutdown(wait=False, cancel_futures=True)

    def _enqueue_operator_review(self, context: dict) -> dict:
        """operator_review: kullanici onay kuyruguna istek yaz.

        sentinel_requests tablosuna ``kind='approval'`` kaydi eklenir; sentinel
        DialogController bunu zenity popup'a cevirir. Kullanici 'Evet' derse
        islem mesru kabul edilir; 'Hayir' derse ilgili PID sonlandirilir.
        """
        finding = context.get("finding") if isinstance(context.get("finding"), dict) else {}
        event = context.get("event") if isinstance(context.get("event"), dict) else {}
        ext = (event.get("metadata") or {}).get("extensions") or {}
        pid = ext.get("host.pid") or finding.get("pid")
        cmd = ext.get("host.cmd") or finding.get("cmd") or ""
        uid = ext.get("host.uid")
        rule_id = finding.get("rule_id") or finding.get("type")
        finding_id = context.get("finding_id")
        # Ayni rule+pid icin tekrar popup uretmemek adina dedup.
        dedup_key = f"{rule_id}|{pid}|{finding_id}"
        try:
            from .sentinel import setup as sentinel_setup
            sentinel_setup(self.store.db)
        except Exception:
            return {"status": "failed", "action": "operator_review",
                    "reason": "sentinel_requests tablosu hazirlanamadi"}
        existing = self.store.db.execute(
            "SELECT 1 FROM sentinel_requests WHERE body LIKE ? "
            "AND status IN ('pending','yes','no','allow','block','running') LIMIT 1",
            (f'%{dedup_key}%',),
        ).fetchone()
        if existing:
            return {"status": "operator_review_duplicate", "action": "operator_review"}
        import uuid as _uuid
        ident = str(_uuid.uuid4())
        body = {
            "kind": "approval",
            "rule_id": rule_id,
            "rule_name": finding.get("rule_name"),
            "severity": finding.get("severity"),
            "classification": finding.get("classification"),
            "summary": finding.get("summary"),
            "pid": pid,
            "cmd": cmd,
            "uid": uid,
            "finding_id": finding_id,
            "dedup_key": dedup_key,
            "actions": finding.get("actions") or [],
        }
        self.store.db.execute(
            "INSERT INTO sentinel_requests(id,created,body,status) VALUES(?,?,?,'pending')",
            (ident, time.time(), json.dumps(body, ensure_ascii=True)),
        )
        self.store.db.commit()
        self.store.add("actions", {
            "timestamp": time.time(),
            "status": "operator_review_enqueued",
            "action": "operator_review",
            "request_id": ident,
            "rule_id": rule_id,
            "pid": pid,
        })
        return {"status": "operator_review_enqueued", "action": "operator_review",
                "request_id": ident}

    def _watch_file(self, context: dict) -> dict:
        """watch_file: file sensor'nin isaret ettigi dosyayi yakin takibe al.

        Destructive DEGILDIR. Dosyayi degistirmez; yalnizca watch_files
        listesine ekler. Takip edilen dosya calistirilir veya degisirse
        sys_proc_monitor yeni finding uretir.
        """
        finding = context.get("finding") if isinstance(context.get("finding"), dict) else {}
        event = context.get("event") if isinstance(context.get("event"), dict) else {}
        ext = (event.get("metadata") or {}).get("extensions") or {}
        path = (
            context.get("path")
            or finding.get("path")
            or ext.get("host.file")
            or ext.get("host.file_path")
            or ext.get("host.path")
            or event.get("file")
            or event.get("target")
        )
        if not isinstance(path, str) or not path.startswith("/"):
            return {"status": "watch_skipped", "action": "watch_file",
                    "reason": "missing_or_invalid_path"}
        try:
            from .watch_store import WatchStore
            result = WatchStore(self.store).add(
                path,
                reason=f"file sensor: {finding.get('rule_name') or finding.get('rule_id') or 'match'}",
                rule_id=finding.get("rule_id") or finding.get("type"),
                source="file_sensor",
            )
            return {"status": "watch_added", "action": "watch_file", "path": path,
                    "result": result}
        except Exception as exc:
            return {"status": "failed", "action": "watch_file",
                    "error": f"{type(exc).__name__}: {exc}"[:300]}

    def dispatch(self, action: str, context: dict | None = None) -> dict:
        context = context or {}
        canonical = canonical_action(action)
        from .ai_rule_package import is_ai_finding
        if is_ai_finding(context.get('finding')) and canonical not in ('record', 'evidence', 'correlation_request'):
            return {'status': 'blocked_ai_action', 'action': action, 'executed': False}
        if canonical in DESTRUCTIVE_ACTIONS:
            return {
                "status": "blocked_destructive",
                "action": action,
                "canonical_action": canonical,
                "reason": "destructive actions require response policy gate",
            }
        if canonical not in SAFE_ACTIONS:
            return {
                "status": "unknown_action",
                "action": action,
                "canonical_action": canonical,
            }
        try:
            if canonical == "record":
                if context.get("event") is not None or context.get("finding") is not None:
                    self.store.add("actions", {
                        "timestamp": time.time(),
                        "status": "recorded",
                        "action": action,
                        "event": context.get("event"),
                        "finding_id": context.get("finding_id"),
                    })
                return {"status": "recorded", "action": action}
            if canonical == "auto_action":
                finding = context.get("finding")
                if isinstance(finding, dict):
                    from .auto_action import AutoActionEngine
                    result = AutoActionEngine(self.store, self.config).process(finding)
                    return {"status": "auto_action_processed", "action": action, "result": result}
                return {
                    "status": "finding_required",
                    "action": action,
                    "finding_id": context.get("finding_id"),
                }
            if canonical == "evidence":
                evidence = self._evidence_metadata(context)
                self.store.add("safe_evidence", evidence)
                return {
                    "status": "evidence_metadata",
                    "action": action,
                    "evidence_id": context.get("evidence_id") or evidence.get("finding_id"),
                    "scope": "metadata_only",
                }
            if canonical == "correlation_request":
                self.store.add("actions", {
                    "timestamp": time.time(),
                    "status": "correlation_requested",
                    "action": action,
                    "scope": context.get("scope"),
                })
                return {"status": "correlation_requested", "action": action}
            if canonical == "operator_review":
                # Kullanici onay kuyruguna istek yaz. Gercek aksiyon (kill/blok)
                # kullanici kararindan ve response_policy gate'inden gecer.
                return self._enqueue_operator_review(context)
            if canonical == "watch_file":
                # file sensor tek basina isaretledigi dosyayi yakin takibe al.
                return self._watch_file(context)
            timeout = float(context.get("timeout", 5))
            collectors = {
                "bpf_inventory": lambda: bpf_inventory(int(context.get("limit", 512))),
                "bpffs_inventory": bpffs_inventory,
                "process_inventory": lambda: process_inventory(int(context.get("limit", 256))),
                "network_inventory": lambda: network_inventory(int(context.get("limit", 2048))),
                "capability_inventory": lambda: capability_inventory(context.get("pid")),
                "kernel_posture_snapshot": kernel_posture_snapshot,
            }
            data = self._call_with_timeout(collectors[canonical], timeout)
            return {
                "status": "collected",
                "action": action,
                "read_only": True,
                "data": data,
            }
        except Exception as exc:
            return {
                "status": "failed",
                "action": action,
                "error": f"{type(exc).__name__}: {exc}"[:300],
            }

def action_contract_report(rules) -> dict:
    inv = inventory_rules(rules)
    return {
        "safe_actions": list(SAFE_ACTIONS),
        "status": dict(ACTION_STATUS),
        "raw_rule_actions": inv["raw_counts"],
        "canonical_rule_actions": inv["canonical_counts"],
        "missing_contract_actions": inv["missing_contract_actions"],
        "destructive_actions": sorted(DESTRUCTIVE_ACTIONS),
    }
