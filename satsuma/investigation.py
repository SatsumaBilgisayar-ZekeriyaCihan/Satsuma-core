"""Satsuma Core — Investigation Engine.

Finding → local investigation → process role tracking → user warning. Since
2.2.30 each investigation record carries its source event's identity (pid,
user, program, command) and source rule, so the panel no longer shows the
process as unknown. Every rule defines one role: the triggering process is
the "process to stop", so "no defined role in the process chain" is gone.

Bulgu → yerel araştırma → süreç rolü takibi → kullanıcı uyarısı. 2.2.30'dan
beri her inceleme kaydı kaynak olayın kimliğini (pid, kullanıcı, program,
komut) ve kaynak kuralını taşır; panel süreci artık "Bilinmiyor" göstermez.
Her kural tek bir rol tanımlar: tetikleyen süreç "öldürülecek süreç"tir;
"Süreç zincirinde tanımlı rol bulunamadı" artık çıkmaz.

Bulgu → yerel araştırma → süreç rolü takibi → kullanıcı uyarısı.

Tasarım ilkeleri:
- YEREL çalışır: dış AI bağımlılığı yok, internet gerekmez.
- Web araştırması İSTEĞE BAĞLI ve varsayılan KAPALI (gizlilik korunur).
- Bir bulgu geldiğinde, o saldırı türünde "rol oynayan süreçleri" tanımlar
  (attack_roles.yaml) ve süreç ağacında bu rolleri arar.
- Bulunan kritik süreçler için kullanıcıya uyarı üretir.

Bu modül ticket üretmez; ticket yalnızca yönetim panelinden görülür.
Investigation, bulguyu zenginleştirir ve uyarı üretir.
"""
from __future__ import annotations
import hashlib

import json
import os
import time
from pathlib import Path
from typing import Any

try:
    import yaml
except ImportError:  # pragma: no cover - yaml her zaman mevcut olmalı
    yaml = None


BUNDLED_ROLES = Path(__file__).resolve().parents[1] / "rules" / "attack_roles.yaml"
SYSTEM_ROLES = Path("/etc/satsuma-core/rules/attack_roles.yaml")

# Bulgu tipi → attack_roles anahtarı eşlemesi.
# Kural motoru bulgu tipini/rule_id'sini üretir; burada saldırı türüne çeviririz.
_TYPE_TO_ATTACK = {
    "reverse_shell": "reverse_shell",
    "fileless": "fileless_execution",
    "fileless_memfd": "fileless_execution",
    "tmp_exec": "fileless_execution",
    "ptrace_inject": "fileless_execution",
    "privilege_escalation_attempt": "privilege_escalation",
    "container_escape": "container_escape",
    "ssh_key_theft": "credential_access",
    "cred_store": "credential_access",
    "env_cred": "credential_access",
    "systemd_persist": "persistence",
    "shell_persist": "persistence",
    "cron_persist": "persistence",
    "log_wipe": "defense_evasion",
    "security_disable": "defense_evasion",
    "timestomp": "defense_evasion",
    "cryptomining": "cryptomining",
    "ransomware_encrypt": "ransomware",
    "ransomware_backup_wipe": "ransomware",
    "cloud_metadata": "cloud_metadata",
    "lolbin_pipe_shell": "lolbin",
    "obfuscated_exec": "lolbin",
    "dynamic_code": "lolbin",
    "tty_escape": "lolbin",
    "cloud_exfil": "credential_access",
    "covert_exfil": "credential_access",
}


def _load_roles() -> dict[str, Any]:
    """attack_roles.yaml'ı yükle (sistem > bundled önceliği)."""
    if yaml is None:
        return {}
    path = SYSTEM_ROLES if SYSTEM_ROLES.exists() else BUNDLED_ROLES
    if not path.exists():
        return {}
    try:
        with path.open(encoding="utf-8") as stream:
            data = yaml.safe_load(stream)
        return data if isinstance(data, dict) else {}
    except Exception as exc:
        raise RuntimeError("Attack role knowledge base unreadable") from exc


def _attack_type_for(finding: dict[str, Any]) -> str | None:
    """Bulgu tipini saldırı türüne çevir."""
    for key in ("type", "rule_id", "category", "dedup_group"):
        value = finding.get(key)
        if not value:
            continue
        value = str(value)
        # rule_id içinde geçen bilinen anahtar
        for token, attack in _TYPE_TO_ATTACK.items():
            if token in value:
                return attack
    return None


def _process_chain(store, pid: int, max_depth: int = 6) -> list[dict[str, Any]]:
    """PID'den yukarı doğru süreç ağacını çıkar (parent zinciri)."""
    chain: list[dict[str, Any]] = []
    seen: set[int] = set()
    current = pid
    depth = 0
    while current and current not in seen and depth < max_depth:
        seen.add(current)
        info = _read_proc(current)
        if not info:
            break
        chain.append(info)
        current = info.get("ppid")
        depth += 1
    return chain


def _read_proc(pid: int) -> dict[str, Any] | None:
    """Bir PID'nin süreç bilgisini oku (offline, /proc)."""
    base = Path(f"/proc/{pid}")
    if not base.exists():
        return None
    info: dict[str, Any] = {"pid": pid}
    try:
        info["cmd"] = (base / "cmdline").read_bytes().replace(b"\x00", b" ").decode("utf-8", "replace").strip()
    except OSError:
        info["cmd"] = ""
    try:
        info["exe"] = os.readlink(base / "exe")
    except OSError:
        info["exe"] = ""
    try:
        stat = (base / "stat").read_text(encoding="utf-8", errors="replace")
        # comm parantez içinde; ppid ondan sonraki 2. alan
        rparen = stat.rfind(")")
        fields = stat[rparen + 2:].split()
        info["ppid"] = int(fields[1]) if len(fields) > 1 else 0
        info["name"] = stat[stat.find("(") + 1:rparen]
    except (OSError, ValueError, IndexError):
        info["ppid"] = 0
        info["name"] = ""
    return info


def _match_roles(chain: list[dict[str, Any]], roles: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Süreç zincirinde tanımlı rolleri bul."""
    matched: list[dict[str, Any]] = []
    for proc in chain:
        haystack = f"{proc.get('name', '')} {proc.get('exe', '')} {proc.get('cmd', '')}".lower()
        for role in roles:
            pattern = str(role.get("process", "")).lower()
            if pattern and pattern in haystack:
                matched.append({
                    "pid": proc.get("pid"),
                    "name": proc.get("name"),
                    "cmd": proc.get("cmd"),
                    "role": role.get("role"),
                    "critical": bool(role.get("critical")),
                })
                break
    return matched


KILL_ROLE = "öldürülecek süreç"


def trigger_role(finding: dict[str, Any]) -> dict[str, Any] | None:
    """The single role every rule defines (user decision 2026-11-04): the process
    that triggered the finding is the one to stop. Log-only rules say so; whether
    it is actually stopped is still decided by the response policy gate.

    Her kuralın tanımladığı tek rol (kullanıcı kararı 2026-11-04): bulguyu
    tetikleyen süreç durdurulacak süreçtir. Yalnızca kayıt tutan kurallar bunu
    belirtir; gerçekten durdurulup durdurulmayacağına yine müdahale politikası
    karar verir.
    """
    event = source_identity(finding)
    pid = event.get("pid") or finding.get("pid")
    if pid in (None, ""):
        return None
    exe = str(event.get("exe") or "")
    cmd = str(event.get("cmd") or "")
    name = exe.rsplit("/", 1)[-1] or (cmd.split()[0].rsplit("/", 1)[-1] if cmd.split() else "")
    log_only = bool(finding.get("log_only"))
    return {"pid": pid, "name": name, "cmd": cmd[:300],
            "role": KILL_ROLE + (" (bu kural yalnızca kayıt tutar)" if log_only else ""),
            "critical": not log_only}


def _with_trigger(finding: dict[str, Any], roles: list[dict[str, Any]]) -> list[dict[str, Any]]:
    trigger = trigger_role(finding)
    if trigger is None:
        return roles
    rest = [r for r in roles if str(r.get("pid")) != str(trigger["pid"])]
    return [trigger] + rest


def investigate(store, finding: dict[str, Any], config: dict[str, Any] | None = None) -> dict[str, Any]:
    """Bir bulguyu araştır ve zenginleştirilmiş sonuç döndür.

    Returns:
        {
          'attack_type': str | None,
          'mitre': str | None,
          'description': str,
          'roles_played': [...],       # süreç ağacında bulunan roller
          'indicators': [...],
          'kill_chain': [...],
          'warning': str,              # kullanıcıya gösterilecek uyarı
        }
    """
    config = config or {}
    roles_db = _load_roles()
    attack_type = _attack_type_for(finding)

    result: dict[str, Any] = {
        "attack_type": attack_type,
        "mitre": None,
        "description": "",
        "roles_played": [],
        "indicators": [],
        "kill_chain": [],
        "warning": "",
        "investigated_at": int(time.time()),
    }

    if not attack_type or attack_type not in roles_db:
        # Bilinmeyen saldırı türü — yine de temel uyarı ve tetikleyen süreç rolü
        result["roles_played"] = _with_trigger(finding, [])
        result["warning"] = _build_warning(finding, {}, result["roles_played"]) if result["roles_played"] else _basic_warning(finding)
        return result

    attack = roles_db[attack_type]
    result["mitre"] = attack.get("mitre")
    result["description"] = attack.get("description", "")
    result["indicators"] = list(attack.get("indicators", []))
    result["kill_chain"] = list(attack.get("kill_chain", []))

    # Süreç zincirini çıkar ve rolleri eşleştir
    pid = finding.get("pid") or (finding.get("event") or {}).get("pid")
    if pid:
        try:
            chain = _process_chain(store, int(pid))
            result["roles_played"] = _match_roles(chain, attack.get("roles", []))
        except (ValueError, TypeError):
            pass

    result["roles_played"] = _with_trigger(finding, result["roles_played"])
    result["warning"] = _build_warning(finding, attack, result["roles_played"])

    return result


def _basic_warning(finding: dict[str, Any]) -> str:
    name = finding.get("summary") or finding.get("rule_name") or finding.get("type") or "Bilinmeyen bulgu"
    severity = finding.get("severity", "info")
    return f"[{severity.upper()}] {name} — inceleme gerekli."


def _build_warning(finding: dict[str, Any], attack: dict[str, Any], roles: list[dict[str, Any]]) -> str:
    name = finding.get("summary") or finding.get("rule_name") or attack.get("description", "Saldırı")
    severity = str(finding.get("severity", "info")).upper()
    lines = [f"[{severity}] {name}"]
    if attack.get("mitre"):
        lines.append(f"MITRE: {attack['mitre']}")
    if roles:
        lines.append("Rol oynayan süreçler:")
        for r in roles:
            flag = " (KRİTİK)" if r.get("critical") else ""
            lines.append(f"  - PID {r['pid']} {r['name']}: {r['role']}{flag}")
    else:
        lines.append("Süreç zincirinde tanımlı rol bulunamadı.")
    return "\n".join(lines)


def source_identity(finding: dict[str, Any]) -> dict[str, Any]:
    """Who did it: pid, user, program and command of the finding's own event."""
    event = finding.get("event") if isinstance(finding.get("event"), dict) else {}
    metadata = event.get("metadata") if isinstance(event.get("metadata"), dict) else {}
    ext = metadata.get("extensions") if isinstance(metadata.get("extensions"), dict) else {}
    identity = {}
    for key in ("pid", "ppid", "uid", "exe", "cmd", "parent_cmd", "starttime", "timestamp", "source"):
        value = event.get(key)
        if value in (None, ""):
            value = ext.get("host." + key)
        if value not in (None, ""):
            identity[key] = str(value)[:500] if isinstance(value, str) else value
    return identity


def investigate_and_record(store, finding: dict[str, Any], config: dict[str, Any] | None = None) -> dict[str, Any]:
    """Araştır ve sonucu event havuzuna yaz (finding_store dedup ile)."""
    result = investigate(store, finding, config)
    try:
        from .finding_store import record_finding
        record_finding(store, {
            "type": "investigation",
            "finding_id": "investigation:" + str(finding.get("finding_id") or hashlib.sha256(json.dumps(finding, sort_keys=True, default=str).encode()).hexdigest()),
            "rule_id": f"investigation:{result.get('attack_type') or finding.get('rule_id') or 'unknown'}",
            "source_rule_id": finding.get("rule_id"),
            "source_finding_id": finding.get("finding_id"),
            # Field 2026-11-04: the panel showed "Bilinmiyor" for process and PID
            # because the source event's identity was not carried over.
            "event": source_identity(finding),
            "summary": result.get("warning", "")[:200],
            "severity": finding.get("severity", "info"),
            "classification": "suspicious",
            "investigation": result,
        }, "investigation")
    except Exception as exc:
        store.add("errors", {"component": "investigation.persist", "error": str(exc)})
        raise
    return result
