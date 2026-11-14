"""PID-reuse-resistant process target identity checks.

A PID alone is never sufficient to terminate a process.  Immediately before a
kill the caller must prove all of the following:

1. PID matches the evidence (when the evidence carries a PID).
2. The detection-time/evidence start time is present and matches the live
   ``/proc/<pid>/stat`` starttime.
3. The evidence executable path is present and its canonical path matches the
   live ``/proc/<pid>/exe`` canonical path.
4. The live process is not PID 1 (the kernel refuses) and not the caller
   (it must finish the response). Since 2.2.38 no name and no Satsuma unit
   protects a process (owner, 2026-11-13): a rule match inside sshd, the
   journal or Satsuma itself means something got in, and it is stopped.

The module is read-only.  It never sends a signal.

PID'yi yeniden kullanmaya dayanıklı işlem kimliği denetimleri. Tek başına bir
PID asla durdurma için yeterli değildir; kanıttaki PID, başlangıç zamanı ve
program yolu canlı işlemle eşleşmelidir. 2.2.38'den beri yalnızca PID 1
(çekirdek izin vermez) ve çağıranın kendisi hedef olamaz; hiçbir ad ya da
Satsuma birimi bir süreci korumaz (sahibi, 2026-11-13). read_tracer_pid bağlı bir debugger'ı
bildirir; okunamazsa sonuç "bilinmiyor"dur. Modül yalnızca okur, sinyal
göndermez.
"""
from __future__ import annotations

import os
import re
from dataclasses import dataclass, asdict
from pathlib import Path



def _pid(value):
    try:
        number = int(value)
    except (TypeError, ValueError):
        return None
    return number if number > 0 else None


def read_proc_starttime(pid) -> int | None:
    """Return the raw ``starttime`` field from ``/proc/<pid>/stat``.

    The field is in clock ticks since boot and is the kernel's PID-reuse
    discriminator.  Return ``None`` when the process does not exist or cannot
    be safely read.
    """
    pid = _pid(pid)
    if pid is None:
        return None
    try:
        text = Path(f"/proc/{pid}/stat").read_text(encoding="utf-8", errors="replace")
        # Comm may contain spaces/parentheses; split after the final ')'.
        fields = text.rsplit(")", 1)[-1].split()
        # After the final ')', fields[0] is state (field 3).  starttime is field
        # 22, i.e. index 19 in this suffix.
        if len(fields) <= 19:
            return None
        return int(fields[19])
    except (OSError, ValueError, PermissionError):
        return None


def read_proc_exe(pid) -> str | None:
    """Return a canonical executable path for ``/proc/<pid>/exe``."""
    pid = _pid(pid)
    if pid is None:
        return None
    try:
        raw = os.readlink(f"/proc/{pid}/exe")
    except (OSError, PermissionError, ValueError):
        return None
    return canonical_exe_path(raw)


def canonical_exe_path(path) -> str:
    """Canonicalise a process executable path, tolerating deleted suffixes."""
    if not path:
        return ""
    text = str(path)
    if text.endswith(" (deleted)"):
        text = text[: -len(" (deleted)")]
    try:
        return os.path.realpath(text)
    except (OSError, ValueError):
        return text


def read_proc_comm(pid) -> str:
    pid = _pid(pid)
    if pid is None:
        return ""
    try:
        return Path(f"/proc/{pid}/comm").read_text(encoding="utf-8", errors="replace").strip()
    except (OSError, PermissionError):
        return ""


def read_proc_cmdline(pid) -> str:
    pid = _pid(pid)
    if pid is None:
        return ""
    try:
        data = Path(f"/proc/{pid}/cmdline").read_bytes()
    except (OSError, PermissionError):
        return ""
    return data.replace(b"\0", b" ").decode("utf-8", "replace").strip()


def read_boot_id() -> str:
    try:
        return Path("/proc/sys/kernel/random/boot_id").read_text(encoding="utf-8").strip()
    except (OSError, PermissionError):
        return ""


def _read_status_ids(pid) -> tuple[int | None, int | None, int | None]:
    """Return real uid, real gid and PPid for a live process."""
    try:
        text = Path(f"/proc/{int(pid)}/status").read_text(encoding="utf-8", errors="replace")
    except (OSError, ValueError, PermissionError):
        return None, None, None
    uid = gid = ppid = None
    for line in text.splitlines():
        try:
            if line.startswith("Uid:"):
                uid = int(line.split()[1])
            elif line.startswith("Gid:"):
                gid = int(line.split()[1])
            elif line.startswith("PPid:"):
                ppid = int(line.split()[1])
        except (IndexError, ValueError):
            continue
    return uid, gid, ppid


def read_proc_cgroup(pid) -> str:
    try:
        lines = Path(f"/proc/{int(pid)}/cgroup").read_text(encoding="utf-8", errors="replace").splitlines()
    except (OSError, ValueError, PermissionError):
        return ""
    # On cgroup v2 the canonical path is the third field of 0::/path.
    for line in lines:
        parts = line.split(":", 2)
        if len(parts) == 3 and parts[0] == "0":
            return parts[2]
    return lines[0].split(":", 2)[-1] if lines else ""


def infer_systemd_unit(cgroup: str) -> str:
    if not cgroup:
        return ""
    for part in reversed(cgroup.split("/")):
        if part.endswith((".service", ".scope", ".slice")):
            return part
    return ""


def read_exe_identity(pid) -> tuple[int | None, int | None]:
    try:
        st = os.stat(f"/proc/{int(pid)}/exe", follow_symlinks=True)
        return int(st.st_dev), int(st.st_ino)
    except (OSError, ValueError, PermissionError):
        return None, None


@dataclass(frozen=True)
class ProcessIdentity:
    boot_id: str
    pid: int
    starttime: int
    exe: str
    uid: int | None = None
    gid: int | None = None
    ppid: int | None = None
    exe_device: int | None = None
    exe_inode: int | None = None
    cgroup: str = ""
    systemd_unit: str = ""
    comm: str = ""
    cmdline: str = ""

    @property
    def identity_key(self) -> str:
        # boot_id + pid + starttime is the canonical PID-reuse-resistant key.
        return f"{self.boot_id}|{self.pid}|{self.starttime}"

    def to_dict(self) -> dict:
        data = asdict(self)
        data["identity_key"] = self.identity_key
        return data


def capture_process_identity_obj(pid) -> ProcessIdentity | None:
    pid = _pid(pid)
    if pid is None:
        return None
    starttime = read_proc_starttime(pid)
    exe = read_proc_exe(pid)
    boot_id = read_boot_id()
    if starttime is None or not exe or not boot_id:
        return None
    uid, gid, ppid = _read_status_ids(pid)
    dev, ino = read_exe_identity(pid)
    cgroup = read_proc_cgroup(pid)
    identity = ProcessIdentity(
        boot_id=boot_id,
        pid=pid,
        starttime=int(starttime),
        exe=exe,
        uid=uid,
        gid=gid,
        ppid=ppid,
        exe_device=dev,
        exe_inode=ino,
        cgroup=cgroup,
        systemd_unit=infer_systemd_unit(cgroup),
        comm=read_proc_comm(pid),
        cmdline=read_proc_cmdline(pid),
    )
    if read_proc_starttime(pid)!=starttime or read_proc_exe(pid)!=exe:
        return None
    return identity


def capture_process_identity(pid) -> dict | None:
    """Capture a live process identity for later immediate revalidation.

    Backwards-compatible dictionary return value.  New callers should regard
    ``boot_id + pid + starttime`` as the canonical identity and never PID alone.
    """
    identity = capture_process_identity_obj(pid)
    return identity.to_dict() if identity is not None else None


def revalidate_captured_identity(captured: dict | None) -> bool:
    """Confirm a previously captured live identity still matches now."""
    if not isinstance(captured, dict):
        return False
    current = capture_process_identity(captured.get("pid"))
    if current is None:
        return False
    boot_ok = not captured.get("boot_id") or captured.get("boot_id") == current.get("boot_id")
    return (
        boot_ok
        and int(captured.get("starttime", -1)) == int(current["starttime"])
        and canonical_exe_path(captured.get("exe")) == canonical_exe_path(current["exe"])
    )


def _nested_first(data, keys, depth=0):
    """Find the first matching key in a nested evidence/finding object."""
    if depth > 6 or data is None:
        return None
    if isinstance(data, dict):
        for key in keys:
            if key in data and data[key] is not None:
                return data[key]
        for key in ("event", "events", "process", "target", "finding", "extensions", "metadata", "raw"):
            if key in data:
                found = _nested_first(data[key], keys, depth + 1)
                if found is not None:
                    return found
        for value in data.values():
            if isinstance(value, (dict, list, tuple)):
                found = _nested_first(value, keys, depth + 1)
                if found is not None:
                    return found
    elif isinstance(data, (list, tuple)):
        for item in data:
            found = _nested_first(item, keys, depth + 1)
            if found is not None:
                return found
    return None


def _first_typed(data, specs, depth=0):
    """Return ``(value, kind)`` for the first matching key.

    ``specs`` is an ordered tuple of ``(key, kind)`` pairs.  Dotted keys are
    matched literally first, then nested mappings are searched.
    """
    if depth > 6 or data is None:
        return None
    if isinstance(data, dict):
        for key, kind in specs:
            if key in data and data[key] is not None:
                return data[key], kind
        # Dotted keys may live inside an extensions mapping.
        for nested_key in ("event", "events", "process", "target", "finding", "extensions", "metadata", "raw"):
            if nested_key in data:
                found = _first_typed(data[nested_key], specs, depth + 1)
                if found is not None:
                    return found
        for value in data.values():
            if isinstance(value, (dict, list, tuple)):
                found = _first_typed(value, specs, depth + 1)
                if found is not None:
                    return found
    elif isinstance(data, (list, tuple)):
        for item in data:
            found = _first_typed(item, specs, depth + 1)
            if found is not None:
                return found
    return None


def _to_int(value):
    try:
        return int(value)
    except (TypeError, ValueError):
        return None


def evidence_pid(evidence) -> int | None:
    value = _nested_first(evidence, ("pid", "target_pid", "process_id", "host.pid"))
    return _to_int(value)


def evidence_starttime(evidence):
    """Return ``(value, kind)`` where kind is ``jiffies`` or ``seconds``."""
    return _first_typed(
        evidence,
        (
            ("starttime", "jiffies"),
            ("starttime_jiffies", "jiffies"),
            ("host.starttime", "jiffies"),
            ("evidence_starttime", "jiffies"),
            ("detection_starttime", "jiffies"),
            ("start_seconds", "seconds"),
            ("host.start_seconds", "seconds"),
        ),
    )


def evidence_exe(evidence) -> str | None:
    value = _nested_first(evidence, ("exe", "executable", "exe_path", "host.exe"))
    if not value:
        return None
    return canonical_exe_path(value)


def _clock_ticks():
    try:
        return int(os.sysconf("SC_CLK_TCK"))
    except (ValueError, OSError, AttributeError):
        return 100


def _is_satsuma_process(exe: str, cmdline: str, *, pid=None) -> bool:
    from .trusted_process import satsuma_entry
    args=[]
    if pid is not None:
        try:
            data=Path(f'/proc/{int(pid)}/cmdline').read_bytes()
            if len(data)>1024*1024:return False
            args=[v.decode('utf-8','replace') for v in data.split(b'\0') if v]
        except (OSError,ValueError):return False
    return satsuma_entry(exe,args)



def verify_process_identity(pid, evidence=None, *, require_evidence: bool = True) -> dict:
    """Verify that ``pid`` is the exact process described by ``evidence``.

    Returns a dictionary with ``ok``, ``reason`` and the compared identity
    fields.  A false ``ok`` means the caller must not kill the process.
    """
    result = {
        "ok": False,
        "reason": "identity_verification_failed",
        "pid": None,
        "evidence_pid": None,
        "evidence_starttime": None,
        "evidence_starttime_kind": None,
        "live_starttime": None,
        "evidence_exe": None,
        "live_exe": None,
        "live_comm": "",
    }
    pid = _pid(pid)
    if pid is None:
        pid = evidence_pid(evidence)
    result["pid"] = pid
    if pid is None:
        result["reason"] = "missing_or_invalid_pid"
        return result
    if pid <= 1:
        result["reason"] = "protected_pid"
        return result
    if pid == os.getpid():
        result["reason"] = "self_pid"
        return result
    if require_evidence and not evidence:
        result["reason"] = "missing_process_evidence"
        return result
    if evidence is not None:
        ev_pid = evidence_pid(evidence)
        result["evidence_pid"] = ev_pid
        if ev_pid is not None and ev_pid != pid:
            result["reason"] = "evidence_pid_mismatch"
            return result

    live_start = read_proc_starttime(pid)
    live_exe = read_proc_exe(pid)
    live_comm = read_proc_comm(pid)
    live_cmdline = read_proc_cmdline(pid)
    result.update({
        "live_starttime": live_start,
        "live_exe": live_exe,
        "live_comm": live_comm,
        "live_cmdline": live_cmdline,
    })
    if live_start is None or not live_exe:
        result["reason"] = "live_process_not_found"
        return result

    if not require_evidence:
        result["ok"] = True
        result["reason"] = "ok"
        return result

    start_info = evidence_starttime(evidence)
    if start_info is None:
        result["reason"] = "missing_starttime_evidence"
        return result
    ev_start, start_kind = start_info
    ev_start_int = _to_int(ev_start)
    result["evidence_starttime"] = ev_start_int if ev_start_int is not None else ev_start
    result["evidence_starttime_kind"] = start_kind
    if ev_start_int is None:
        result["reason"] = "invalid_starttime_evidence"
        return result
    if start_kind == "seconds":
        live_seconds = int(live_start / _clock_ticks())
        if ev_start_int != live_seconds:
            result["reason"] = "starttime_mismatch"
            return result
    else:
        if ev_start_int != int(live_start):
            result["reason"] = "starttime_mismatch"
            return result

    ev_exe = evidence_exe(evidence)
    result["evidence_exe"] = ev_exe
    if not ev_exe:
        result["reason"] = "missing_exe_evidence"
        return result
    if canonical_exe_path(ev_exe) != canonical_exe_path(live_exe):
        result["reason"] = "exe_mismatch"
        return result

    result["ok"] = True
    result["reason"] = "ok"
    return result


def read_tracer_pid(pid, proc_root="/proc") -> int | None:
    """``TracerPid`` of a process; None means unknown, never "no debugger".

    A tracer can rewrite a process's code (breakpoints, injection), so an
    automatic stop based on a code difference must not run while one is
    attached, or while this cannot be read.

    Bir sürecin ``TracerPid`` değeri; None "bilinmiyor" demektir, asla
    "debugger yok" değil. Bağlı bir izleyici kodu değiştirebilir; kod farkına
    dayanan otomatik durdurma, izleyici bağlıyken ya da bu okunamazken yapılmaz.
    """
    pid = _pid(pid)
    if pid is None:
        return None
    try:
        with open(os.path.join(proc_root, str(pid), "status"), "rb") as stream:
            text = stream.read(65537).decode("ascii", "replace")
    except OSError:
        return None
    for line in text.splitlines():
        if line.startswith("TracerPid:"):
            values = line.split(":", 1)[1].split()
            if len(values) != 1 or not values[0].isascii() or not values[0].isdigit():
                return None
            return int(values[0])
    return None
