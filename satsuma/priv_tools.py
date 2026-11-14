"""Satsuma Core — Privileged tool discovery.

/etc/passwd'den UID 0 kullanicilari bulur, ardindan bu UID'lere
ait setuid binary'leri tarar. sudo/satsuma-zack/... hangi isim
olursa olsun dogru calisir.
"""
from __future__ import annotations

import os
import re
import time
from dataclasses import dataclass

_SCAN_DIRS = (
    "/usr/bin", "/usr/sbin", "/bin", "/sbin",
    "/usr/local/bin", "/usr/local/sbin", "/opt",
)
_CACHE_TTL = 300.0  # 5 dakika


@dataclass(frozen=True)
class PrivTool:
    name: str
    path: str
    uid: int


class PrivilegedToolRegistry:
    def __init__(self, cache_ttl: float = _CACHE_TTL) -> None:
        self._cache_ttl = cache_ttl
        self._cached_at = 0.0
        self._tools: tuple[PrivTool, ...] = ()

    def _find_root_uids(self) -> tuple[int, ...]:
        uids = set()
        try:
            with open("/etc/passwd", "r", encoding="utf-8", errors="replace") as f:
                for line in f:
                    parts = line.strip().split(":")
                    if len(parts) < 4:
                        continue
                    try:
                        uid = int(parts[2])
                    except ValueError:
                        continue
                    if uid == 0:
                        uids.add(uid)
        except OSError:
            pass
        return tuple(sorted(uids)) if uids else (0,)

    def _scan_dir(self, d: str, root_uids: tuple[int, ...]) -> list[PrivTool]:
        found: list[PrivTool] = []
        try:
            entries = os.listdir(d)
        except (OSError, PermissionError):
            return found

        for name in entries:
            full = os.path.join(d, name)
            try:
                st = os.stat(full, follow_symlinks=False)
            except (OSError, PermissionError):
                continue
            if not (st.st_mode & 0o4000):     # setuid yok
                continue
            if st.st_uid not in root_uids:    # root sahibi degil
                continue
            if not (st.st_mode & 0o100):      # calistirilamaz
                continue
            if os.path.islink(full):          # symlink
                continue
            found.append(PrivTool(name=name, path=full, uid=st.st_uid))
        return found

    def discover(self, force: bool = False) -> tuple[PrivTool, ...]:
        now = time.time()
        if not force and (now - self._cached_at) < self._cache_ttl and self._tools:
            return self._tools
        root_uids = self._find_root_uids()
        tools: list[PrivTool] = []
        seen: set[str] = set()
        for d in _SCAN_DIRS:
            for tool in self._scan_dir(d, root_uids):
                if tool.name not in seen:
                    seen.add(tool.name)
                    tools.append(tool)
        self._tools = tuple(sorted(tools, key=lambda t: t.name))
        self._cached_at = now
        return self._tools

    def names(self) -> tuple[str, ...]:
        return tuple(t.name for t in self.discover())

    def shell_pattern(self) -> re.Pattern:
        names = self.names() or ("sudo",)
        alt = "|".join(re.escape(n) for n in names)
        return re.compile(
            rf"(?:^|\s)(?:{alt})\s+(?:su(?:\s+-)?|-i|-s|-si|-is|bash|sh)(?:\s|$)"
        )

    def pkill_pattern(self) -> str:
        names = self.names() or ("sudo",)
        return "|".join(rf"{re.escape(n)} su" for n in names)


_registry = PrivilegedToolRegistry()


def get_registry() -> PrivilegedToolRegistry:
    return _registry


def priv_tool_names() -> tuple[str, ...]:
    return _registry.names()


def shell_session_regex() -> re.Pattern:
    return _registry.shell_pattern()


def pkill_pattern() -> str:
    return _registry.pkill_pattern()
