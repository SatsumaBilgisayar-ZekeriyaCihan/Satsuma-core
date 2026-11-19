"""Satsuma Core — Self-Integrity Guard: kapsam tanımı.

Release-owned davranış dosyaları izlenir.  Runtime üretilen state (DB,
WAL/SHM, admin.hash, log, cache) manifest kapsamına girmez.  Private signing
anahtarları asla manifest/source ağacına dahil edilmez; yalnızca public trust
materyali ve trust konfigürasyonu izlenir.
"""
from __future__ import annotations

from fnmatch import fnmatch
from pathlib import Path


INCLUDE_FILES = (
    "/opt/satsuma-core/main.py",
    "/opt/satsuma-core/run_satsuma_teams.py",
    "/etc/satsuma-core/config.json",
    "/etc/satsuma-core/policy.json",
    "/etc/satsuma-core/policy.json.sig",
    "/etc/satsuma-core/policy-signing.pub",
    "/etc/satsuma-core/satsuma-zack_gate.py",
    "/usr/local/bin/satsuma-zack",
    "/etc/satsuma-core/sudo_gate.py",
    "/usr/local/bin/sudo",
    "/opt/satsuma-core/bin/integrity_check.py",
    "/opt/satsuma-core/bin/validate_rules.py",
    "/opt/satsuma-core/bin/verify_release.py",
    "/opt/satsuma-core/SOURCE_MANIFEST.sha256",
    "/opt/satsuma-core/bin/satsuma-admin",
    "/usr/bin/satsuma-admin",
    "/usr/local/bin/satsuma-admin-passwd",
)

# Deploy edilen systemd unit/timer dosyaları ve public trust materyali glob
# ile kapsanır.  Böylece tek tek servis listesi bakımı gerekmez.
INCLUDE_GLOBS = (
    "/usr/lib/systemd/system/satsuma*.service",
    "/usr/lib/systemd/system/satsuma*.timer",
    "/opt/satsuma-core/systemd/*.service",
    "/opt/satsuma-core/systemd/*.timer",
    "/etc/satsuma-core/trust/*.pub",
    "/etc/satsuma-core/trust/*.pem",
    "/etc/satsuma-core/trust/*.crt",
    "/etc/satsuma-core/trust/*.json",
    "/etc/satsuma-core/trust/*.ed25519",
    "/etc/satsuma-core/trust/*.asc",
)

INCLUDE_DIRS = (
    "/opt/satsuma-core",
    "/opt/satsuma-core/satsuma",
    "/opt/satsuma-core/core",
    "/opt/satsuma-core/workers",
    "/opt/satsuma-core/rules",
    "/opt/satsuma-core/future_specs",
    "/opt/satsuma-core/schemas",
    "/usr/share/satsuma-core",
)

EXCLUDE_DIRS = ()

# Manifest/imza dosyaları ve private key kendi kendini izleyemez.
EXCLUDE_FILES = (
    "/usr/share/satsuma-core/self-integrity.json",
    "/usr/share/satsuma-core/self-integrity.json.sig",
    "/usr/share/satsuma-core/satsuma-manifest.json",
    "/usr/share/satsuma-core/satsuma-manifest.json.sig",
    "/etc/satsuma-core/admin.hash",  # runtime-generated operator credential state
)

EXCLUDE_GLOBS = (
    "**/__pycache__/**",
    "**/*.pyc",
    "**/*.pyo",
    "**/*.log",
    "**/*.db",
    "**/*.db-wal",
    "**/*.db-shm",
    "**/*.swp",
    "**/*.tmp",
    "**/*.bak",         # .bak
    "**/*.bak-*",       # .bak-20260921-104147
    "**/*.bak.*",       # .bak.20260921
    "**/*.before*",     # .before-retention-fix
    "**/*.orig",        # .orig
    "**/*.ORIGINAL",
    "**/admin.hash",
    "**/manifest.key",
    "**/*.key",
    "**/*.p12",
    "**/*.pfx",
    "**/.git/**",
    "**/venv/**",
    "**/.venv/**",
    "**/*.egg-info/**",
    "**/.pytest_cache/**",
    "**/.mypy_cache/**",
    "**/.ruff_cache/**",
)

RUNTIME_ROOTS = (
    "/var/lib/satsuma-core",
    "/var/log/satsuma-core",
    "/run/satsuma-core",
    "/tmp/satsuma-core",
)


def in_scope(path: str) -> bool:
    """Verilen yol manifest kapsamında mı?"""
    if path in EXCLUDE_FILES:
        return False
    for r in RUNTIME_ROOTS:
        if path == r or path.startswith(r + "/"):
            return False
    for d in EXCLUDE_DIRS:
        if path == d or path.startswith(d + "/"):
            return False
    for g in EXCLUDE_GLOBS:
        if fnmatch(path, g):
            return False
    if path in INCLUDE_FILES:
        return True
    for g in INCLUDE_GLOBS:
        if fnmatch(path, g):
            return True
    for d in INCLUDE_DIRS:
        if path == d or path.startswith(d + "/"):
            return True
    return False


def sanity_check():
    """Kapsam tutarlılığını doğrula."""
    errors = []
    for f in INCLUDE_FILES:
        for d in EXCLUDE_DIRS:
            if f == d or f.startswith(d + "/"):
                errors.append("INCLUDE_FILES vs EXCLUDE_DIRS çakışma: " + f)
    for f in INCLUDE_FILES:
        if any(f == r or f.startswith(r + "/") for r in RUNTIME_ROOTS):
            errors.append("Runtime state INCLUDE_FILES içinde: " + f)
    if any("admin.hash" in f for f in INCLUDE_FILES):
        errors.append("admin.hash release-owned INCLUDE_FILES içinde olmamalı")
    if any("admin.hash" in g for g in INCLUDE_GLOBS):
        errors.append("admin.hash release-owned INCLUDE_GLOBS içinde olmamalı")
    guard_path = "/opt/satsuma-core/satsuma/self_guard"
    if not any(guard_path.startswith(d) for d in INCLUDE_DIRS):
        errors.append("Guard kendi kodunu izlemiyor (INCLUDE_DIRS)")
    if "/opt/satsuma-core/bin/integrity_check.py" not in INCLUDE_FILES:
        errors.append("bin/integrity_check.py INCLUDE_FILES'ta değil")
    if not in_scope("/usr/lib/systemd/system/satsuma-reader.service"):
        errors.append("systemd satsuma-reader.service kapsam dışı")
    if in_scope("/var/lib/satsuma-core/core.db"):
        errors.append("core.db runtime state kapsam içinde")
    if in_scope("/etc/satsuma-core/admin.hash"):
        errors.append("admin.hash runtime state kapsam içinde")
    return (len(errors) == 0, errors)
