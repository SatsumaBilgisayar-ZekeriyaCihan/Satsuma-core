"""Release archive hygiene helpers (pure stdlib)."""
from __future__ import annotations

import fnmatch
from pathlib import Path

FORBIDDEN_GLOBS = (
    "*.pyc",
    "*.pyo",
    "__pycache__",
    ".pytest_cache",
    ".mypy_cache",
    ".ruff_cache",
    ".coverage",
    "htmlcov",
    "*.egg-info",
    "*.db",
    "*.db-wal",
    "*.db-shm",
    "*.log",
    "*.bak",
    "*.bak-*",
    "*.tmp",
    "*.swp",
    "*.orig",
    "*.ORIGINAL",
    "admin.hash",
    "*token*",
    "*credential*",
    "*private*",
    "*.key",
    "*.pem",
    "*.p12",
    "*.pfx",
)

# Credential/private-key names are not forbidden if they are clearly rule or
# documentation filenames, not credential material.
_ALLOWED_NAMES = {
    "credential_access.yaml",
}


def forbidden_reason(rel_path: str) -> str | None:
    """Return a reason when a relative archive path is forbidden."""
    rel = str(rel_path).replace("\\", "/")
    if rel.startswith("./"):
        rel = rel[2:]
    rel = rel.lstrip("/")
    parts = [p for p in rel.split("/") if p]
    if not parts:
        return None
    name = parts[-1]
    if name in _ALLOWED_NAMES:
        return None
    cache_dirs = {"__pycache__", ".pytest_cache", ".mypy_cache", ".ruff_cache", ".coverage", "htmlcov"}
    for part in parts:
        if part in cache_dirs:
            return part
        if part.endswith(".egg-info"):
            return "*.egg-info"
    for pattern in FORBIDDEN_GLOBS:
        if fnmatch.fnmatch(name, pattern):
            return pattern
    return None


def find_violations(root: str | Path) -> list[tuple[str, str]]:
    root = Path(root)
    violations: list[tuple[str, str]] = []
    for p in sorted(root.rglob("*")):
        reason = forbidden_reason(str(p.relative_to(root)))
        if reason:
            violations.append((str(p.relative_to(root)), reason))
    return violations


def is_release_source_path(rel_path: str) -> bool:
    """Keep only source/rules/units/tests/docs/validation-report material."""
    rel = str(rel_path).replace("\\", "/")
    if rel.startswith("./"):
        rel = rel[2:]
    rel = rel.lstrip("/")
    if not rel or rel.startswith("."):
        return False
    if forbidden_reason(rel):
        return False
    top = rel.split("/", 1)[0]
    if top in {"satsuma", "core", "workers", "rules", "tests", "systemd", "bin", "config_examples", "validation"}:
        return True
    if rel in {
        "main.py",
        "run_satsuma_teams.py",
        "DELIVERY.md",
        "DELIVERY_NOTES.md",
        "DASHBOARD_V06_NOTES.md",
        "ROADMAP.md",
        "RELEASE_READINESS_REPORT.md",
        "RULE_VALIDATION.json",
        "SOURCE_MANIFEST.sha256",
        "TEST_REPORT.txt",
        "SECURITY_HOTFIX_REPORT.md",
    }:
        return True
    return False
