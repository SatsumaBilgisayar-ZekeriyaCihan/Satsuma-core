"""Satsuma Core — Self-Integrity Guard: çekirdek mantık.
Manifest üretimi ve doğrulama. Saf Python + stdlib.
"""
from __future__ import annotations

import hashlib
import json
import os
import stat
from datetime import datetime, timezone
from pathlib import Path

from glob import glob

from .scope import in_scope, INCLUDE_DIRS, INCLUDE_FILES, INCLUDE_GLOBS
from ._types import (
    FileRecord,
    Violation,
    ViolationType,
    IntegrityState,
    classify_state,
)


# ============================================================
# SHA-256
# ============================================================

def sha256_file(path: Path, chunk_size: int = 1 << 20) -> str:
    """Dosyanın SHA-256'sını hesapla. Stream — büyük dosyalar için."""
    h = hashlib.sha256()
    with path.open("rb") as f:
        for block in iter(lambda: f.read(chunk_size), b""):
            h.update(block)
    return h.hexdigest()


# ============================================================
# MANIFEST ÜRETİMİ
# ============================================================

def _iter_scope_files() -> list[Path]:
    """Kapsam içindeki tüm dosyaları dolaş."""
    found: set[Path] = set()

    # 1. Açıkça listelenmiş dosyalar
    for f in INCLUDE_FILES:
        p = Path(f)
        if p.exists() or p.is_symlink():
            found.add(p)

    # 2. Public/unit glob kapsamı
    for pattern in INCLUDE_GLOBS:
        for raw_path in glob(pattern, recursive=True):
            p = Path(raw_path)
            if p.is_file() and in_scope(str(p)):
                found.add(p)

    # 3. Dizinler altında tara
    for d in INCLUDE_DIRS:
        root = Path(d)
        if not root.exists():
            continue
        for p in root.rglob("*"):
            if p.is_dir():
                continue
            if in_scope(str(p)):
                found.add(p)

    return sorted(found)


def _record_from_path(path: Path) -> FileRecord:
    """Bir dosyayı FileRecord'a dönüştür."""
    st = path.lstat()  # lstat — symlink'i takip etmez

    if stat.S_ISLNK(st.st_mode):
        return FileRecord(
            path=str(path),
            sha256="",
            uid=st.st_uid,
            gid=st.st_gid,
            mode=stat.S_IMODE(st.st_mode),
            is_symlink=True,
            link_target=os.readlink(path),
        )

    return FileRecord(
        path=str(path),
        sha256=sha256_file(path),
        uid=st.st_uid,
        gid=st.st_gid,
        mode=stat.S_IMODE(st.st_mode),
        is_symlink=False,
        link_target=None,
    )


def build_manifest() -> dict:
    """Tüm kapsamı tara, manifest oluştur.
    Returns: {'schema_version':1, 'generated_at':..., 'files':[...]}
    """
    files: list[FileRecord] = []

    for p in _iter_scope_files():
        try:
            files.append(_record_from_path(p))
        except (OSError, PermissionError) as e:
            raise RuntimeError('Cannot enroll unreadable integrity target: '+str(p)) from e

    return {
        "schema_version": 1,
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "files": [
            {
                "path": f.path,
                "sha256": f.sha256,
                "uid": f.uid,
                "gid": f.gid,
                "mode": f.mode,
                "is_symlink": f.is_symlink,
                "link_target": f.link_target,
            }
            for f in files
        ],
    }


def save_manifest(manifest: dict, path: Path) -> None:
    """Manifest'i JSON olarak yaz (atomik)."""
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_name(path.name + ".tmp")
    with tmp.open("w", encoding="utf-8") as f:
        json.dump(manifest, f, indent=2, sort_keys=True)
        f.write("\n")
    os.chmod(tmp, 0o644)
    os.replace(tmp, path)


def load_manifest(path: Path) -> dict:
    """Manifest'i oku ve schema doğrula."""
    with Path(path).open("r", encoding="utf-8") as f:
        data = json.load(f)
    if data.get("schema_version") != 1:
        raise ValueError(f"Bilinmeyen manifest schema: {data.get('schema_version')}")
    if not isinstance(data.get("files"), list):
        raise ValueError("Manifest 'files' listesi eksik")
    return data


# ============================================================
# DOĞRULAMA
# ============================================================

def _violation_type_for(path: str) -> str:
    """Dosya değişmişse hangi violation tipi?"""
    if path == "/etc/satsuma-core/policy.json":
        return ViolationType.POLICY_INTEGRITY_VIOLATION.value
    if "/systemd/system/" in path:
        return ViolationType.SYSTEMD_UNIT_VIOLATION.value
    return ViolationType.FILE_MODIFIED.value


def verify_integrity(manifest: dict) -> tuple[IntegrityState, list[Violation]]:
    """Manifest ile disk durumunu karşılaştır.
    Returns: (state, violations)
    """
    now = datetime.now(timezone.utc).isoformat()
    violations: list[Violation] = []

    expected_by_path = {f["path"]: f for f in manifest["files"]}
    seen_paths: set[str] = set()

    # 1. Manifest'teki her dosyayı kontrol et
    for path_str, rec in expected_by_path.items():
        seen_paths.add(path_str)
        p = Path(path_str)

        # Varlık
        if not p.exists() and not p.is_symlink():
            violations.append(Violation(
                timestamp=now,
                file=path_str,
                violation_type=ViolationType.FILE_MISSING.value,
                expected_sha256=rec["sha256"] or None,
            ))
            continue

        st = p.lstat()
        actual_is_symlink = stat.S_ISLNK(st.st_mode)

        # Symlink beklenmedik/beklenen mi?
        if actual_is_symlink != rec["is_symlink"]:
            violations.append(Violation(
                timestamp=now,
                file=path_str,
                violation_type=ViolationType.UNEXPECTED_SYMLINK.value,
                link_target=os.readlink(p) if actual_is_symlink else None,
            ))
            continue

        # Owner
        if st.st_uid != rec["uid"]:
            violations.append(Violation(
                timestamp=now,
                file=path_str,
                violation_type=ViolationType.OWNER_MISMATCH.value,
                expected_uid=rec["uid"],
                actual_uid=st.st_uid,
            ))

        # Group
        if st.st_gid != rec["gid"]:
            violations.append(Violation(
                timestamp=now,
                file=path_str,
                violation_type=ViolationType.GROUP_MISMATCH.value,
                expected_gid=rec["gid"],
                actual_gid=st.st_gid,
            ))

        # Mode
        actual_mode = stat.S_IMODE(st.st_mode)
        if actual_mode != rec["mode"]:
            violations.append(Violation(
                timestamp=now,
                file=path_str,
                violation_type=ViolationType.MODE_MISMATCH.value,
                expected_mode=rec["mode"],
                actual_mode=actual_mode,
            ))

        # SHA-256 (symlink değilse)
        if not rec["is_symlink"]:
            try:
                actual_sha = sha256_file(p)
                if actual_sha != rec["sha256"]:
                    violations.append(Violation(
                        timestamp=now,
                        file=path_str,
                        violation_type=_violation_type_for(path_str),
                        expected_sha256=rec["sha256"],
                        actual_sha256=actual_sha,
                    ))
            except (OSError, PermissionError):
                pass

    # 2. Kapsam içinde ama manifest'te olmayan dosyalar
    for p in _iter_scope_files():
        path_str = str(p)
        if path_str not in seen_paths:
            violations.append(Violation(
                timestamp=now,
                file=path_str,
                violation_type=ViolationType.FILE_UNEXPECTED.value,
            ))

    return classify_state(violations), violations
