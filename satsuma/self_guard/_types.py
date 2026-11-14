"""Satsuma Core — Self-Integrity Guard: veri tipleri.
Sadece enum ve dataclass. Bağımlılık yok, saf Python.
"""
from __future__ import annotations

from dataclasses import dataclass, field, asdict
from enum import Enum
from typing import Optional


class IntegrityState(str, Enum):
    """Başlangıç kontrolü sonucu."""
    VALID = "VALID"
    DEGRADED = "DEGRADED"
    INTEGRITY_VIOLATION = "INTEGRITY_VIOLATION"


class ViolationType(str, Enum):
    """İhlal türleri — her biri ayrı event üretir."""
    FILE_MODIFIED = "FILE_MODIFIED"
    FILE_MISSING = "FILE_MISSING"
    FILE_UNEXPECTED = "FILE_UNEXPECTED"
    OWNER_MISMATCH = "OWNER_MISMATCH"
    GROUP_MISMATCH = "GROUP_MISMATCH"
    MODE_MISMATCH = "MODE_MISMATCH"
    UNEXPECTED_SYMLINK = "UNEXPECTED_SYMLINK"
    POLICY_INTEGRITY_VIOLATION = "POLICY_INTEGRITY_VIOLATION"
    SYSTEMD_UNIT_VIOLATION = "SYSTEMD_UNIT_VIOLATION"
    MANIFEST_TAMPERED = "MANIFEST_TAMPERED"
    MANIFEST_MISSING = "MANIFEST_MISSING"
    MANIFEST_SIGNATURE_INVALID = "MANIFEST_SIGNATURE_INVALID"


@dataclass(frozen=True)
class FileRecord:
    """Bir dosyanın beklenen hali."""
    path: str
    sha256: str
    uid: int
    gid: int
    mode: int
    is_symlink: bool = False
    link_target: Optional[str] = None


@dataclass
class Violation:
    """Tespit edilen tek bir sapma."""
    timestamp: str
    file: str
    violation_type: str
    expected_sha256: Optional[str] = None
    actual_sha256: Optional[str] = None
    expected_uid: Optional[int] = None
    actual_uid: Optional[int] = None
    expected_gid: Optional[int] = None
    actual_gid: Optional[int] = None
    expected_mode: Optional[int] = None
    actual_mode: Optional[int] = None
    link_target: Optional[str] = None

    def to_dict(self) -> dict:
        return {k: v for k, v in asdict(self).items() if v is not None}


SEVERE_VIOLATIONS = frozenset({
    ViolationType.FILE_MODIFIED.value,
    ViolationType.POLICY_INTEGRITY_VIOLATION.value,
    ViolationType.SYSTEMD_UNIT_VIOLATION.value,
    ViolationType.MANIFEST_TAMPERED.value,
    ViolationType.MANIFEST_SIGNATURE_INVALID.value,
    ViolationType.MANIFEST_MISSING.value,
    ViolationType.UNEXPECTED_SYMLINK.value,
    ViolationType.FILE_MISSING.value,
})


def classify_state(violations: list) -> IntegrityState:
    """Violation listesinden genel durum çıkar."""
    if not violations:
        return IntegrityState.VALID
    if any(v.violation_type in SEVERE_VIOLATIONS for v in violations):
        return IntegrityState.INTEGRITY_VIOLATION
    return IntegrityState.DEGRADED
