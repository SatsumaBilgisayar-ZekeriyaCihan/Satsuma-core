"""Satsuma Core — Self-Integrity Guard: public API."""
from ._types import (
    IntegrityState, ViolationType, FileRecord, Violation, classify_state,
)
from .scope import in_scope, sanity_check
from .core import (
    build_manifest, save_manifest, load_manifest, verify_integrity,
)
from .trust import (
    generate_key, load_key, sign_manifest, verify_signature,
    save_signature, load_signature, load_trusted_manifest,
)
from .emit import emit_violations, emit_state

__all__ = [
    "IntegrityState", "ViolationType", "FileRecord", "Violation", "classify_state",
    "in_scope", "sanity_check",
    "build_manifest", "save_manifest", "load_manifest", "verify_integrity",
    "generate_key", "load_key", "sign_manifest", "verify_signature",
    "save_signature", "load_signature", "load_trusted_manifest",
    "emit_violations", "emit_state",
]


def verify(mode="audit"):
    from installer.integrity import verify as check_installation
    return check_installation()
