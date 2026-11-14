"""Satsuma Core — Self-Integrity Guard: CLI."""
from __future__ import annotations

import argparse
import json
import logging
import sys
from pathlib import Path

from .core import build_manifest, save_manifest, verify_integrity
from .emit import emit_violations, emit_state
from .trust import (
    generate_key, sign_manifest, save_signature, load_key,
    load_trusted_manifest, DEFAULT_KEY_PATH, DEFAULT_SIG_PATH,
    DEFAULT_MANIFEST_PATH,
)
from ._types import IntegrityState, ViolationType


logger = logging.getLogger("satsuma.self_guard")


def _cmd_init_key(args) -> int:
    try:
        generate_key(Path(args.key_path))
        logger.info("Anahtar üretildi: %s", args.key_path)
        return 0
    except FileExistsError:
        logger.error("Anahtar zaten var: %s", args.key_path)
        return 1


def _cmd_build_manifest(args) -> int:
    manifest = build_manifest()
    save_manifest(manifest, Path(args.manifest_path))
    logger.info("Manifest üretildi: %d dosya", len(manifest["files"]))

    key_path = Path(args.key_path)
    if not key_path.exists():
        logger.info("Anahtar yok, yeni üretiliyor: %s", key_path)
        generate_key(key_path)

    key = load_key(key_path)
    manifest_bytes = Path(args.manifest_path).read_bytes()
    sig = sign_manifest(manifest_bytes, key)
    save_signature(sig, Path(args.sig_path))
    logger.info("İmza kaydedildi: %s", args.sig_path)
    return 0


def _cmd_check(args) -> int:
    # 1. Manifest yükle + imza doğrula
    try:
        manifest = load_trusted_manifest(
            Path(args.manifest_path),
            Path(args.sig_path),
            Path(args.key_path),
        )
    except FileNotFoundError as e:
        logger.error("INTEGRITY_MANIFEST_MISSING %s", e)
        return 1 if args.mode == "enforce" else 0
    except PermissionError as e:
        logger.error("INTEGRITY_MANIFEST_SIGNATURE_INVALID %s", e)
        return 1 if args.mode == "enforce" else 0

    # 2. Doğrula
    state, violations = verify_integrity(manifest)

    if state == IntegrityState.VALID:
        logger.info("INTEGRITY_OK")
    elif state == IntegrityState.DEGRADED:
        logger.warning("INTEGRITY_DEGRADED count=%d", len(violations))
    else:
        logger.error("INTEGRITY_VIOLATION count=%d", len(violations))

    # 3. Violation varsa event üret
    if violations:
        try:
            from ..store import Store
            store = Store()
            try:
                n = emit_violations(store, violations)
                emit_state(store, state, len(violations))
                logger.info("Event yazıldı: %d", n)
            finally:
                store.close()
        except Exception as e:
            logger.error("Event emit başarısız: %s", e)

    # 4. JSON çıktı
    if args.json:
        print(json.dumps({
            "state": state.value,
            "violations": [v.to_dict() for v in violations],
        }, indent=2))

    # 5. Fail-closed sadece enforce modda
    if state == IntegrityState.INTEGRITY_VIOLATION and args.mode == "enforce":
        logger.critical("FAIL_CLOSED: startup reddedildi")
        return 78  # EX_CONFIG
    return 0


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(
        prog="satsuma.self_guard",
        description="Satsuma Core — Self-Integrity Guard",
    )
    parser.add_argument("--check", action="store_true")
    parser.add_argument("--mode", choices=["audit", "enforce"], default="audit")
    parser.add_argument("--build-manifest", action="store_true")
    parser.add_argument("--init-key", action="store_true")
    parser.add_argument("--json", action="store_true")
    parser.add_argument("--manifest-path", default=str(DEFAULT_MANIFEST_PATH))
    parser.add_argument("--sig-path", default=str(DEFAULT_SIG_PATH))
    parser.add_argument("--key-path", default=str(DEFAULT_KEY_PATH))
    parser.add_argument("--verbose", "-v", action="store_true")

    args = parser.parse_args(argv)

    logging.basicConfig(
        level=logging.DEBUG if args.verbose else logging.INFO,
        format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
        stream=sys.stderr,
    )

    if args.init_key:
        return _cmd_init_key(args)
    if args.build_manifest:
        return _cmd_build_manifest(args)
    if args.check:
        return _cmd_check(args)

    parser.print_help()
    return 0
