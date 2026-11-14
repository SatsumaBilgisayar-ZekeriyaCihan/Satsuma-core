"""Satsuma Core — Self-Integrity Guard: manifest imzası.
HMAC-SHA256 (simetrik). Anahtar: /etc/satsuma-core/trust/manifest.key
"""
from __future__ import annotations

import hashlib
import hmac
import os
import secrets
from pathlib import Path


DEFAULT_KEY_PATH = Path("/etc/satsuma-core/trust/manifest.key")
DEFAULT_SIG_PATH = Path("/usr/share/satsuma-core/self-integrity.json.sig")
DEFAULT_MANIFEST_PATH = Path("/usr/share/satsuma-core/self-integrity.json")


# ============================================================
# ANAHTAR YÖNETİMİ
# ============================================================

def generate_key(path: Path = DEFAULT_KEY_PATH, key_bytes: int = 32) -> bytes:
    """Yeni HMAC anahtarı üret. Sadece ilk kurulumda çağrılır."""
    path = Path(path)
    if path.exists():
        raise FileExistsError(f"Anahtar zaten var: {path}")
    path.parent.mkdir(parents=True, exist_ok=True)
    key = secrets.token_bytes(key_bytes)
    fd = os.open(str(path), os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    try:
        os.write(fd, key)
        os.fsync(fd)
    finally:
        os.close(fd)
    os.chmod(path, 0o600)
    return key


def load_key(path: Path = DEFAULT_KEY_PATH) -> bytes:
    """Anahtarı oku. İzin ve sahiplik kontrolü yap."""
    path = Path(path)
    if not path.exists():
        raise FileNotFoundError(f"Anahtar yok: {path}")
    st = path.stat()
    if st.st_uid != 0:
        raise PermissionError(f"Anahtar root'a ait değil: uid={st.st_uid}")
    if st.st_mode & 0o077:
        raise PermissionError(f"Anahtar izinleri çok açık: {oct(st.st_mode)}")
    return path.read_bytes()


# ============================================================
# İMZALAMA
# ============================================================

def sign_manifest(manifest_bytes: bytes, key: bytes) -> bytes:
    """Manifest byte'larının HMAC-SHA256 imzasını üret."""
    return hmac.new(key, manifest_bytes, hashlib.sha256).digest()


def verify_signature(manifest_bytes: bytes, signature: bytes, key: bytes) -> bool:
    """İmzayı constant-time karşılaştırmayla doğrula."""
    expected = hmac.new(key, manifest_bytes, hashlib.sha256).digest()
    return hmac.compare_digest(expected, signature)


def save_signature(sig: bytes, path: Path = DEFAULT_SIG_PATH) -> None:
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_name(path.name + ".tmp")
    fd = os.open(str(tmp), os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o644)
    try:
        os.write(fd, sig)
        os.fsync(fd)
    finally:
        os.close(fd)
    os.replace(tmp, path)


def load_signature(path: Path = DEFAULT_SIG_PATH) -> bytes:
    return Path(path).read_bytes()


def load_trusted_manifest(
    manifest_path: Path = DEFAULT_MANIFEST_PATH,
    sig_path: Path = DEFAULT_SIG_PATH,
    key_path: Path = DEFAULT_KEY_PATH,
) -> dict:
    """İmzayı doğrulayıp manifest'i yükle. İmza geçersizse raise."""
    import json as _json
    from ._types import ViolationType

    manifest_path = Path(manifest_path)
    sig_path = Path(sig_path)
    key_path = Path(key_path)

    if not manifest_path.exists():
        raise FileNotFoundError(f"Manifest yok: {manifest_path}")
    if not sig_path.exists():
        raise FileNotFoundError(f"İmza yok: {sig_path}")

    manifest_bytes = manifest_path.read_bytes()
    signature = sig_path.read_bytes()
    key = load_key(key_path)

    if not verify_signature(manifest_bytes, signature, key):
        raise PermissionError(ViolationType.MANIFEST_SIGNATURE_INVALID.value)

    return _json.loads(manifest_bytes)
