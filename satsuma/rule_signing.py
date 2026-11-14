"""Verify detached GPG signatures using a root-managed public-only keyring.

There is intentionally no signing/private-key API in the root service.
"""
import hashlib
import json
import os
import re
import stat
import subprocess
import tempfile
from pathlib import Path
from .ai_rule_package import canonical, digest, validate_package

TRUSTED_PUBLIC_KEY = Path('/etc/satsuma-core/trust/deepseek-rules.gpg')
MANAGED_RULES_DIR = Path('/var/lib/satsuma-core/generated_rules/active')
TRUSTED_OWNER = 0
MAX_SIGNATURE_BYTES = 16384
# 2.2.20: operator approval seals the package with Satsuma's local 32-byte key
# (the same root-only key that seals the installation inventory). A GPG
# signature is still accepted but no longer required.
SEAL_KEY = Path('/etc/satsuma-core/trust/manifest.key')
SEAL_PREFIX = 'satsuma-seal-v1:'


def _seal_key(path=None):
    path = SEAL_KEY if path is None else Path(path)
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    try:
        st = os.fstat(fd)
        if (not stat.S_ISREG(st.st_mode) or st.st_nlink != 1 or st.st_uid != TRUSTED_OWNER
                or st.st_mode & 0o077):
            raise ValueError('untrusted_seal_key')
        key = os.read(fd, 4096)
    finally:
        os.close(fd)
    if len(key) != 32:
        raise ValueError('invalid_seal_key')
    return key


def seal_payload(payload):
    """Local tamper seal for an approved payload; the key never leaves the root backend.

    Onaylanan paket için yerel mühür; anahtar root arka uçtan çıkmaz.
    """
    import hmac
    return SEAL_PREFIX + hmac.new(_seal_key(), payload, hashlib.sha256).hexdigest()


def read_regular(path, maximum):
    path = Path(path).absolute()
    if path.resolve() != path:
        raise ValueError('symlink_path_refused')
    with os.fdopen(os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK), 'rb') as stream:
        st = os.fstat(stream.fileno())
        if not stat.S_ISREG(st.st_mode) or st.st_nlink != 1 or st.st_uid != TRUSTED_OWNER or st.st_mode & 0o022:
            raise ValueError('untrusted_file_permissions')
        data = stream.read(maximum + 1)
        if len(data) > maximum:
            raise ValueError('file_too_large')
        return data


def verify_payload(payload, signature):
    text = signature.decode('ascii', 'replace') if isinstance(signature, bytes) else signature
    if isinstance(text, str) and text.startswith(SEAL_PREFIX):
        import hmac
        try:
            expected = seal_payload(payload)
        except (OSError, ValueError):
            return {'valid': False, 'error': 'seal_key_unavailable'}
        if hmac.compare_digest(expected, text.strip()):
            return {'valid': True, 'fingerprint': 'satsuma-local-seal'}
        return {'valid': False, 'error': 'seal_mismatch_content_changed'}
    try:
        signature = signature.encode('ascii') if isinstance(signature, str) else signature
        if not isinstance(signature, bytes) or not 1 <= len(signature) <= MAX_SIGNATURE_BYTES:
            return {'valid': False, 'error': 'invalid_signature_size'}
        keyring = read_regular(TRUSTED_PUBLIC_KEY, 1048576)
        with tempfile.TemporaryDirectory(prefix='satsuma-gpg-') as folder:
            root = Path(folder)
            # Copy the checked public bytes, eliminating path replacement races.
            (root / 'trusted.gpg').write_bytes(keyring)
            (root / 'payload.json').write_bytes(payload)
            (root / 'signature.asc').write_bytes(signature)
            home = root / 'home';home.mkdir(mode=0o700)
            result = subprocess.run(['/usr/bin/gpg', '--no-options', '--homedir', str(home),
                '--batch', '--no-default-keyring', '--keyring', str(root / 'trusted.gpg'),
                '--no-auto-key-retrieve', '--auto-key-locate', 'clear', '--status-fd', '1',
                '--verify', str(root / 'signature.asc'), str(root / 'payload.json')],
                stdin=subprocess.DEVNULL, capture_output=True, timeout=10)
            match = re.search(rb'\[GNUPG:\] VALIDSIG ([A-F0-9]{40,64})\b', result.stdout)
            if result.returncode != 0 or not match:
                return {'valid': False, 'error': 'signature_not_trusted_or_content_changed'}
            return {'valid': True, 'fingerprint': match[1].decode()}
    except Exception:
        return {'valid': False, 'error': 'trusted_public_key_or_gpg_unavailable'}


def verify_installed_rule(path, rules):
    """All AI YAML load paths require the signed detection/response envelope."""
    folder = Path(path).parent
    payload = read_regular(folder / 'package.json', 65536)
    envelope = json.loads(payload)
    if canonical(envelope) != payload or set(envelope) != {'package', 'approval'}:
        raise ValueError('invalid_signed_envelope')
    package, approval = envelope['package'], envelope['approval']
    errors = validate_package(package)
    if errors or not isinstance(approval, dict) or set(approval) != {'operator_uid', 'reviewed_at', 'package_sha256'}:
        raise ValueError('signed_package_invalid')
    if type(approval['operator_uid']) is not int or type(approval['reviewed_at']) not in (int, float) or approval['package_sha256'] != digest(package):
        raise ValueError('approval_binding_invalid')
    if rules != [package['detection']]:
        raise ValueError('installed_detection_differs_from_signature')
    signature = read_regular(folder / 'signature.asc', MAX_SIGNATURE_BYTES)
    verified = verify_payload(payload, signature)
    if not verified['valid']:
        raise ValueError(verified['error'])
    return {'package_hash': digest(package), 'detection_hash':digest(package['detection']), 'payload_hash': hashlib.sha256(payload).hexdigest(),
            'response_proposal': package['response_proposal'], 'fingerprint': verified['fingerprint']}
