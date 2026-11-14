"""Verifier-side TPM2 credential activation using an already-existing EK/AK.

No TPM device is opened by this module. MakeCredential runs with TCTI=none.
The device operator separately runs ActivateCredential with preexisting handles;
Satsuma NEVER creates an EK/AK, writes NV, persists handles, or changes firmware.

A valid response proves a credential for the pinned AK *Name* was activated
using the indicated EK public key. This does not independently bind a separate
quote PEM to that Name, or prove trusted boot/firmware integrity.
"""
from __future__ import annotations

import argparse
import hashlib
import hmac
import json
import os
import re
import secrets
import stat
import subprocess
import tempfile
import time
from pathlib import Path

from .tpm_trust_bundle import verify_ek_certificate, _bounded_file, MAX_CERT

MAKECREDENTIAL = '/usr/bin/tpm2_makecredential'
ENV = {'PATH': '/usr/sbin:/usr/bin:/sbin:/bin', 'LC_ALL': 'C'}
HEX64 = re.compile(r'^[a-fA-F0-9]{64}$')
AK_NAME_SHA256 = re.compile(r'^000b[a-fA-F0-9]{64}$')
CHALLENGE_ID = re.compile(r'^[a-f0-9]{32}$')
LIFETIME = 300


def _private_state_dir(state_dir):
    path = Path(state_dir)
    # Never follow a symlink for a state directory; parent trust remains the
    # installer's/verifier's responsibility. This is NOT safe for shared dirs.
    if path.is_symlink():
        raise ValueError('symlinked state directory')
    path.mkdir(mode=0o700, parents=False, exist_ok=True)
    st = path.stat(follow_symlinks=False)
    if not stat.S_ISDIR(st.st_mode) or st.st_uid != os.geteuid() or (st.st_mode & 0o077):
        raise ValueError('state directory must be private and owned by verifier')
    return path


def _write_exclusive(path, payload):
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC, 0o600)
    try:
        os.write(fd, payload)
        os.fsync(fd)
    finally:
        os.close(fd)


def issue_challenge(*, state_dir, ek_certificate, manufacturer_ca, expected_ca_sha256,
                    expected_ek_spki_sha256, ak_name_hex, expected_ak_name_sha256,
                    executable=MAKECREDENTIAL, runner=subprocess.run, now=None):
    """Generate a fresh verifier-side challenge and a TPM credential blob.

    `expected_ak_name_sha256` must be supplied OUT OF BAND. The AK name is
    supplied as TPM2B_NAME (000b + 32-byte SHA-256) in hex. For now only
    SHA-256 names are supported to avoid ambiguous template interpretations.
    """
    rejected = {'status': 'CHALLENGE_NOT_ISSUED', 'credential_activation_verified': False,
                'ek_ak_binding_verified': False, 'platform_identity_verified': False}
    if not (isinstance(ak_name_hex, str) and AK_NAME_SHA256.fullmatch(ak_name_hex)
            and isinstance(expected_ak_name_sha256, str) and HEX64.fullmatch(expected_ak_name_sha256)
            and hmac.compare_digest(hashlib.sha256(bytes.fromhex(ak_name_hex)).hexdigest(),
                                    expected_ak_name_sha256.lower())):
        return {**rejected, 'status': 'AK_NAME_REFERENCE_MISMATCH'}
    ek = verify_ek_certificate(ek_certificate=ek_certificate, manufacturer_ca=manufacturer_ca,
        expected_ca_sha256=expected_ca_sha256, expected_ek_spki_sha256=expected_ek_spki_sha256)
    if not ek['ek_certificate_verified']:
        return {**rejected, 'status': 'EK_NOT_VERIFIED', 'ek': ek}
    try:
        from cryptography import x509
        from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat
        from cryptography.hazmat.primitives.asymmetric import rsa, ec
        raw = _bounded_file(ek_certificate, MAX_CERT)
        cert = (x509.load_pem_x509_certificate(raw) if b'-----BEGIN CERTIFICATE-----' in raw
                else x509.load_der_x509_certificate(raw))
        pub = cert.public_key()
        if isinstance(pub, rsa.RSAPublicKey):
            alg = 'rsa'
        elif isinstance(pub, ec.EllipticCurvePublicKey):
            alg = 'ecc'
        else:
            return {**rejected, 'status': 'UNSUPPORTED_EK_KEY'}
        d = _private_state_dir(state_dir)
        secret = secrets.token_bytes(32)
        ident = secrets.token_hex(16)
        issued = int(time.time() if now is None else now)
        blob = d / (ident + '.credential')
        with tempfile.TemporaryDirectory(prefix='.ekpub-', dir=d) as temp:
            pem_path = Path(temp) / 'ek.pem'
            _write_exclusive(pem_path, pub.public_bytes(Encoding.PEM, PublicFormat.SubjectPublicKeyInfo))
            cmd = [executable, '--tcti=none', '-G', alg, '-u', str(pem_path),
                   '-n', ak_name_hex.lower(), '-s', '-', '-o', str(blob)]
            proc = runner(cmd, input=secret, capture_output=True, timeout=20, check=False, env=ENV)
            if proc.returncode != 0:
                blob.unlink(missing_ok=True)
                return {**rejected, 'status': 'MAKECREDENTIAL_FAILED'}
        # Do not trust subprocess-created file mode or arbitrary blob sizes.
        data = _bounded_file(blob, 65536)
        if not data:
            raise ValueError('empty credential')
        os.chmod(blob, 0o600, follow_symlinks=False)
        state = {'version': 1, 'id': ident, 'issued': issued, 'expires': issued + LIFETIME,
                 'secret_sha256': hashlib.sha256(secret).hexdigest(),
                 'ek_spki_sha256': expected_ek_spki_sha256.lower(),
                 'ak_name_sha256': expected_ak_name_sha256.lower()}
        try:
            _write_exclusive(d / (ident + '.pending'), json.dumps(state, sort_keys=True).encode())
        except BaseException:
            blob.unlink(missing_ok=True)
            raise
        return {'status': 'CHALLENGE_ISSUED', 'challenge_id': ident,
                'credential_blob': str(blob), 'expires': state['expires'],
                'credential_activation_verified': False, 'ek_ak_binding_verified': False,
                'platform_identity_verified': False,
                'note': 'Credential blob TPM ajanina aktarilir; ActivateCredential mevcut EK/AK ile ayrica calistirilir'}
    except (OSError, ValueError, TypeError, subprocess.TimeoutExpired, ImportError):
        return {**rejected, 'status': 'CHALLENGE_GENERATION_UNAVAILABLE'}


def verify_activation(*, state_dir, challenge_id, activated_secret, now=None):
    """Consume single-use challenge BEFORE checking response (including failures)."""
    base = {'status': 'ACTIVATION_UNVERIFIED', 'credential_activation_verified': False,
            'ek_ak_binding_verified': False, 'platform_identity_verified': False,
            'trusted_boot_verified': False, 'tpm_modified': False}
    if not isinstance(challenge_id, str) or not CHALLENGE_ID.fullmatch(challenge_id):
        return {**base, 'status': 'INVALID_CHALLENGE_ID'}
    try:
        d = _private_state_dir(state_dir)
        pending = d / (challenge_id + '.pending')
        consumed = d / (challenge_id + '.consumed')
        if consumed.exists():
            return {**base, 'status': 'CHALLENGE_ALREADY_CONSUMED'}
        # Directory must only be accessible to the verifier's effective UID.
        # Atomic replacement prevents two successful verifications in ordinary
        # single-verifier deployments; concurrent verification requires locking.
        os.rename(pending, consumed)
        raw = _bounded_file(consumed, 4096)
        state = json.loads(raw)
        if (state.get('version') != 1 or state.get('id') != challenge_id
                or not isinstance(state.get('expires'), int)
                or not isinstance(state.get('issued'), int)
                or not HEX64.fullmatch(str(state.get('secret_sha256', '')))):
            return {**base, 'status': 'INVALID_CHALLENGE_STATE'}
        current = int(time.time() if now is None else now)
        if current < state['issued'] or current > state['expires']:
            return {**base, 'status': 'CHALLENGE_EXPIRED'}
        received = _bounded_file(activated_secret, 64)
        if len(received) != 32 or not hmac.compare_digest(
                hashlib.sha256(received).hexdigest(), state['secret_sha256']):
            return {**base, 'status': 'ACTIVATION_SECRET_MISMATCH'}
        return {**base, 'status': 'NAMED_AK_EK_CREDENTIAL_ACTIVATION_VERIFIED',
                'credential_activation_verified': True, 'ek_ak_binding_verified': True,
                'ek_spki_sha256': state['ek_spki_sha256'],
                'ak_name_sha256': state['ak_name_sha256'],
                'note': 'Yalniz verilen AK Name ve EK icin credential activation kaniti. '
                        'Quote imza anahtarinin ayni AK oldugu ve boot guveni ayrica dogrulanmalidir'}
    except FileNotFoundError:
        return {**base, 'status': 'UNKNOWN_OR_CONSUMED_CHALLENGE'}
    except (OSError, ValueError, KeyError, TypeError, json.JSONDecodeError):
        return {**base, 'status': 'ACTIVATION_EVIDENCE_INVALID'}


def main(argv=None):
    p = argparse.ArgumentParser(description='Verifier-side offline TPM credential activation; never writes to TPM')
    sub = p.add_subparsers(dest='action', required=True)
    issue = sub.add_parser('issue')
    for name in ('state-dir', 'ek-certificate', 'manufacturer-ca', 'expected-ca-sha256',
                 'expected-ek-spki-sha256', 'ak-name-hex', 'expected-ak-name-sha256'):
        issue.add_argument('--' + name, required=True)
    verify = sub.add_parser('verify')
    for name in ('state-dir', 'challenge-id', 'activated-secret'):
        verify.add_argument('--' + name, required=True)
    opts = vars(p.parse_args(argv))
    action = opts.pop('action')
    result = issue_challenge(**{k.replace('-', '_'): v for k, v in opts.items()}) if action == 'issue' else verify_activation(**opts)
    print(json.dumps(result, ensure_ascii=False, indent=2))
    return 0 if result['status'] in ('CHALLENGE_ISSUED', 'NAMED_AK_EK_CREDENTIAL_ACTIVATION_VERIFIED') else 2


if __name__ == '__main__':
    raise SystemExit(main())
