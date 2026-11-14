"""Offline EK certificate, quote, and TPM inventory evidence correlation.

No TPM device access, no keys/NV/firmware mutation and no implicit trust in
local roots. EK->AK binding requires an independently verified TPM credential
activation protocol and is deliberately NOT inferred from two valid proofs.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import stat
import subprocess
from pathlib import Path

from .tpm_quote_verifier import verify_quote

OPENSSL = '/usr/bin/openssl'
HEX64 = re.compile(r'^[0-9a-fA-F]{64}$')
MAX_CERT = 65536
MAX_CA = 262144
ENV = {'PATH': '/usr/sbin:/usr/bin:/sbin:/bin', 'LC_ALL': 'C'}


def _bounded_file(path, maximum):
    """Return stable bounded bytes; reject links, devices, and size changes."""
    fd = os.open(Path(path), os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC | os.O_NONBLOCK)
    try:
        st = os.fstat(fd)
        if not stat.S_ISREG(st.st_mode) or not 0 < st.st_size <= maximum:
            raise ValueError('invalid evidence file')
        chunks = bytearray()
        while len(chunks) <= maximum:
            block = os.read(fd, min(65536, maximum + 1 - len(chunks)))
            if not block:
                break
            chunks.extend(block)
        if len(chunks) != st.st_size or len(chunks) > maximum:
            raise ValueError('evidence changed or oversized')
        return bytes(chunks)
    finally:
        os.close(fd)


def verify_ek_certificate(*, ek_certificate, manufacturer_ca, expected_ca_sha256,
                          expected_ek_spki_sha256, openssl=OPENSSL,
                          runner=subprocess.run):
    """Validate manufacturer EK chain and externally pinned EK SPKI.

    Never use the machine default certificate trust store. The provided CA
    is only trusted when its exact bytes match the independent SHA-256 pin.
    Both an X.509 chain and public-key pin must pass.
    """
    base = {'status': 'EK_NOT_VERIFIED', 'ek_certificate_verified': False,
            'ek_ak_binding_verified': False, 'platform_identity_verified': False}
    if not (isinstance(expected_ca_sha256, str) and HEX64.fullmatch(expected_ca_sha256)
            and isinstance(expected_ek_spki_sha256, str) and HEX64.fullmatch(expected_ek_spki_sha256)):
        return {**base, 'status': 'INVALID_EXTERNAL_TRUST_PINS'}
    try:
        cert_data = _bounded_file(ek_certificate, MAX_CERT)
        ca_data = _bounded_file(manufacturer_ca, MAX_CA)
        if hashlib.sha256(ca_data).hexdigest() != expected_ca_sha256.lower():
            return {**base, 'status': 'MANUFACTURER_CA_PIN_MISMATCH'}
        from cryptography import x509
        from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat
        cert = (x509.load_pem_x509_certificate(cert_data) if b'-----BEGIN CERTIFICATE-----' in cert_data
                else x509.load_der_x509_certificate(cert_data))
        spki = cert.public_key().public_bytes(Encoding.DER, PublicFormat.SubjectPublicKeyInfo)
        if hashlib.sha256(spki).hexdigest() != expected_ek_spki_sha256.lower():
            return {**base, 'status': 'EK_PUBLIC_KEY_MISMATCH'}
        # Verify the actual supplied certificate, not a permissive system CA store.
        # The same paths are hashed and rechecked to detect file replacement.
        args = [openssl, 'verify', '-purpose', 'any', '-no-CApath', '-no-CAstore',
                '-CAfile', str(manufacturer_ca),
                str(ek_certificate)]
        process = runner(args, capture_output=True, timeout=15, check=False, env=ENV)
        if process.returncode != 0:
            return {**base, 'status': 'EK_CERTIFICATE_CHAIN_REJECTED'}
        if (_bounded_file(ek_certificate, MAX_CERT) != cert_data
                or _bounded_file(manufacturer_ca, MAX_CA) != ca_data):
            return {**base, 'status': 'EK_EVIDENCE_CHANGED'}
        # A valid certificate doesn't establish possession by the current TPM.
        return {**base, 'status': 'EK_CERT_CHAIN_AND_PUBLIC_PIN_VERIFIED',
                'ek_certificate_verified': True,
                'note': 'EK sertifikasinin zinciri ve dis EK anahtar pini dogrulandi; TPM possession ve AK baglantisi yok'}
    except (OSError, ValueError, TypeError, subprocess.TimeoutExpired, ImportError):
        return {**base, 'status': 'EK_EVIDENCE_UNAVAILABLE_OR_INVALID'}


def verify_combined(*, ek_certificate, manufacturer_ca, expected_ca_sha256,
                    expected_ek_spki_sha256, ak_public, message, signature, pcr,
                    expected_ak_sha256, expected_pcr_sha256, nonce_hex,
                    ek_runner=subprocess.run, quote_runner=subprocess.run):
    """Fail-closed combined evidence; never manufacture AK/EK binding claims."""
    ek = verify_ek_certificate(ek_certificate=ek_certificate,
                              manufacturer_ca=manufacturer_ca,
                              expected_ca_sha256=expected_ca_sha256,
                              expected_ek_spki_sha256=expected_ek_spki_sha256,
                              runner=ek_runner)
    quote = verify_quote(ak_public=ak_public, message=message, signature=signature,
                         pcr=pcr, expected_ak_sha256=expected_ak_sha256,
                         expected_pcr_sha256=expected_pcr_sha256, nonce_hex=nonce_hex,
                         runner=quote_runner)
    both = ek['ek_certificate_verified'] and quote['quote_signature_verified']
    return {
        'status': ('EK_AND_QUOTE_INDEPENDENTLY_VERIFIED_AK_EK_BINDING_MISSING' if both
                   else 'INCOMPLETE_OR_REJECTED_EVIDENCE'),
        'ek': ek, 'quote': quote,
        'ek_ak_binding_verified': False, 'platform_identity_verified': False,
        'trusted_boot_verified': False, 'tpm_modified': False,
        'note': ('EK sertifikasi ve AK quote ayrica dogrulandi; TPM credential activation '
                 've AK/EK baglama protokolu olmadan donanim kimligi dogrulanmaz')
    }


def main(argv=None):
    parser = argparse.ArgumentParser(description='Offline TPM EK and quote correlation (no TPM access)')
    for flag in ('ek-certificate', 'manufacturer-ca', 'expected-ca-sha256',
                 'expected-ek-spki-sha256', 'ak-public', 'message', 'signature',
                 'pcr', 'expected-ak-sha256', 'expected-pcr-sha256', 'nonce-hex'):
        parser.add_argument('--' + flag, required=True)
    args = vars(parser.parse_args(argv))
    report = verify_combined(**{k.replace('-', '_'): v for k, v in args.items()})
    print(json.dumps(report, ensure_ascii=False, indent=2))
    return 0 if report['status'].startswith('EK_AND_QUOTE_') else 2


if __name__ == '__main__':
    raise SystemExit(main())
