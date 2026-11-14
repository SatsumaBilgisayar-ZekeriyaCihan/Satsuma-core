"""Offline TPM2 quote verifier, with externally pinned AK and PCR reference.

A successful quote is *not* hardware identity, EK certification, trusted boot,
or runtime integrity. This module never communicates with or modifies a TPM.
The verifier supplies the nonce and reference hashes out-of-band.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import re
import subprocess
from pathlib import Path

CHECKQUOTE = '/usr/bin/tpm2_checkquote'
HEX64 = re.compile(r'^[0-9a-fA-F]{64}$')
NONCE = re.compile(r'^[0-9a-fA-F]{32,128}$')
PCR_LIST = re.compile(r'^sha256:(?:[0-9]|1[0-9]|2[0-3])(?:,(?:[0-9]|1[0-9]|2[0-3]))*$')
MAX_BYTES = {'ak_public': 64 * 1024, 'message': 64 * 1024,
             'signature': 64 * 1024, 'pcr': 256 * 1024}


def _digest(path: Path, limit: int) -> str:
    """Hash a bounded input; refuse symlinks and non-regular files."""
    import os
    import stat
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC | os.O_NONBLOCK)
    try:
        st = os.fstat(fd)
        if not stat.S_ISREG(st.st_mode) or st.st_size == 0 or st.st_size > limit:
            raise ValueError('invalid attestation input file')
        h = hashlib.sha256()
        n = 0
        while True:
            chunk = os.read(fd, min(65536, limit + 1 - n))
            if not chunk:
                break
            n += len(chunk)
            if n > limit:
                raise ValueError('oversized attestation input')
            h.update(chunk)
        if n != st.st_size:
            raise ValueError('input changed during reading')
        return h.hexdigest()
    finally:
        os.close(fd)


def verify_quote(*, ak_public, message, signature, pcr, expected_ak_sha256,
                 expected_pcr_sha256, nonce_hex, pcr_list='sha256:0,2,4,7',
                 executable=CHECKQUOTE, runner=subprocess.run):
    """Validate quote proof against externally supplied expected values.

    Both pins are mandatory. The PCR file pin is a strict byte-for-byte
    approved reference, and is not a substitute for measured-event analysis.
    Nonce freshness/lifecycle must be managed by the independent verifier.
    """
    report = {'status': 'UNVERIFIED', 'quote_signature_verified': False,
              'platform_identity_verified': False, 'trusted_boot_verified': False,
              'note': 'AK/EK sertifika zinciri ve boot olcum anlambilimi dogrulanmadi'}
    try:
        if not (isinstance(expected_ak_sha256, str) and HEX64.fullmatch(expected_ak_sha256)
                and isinstance(expected_pcr_sha256, str) and HEX64.fullmatch(expected_pcr_sha256)
                and isinstance(nonce_hex, str) and NONCE.fullmatch(nonce_hex)
                and len(nonce_hex) % 2 == 0
                and isinstance(pcr_list, str) and PCR_LIST.fullmatch(pcr_list)):
            return {**report, 'status': 'INVALID_EXTERNAL_REFERENCE'}
        paths = dict(ak_public=Path(ak_public), message=Path(message),
                     signature=Path(signature), pcr=Path(pcr))
        hashes = {k: _digest(p, MAX_BYTES[k]) for k, p in paths.items()}
        if hashes['ak_public'] != expected_ak_sha256.lower():
            return {**report, 'status': 'AK_REFERENCE_MISMATCH'}
        if hashes['pcr'] != expected_pcr_sha256.lower():
            return {**report, 'status': 'PCR_REFERENCE_MISMATCH'}
        # tpm2_checkquote accepts binary TSS quote message and PCR blobs.
        # Never execute a command from the evidence files or invoke a shell.
        args = [executable, '-u', str(paths['ak_public']), '-m', str(paths['message']),
                '-s', str(paths['signature']), '-f', str(paths['pcr']), '-g', 'sha256',
                '-q', nonce_hex]
        # Serialized PCR bundles produced by tpm2_quote -o have their own selection.
        # Do not pass -l, which requests normalized PCR format.
        result = runner(args, timeout=15, capture_output=True, check=False,
                        env={'PATH': '/usr/sbin:/usr/bin:/sbin:/bin', 'LC_ALL': 'C'})
        if result.returncode != 0:
            return {**report, 'status': 'QUOTE_REJECTED'}
        # Recheck pins to prevent an obvious swap between hashing and invocation.
        if any(_digest(p, MAX_BYTES[k]) != hashes[k] for k, p in paths.items()):
            return {**report, 'status': 'EVIDENCE_CHANGED'}
        return {**report, 'status': 'QUOTE_AND_PINNED_PCR_VERIFIED',
                'quote_signature_verified': True,
                'note': 'Quote imzasi, nonce ve PCR kaydi dogrulandi; EK/AK kimligi, PCR anlami ve butun sistem guveni ayri kanit ister'}
    except (OSError, ValueError, subprocess.TimeoutExpired):
        return {**report, 'status': 'CHECK_UNAVAILABLE_OR_INVALID_INPUT'}


def main(argv=None):
    parser = argparse.ArgumentParser(description='Offline TPM2 quote verification (no TPM writes)')
    for name in ('ak-public', 'message', 'signature', 'pcr', 'expected-ak-sha256',
                 'expected-pcr-sha256', 'nonce-hex'):
        parser.add_argument('--' + name, required=True)
    args = parser.parse_args(argv)
    result = verify_quote(ak_public=args.ak_public, message=args.message,
                          signature=args.signature, pcr=args.pcr,
                          expected_ak_sha256=args.expected_ak_sha256,
                          expected_pcr_sha256=args.expected_pcr_sha256,
                          nonce_hex=args.nonce_hex)
    print(json.dumps(result, ensure_ascii=False, indent=2))
    return 0 if result['quote_signature_verified'] else 2


if __name__ == '__main__':
    raise SystemExit(main())
