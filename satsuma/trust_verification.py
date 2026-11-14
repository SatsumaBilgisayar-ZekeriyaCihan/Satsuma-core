"""Offline Fedora image evidence and OSTree verification observation.

Trust anchor fingerprint must be obtained independently of the examined host.
No network, root requirement or host mutations.
"""
from __future__ import annotations
import hashlib
import os
from pathlib import Path
import re
import subprocess
from .host_provenance import _run

FPR_RE = re.compile(r'[0-9A-Fa-f]{40,64}\Z')
SHA256_RE = re.compile(r'[a-fA-F0-9]{64}\Z')
OSTREE_COMMAND = ['/usr/bin/ostree', 'admin', 'status', '--verify']


def ostree_signature_observation(runner=subprocess.run):
    text, error = _run(OSTREE_COMMAND, runner=runner)
    if text is None:
        return {'status': 'UNAVAILABLE', 'error': error, 'verified': False}
    # Text output is *not* a machine-readable proof of all deployment signatures.
    return {'status': 'SIGNATURE_REPORT_AVAILABLE', 'verified': False,
            'note': 'OSTree verification output requires release-specific review; local keyring trust not independently attested',
            'report_excerpt': text[:2048]}


def _signed_hashes(plaintext, image_name):
    # Fedora signed checksum files use SHA256 (filename) = digest.
    # Also accept strict coreutils format to support other official signed manifests.
    found = set()
    for line in plaintext.splitlines():
        m = re.fullmatch(r'SHA256 \(([^\r\n()]+)\) = ([0-9a-fA-F]{64})', line.strip())
        if m and m.group(1) == image_name:
            found.add(m.group(2).lower())
        m = re.fullmatch(r'([0-9a-fA-F]{64}) [ *]([^\r\n]+)', line.strip())
        if m and m.group(2) == image_name:
            found.add(m.group(1).lower())
    return found


def verify_fedora_iso(image, signed_checksum, keyring, trusted_fingerprint, *, runner=subprocess.run):
    """Verify signature + independently pinned signer + exact image digest.

    The caller supplies its own trusted fingerprint (out-of-band). This does
    not establish provenance of an already-installed OS.
    """
    fpr = str(trusted_fingerprint).upper().replace(' ', '')
    if not FPR_RE.fullmatch(fpr):
        return {'status': 'INVALID_TRUST_ANCHOR', 'verified': False}
    paths = [Path(p) for p in (image, signed_checksum, keyring)]
    try:
        if not all(p.is_file() and not p.is_symlink() for p in paths):
            return {'status': 'INVALID_INPUT_FILES', 'verified': False}
        image_path, checksum_path, keyring_path = paths
        if image_path.name != os.path.basename(str(image_path)):
            return {'status': 'INVALID_IMAGE', 'verified': False}
        command = ['/usr/bin/gpgv', '--status-fd', '2', '--keyring', str(keyring_path),
                   '--output', '-', str(checksum_path)]
        outcome = runner(command, capture_output=True, timeout=20, check=False)
        if outcome.returncode != 0:
            return {'status': 'BAD_SIGNATURE', 'verified': False}
        signed_text = outcome.stdout.decode('utf-8', 'replace') if isinstance(outcome.stdout, bytes) else outcome.stdout
        status_text = outcome.stderr.decode('utf-8', 'replace') if isinstance(outcome.stderr, bytes) else outcome.stderr
        valid = {m.group(1).upper() for m in re.finditer(r'\[GNUPG:\] VALIDSIG ([0-9A-Fa-f]{40,64})(?=\s)', status_text)}
        if fpr not in valid:
            return {'status': 'UNTRUSTED_SIGNER', 'verified': False}
        digests = _signed_hashes(signed_text, image_path.name)
        if len(digests) != 1:
            return {'status': 'MISSING_OR_AMBIGUOUS_IMAGE_HASH', 'verified': False}
        expected = next(iter(digests))
        hasher = hashlib.sha256()
        with open(image_path, 'rb') as stream:
            for block in iter(lambda: stream.read(1024 * 1024), b''):
                hasher.update(block)
        if hasher.hexdigest() != expected:
            return {'status': 'IMAGE_HASH_MISMATCH', 'verified': False}
        return {'status': 'VERIFIED_OFFLINE_IMAGE', 'verified': True,
                'sha256': expected, 'signer_fingerprint': fpr,
                'scope': 'supplied_iso_only_not_installed_os'}
    except (OSError, subprocess.TimeoutExpired, UnicodeError, TypeError) as exc:
        return {'status': 'VERIFICATION_ERROR', 'verified': False, 'error': type(exc).__name__}


def main(argv=None):
    """Operator-invoked read-only verification; never trusts a local key by default."""
    import argparse
    import json
    parser = argparse.ArgumentParser(description='Offline Fedora ISO and OSTree evidence verification')
    sub = parser.add_subparsers(dest='action', required=True)
    iso = sub.add_parser('iso', help='verify signed CHECKSUM against an independently trusted fingerprint')
    iso.add_argument('--image', required=True)
    iso.add_argument('--signed-checksum', required=True)
    iso.add_argument('--keyring', required=True)
    iso.add_argument('--trusted-fingerprint', required=True)
    sub.add_parser('ostree-observe', help='inspect local OSTree signature report (not independent trust)')
    args = parser.parse_args(argv)
    if args.action == 'iso':
        result = verify_fedora_iso(args.image, args.signed_checksum, args.keyring, args.trusted_fingerprint)
    else:
        result = ostree_signature_observation()
    print(json.dumps(result, ensure_ascii=False, sort_keys=True))
    return 0 if result.get('verified') is True or result.get('status') == 'SIGNATURE_REPORT_AVAILABLE' else 2


if __name__ == '__main__':
    raise SystemExit(main())
