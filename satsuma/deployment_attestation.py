"""Offline, externally signed OSTree/bootc deployment reference matching.

An independent reference signature establishes publisher-approved *identifiers*,
not immutable runtime state or Secure Boot / measured boot attestation.
No trust anchor is loaded implicitly from the inspected OS.
"""
from __future__ import annotations

import json
import re
import subprocess
from pathlib import Path

from .host_provenance import _run

HEX64 = re.compile(r'[0-9a-fA-F]{64}\Z')
FINGERPRINT = re.compile(r'[0-9a-fA-F]{40,64}\Z')
BOOTC_CMD = ['/usr/bin/bootc', 'status', '--format=json', '--format-version=1']
RPM_OSTREE_CMD = ['/usr/bin/rpm-ostree', 'status', '--json']
MAX_MANIFEST = 65536


def parse_booted_identity(mode: str, raw: str):
    """Extract strict booted digest/checksum; never infer booted from staged/rollback."""
    try:
        parsed = json.loads(raw)
        if not isinstance(parsed, dict):
            raise ValueError('schema')
        if mode == 'bootc':
            if parsed.get('apiVersion') not in ('org.containers.bootc/v1',):
                raise ValueError('api version')
            booted = parsed.get('status', {}).get('booted')
            if not isinstance(booted, dict):
                return {'status': 'NO_BOOTED_DEPLOYMENT'}
            im = booted.get('image')
            if not isinstance(im, dict):
                return {'status': 'MISSING_BOOTED_DIGEST'}
            digest = im.get('imageDigest', '')
            if not isinstance(digest, str) or not digest.startswith('sha256:') or not HEX64.fullmatch(digest[7:]):
                return {'status': 'MISSING_BOOTED_DIGEST'}
            return {'status': 'IDENTITY_OBSERVED', 'mode': mode, 'digest': digest.lower()}
        if mode == 'ostree':
            deployments = parsed.get('deployments')
            if not isinstance(deployments, list):
                raise ValueError('deployments')
            booted = [p for p in deployments if isinstance(p, dict) and p.get('booted') is True]
            if len(booted) != 1:
                return {'status': 'AMBIGUOUS_BOOTED_DEPLOYMENT'}
            checksum = booted[0].get('checksum')
            if not isinstance(checksum, str) or not HEX64.fullmatch(checksum):
                return {'status': 'MISSING_BOOTED_DIGEST'}
            return {'status': 'IDENTITY_OBSERVED', 'mode': mode, 'digest': checksum.lower()}
    except (ValueError, TypeError, AttributeError):
        return {'status': 'INVALID_STATUS_JSON'}
    return {'status': 'UNSUPPORTED_MODE'}


def parse_signed_reference(content: bytes):
    try:
        doc = json.loads(content.decode('utf-8', 'strict'))
        if not isinstance(doc, dict) or set(doc) != {'schema', 'mode', 'allowed_digests'} or doc['schema'] != 1:
            return None
        if doc['mode'] not in ('bootc', 'ostree'):
            return None
        allowed = doc['allowed_digests']
        if not isinstance(allowed, list) or not 1 <= len(allowed) <= 256:
            return None
        prefix = 'sha256:' if doc['mode'] == 'bootc' else ''
        if any(not isinstance(d, str) or not HEX64.fullmatch(d[len(prefix):]) or not d.startswith(prefix)
               for d in allowed):
            return None
        if len(set(allowed)) != len(allowed):
            return None
        return {'mode': doc['mode'], 'allowed_digests': set(d.lower() for d in allowed)}
    except (UnicodeError, ValueError, TypeError, KeyError):
        return None


def compare_reference(reference: dict, identity: dict):
    if identity.get('status') != 'IDENTITY_OBSERVED':
        return {'status': identity.get('status', 'NO_IDENTITY'), 'matched': False, 'verified': False}
    if reference['mode'] != identity['mode']:
        return {'status': 'MODE_MISMATCH', 'matched': False, 'verified': False}
    matched = identity['digest'] in reference['allowed_digests']
    return {'status': 'SIGNED_REFERENCE_MATCH' if matched else 'SIGNED_REFERENCE_MISMATCH',
            'matched': matched, 'verified': False, 'booted_digest': identity['digest'],
            'note': 'Signed reference match is not proof of running filesystem or secure boot integrity'}


def verify_signed_deployment_reference(manifest, signature, keyring, trusted_fingerprint,
                                       *, runner=subprocess.run):
    """Verify detached OpenPGP signature and compare signed digest against local booted status.

    'verified' is deliberately false: matching identifiers does not attest runtime integrity.
    """
    fpr = str(trusted_fingerprint).strip().replace(' ', '').upper()
    if not FINGERPRINT.fullmatch(fpr):
        return {'status': 'INVALID_TRUST_ANCHOR', 'verified': False}
    paths = [Path(p) for p in (manifest, signature, keyring)]
    try:
        if not all(p.is_file() and not p.is_symlink() for p in paths):
            return {'status': 'INVALID_INPUT_FILES', 'verified': False}
        if paths[0].stat().st_size > MAX_MANIFEST or paths[1].stat().st_size > 16384 or paths[2].stat().st_size > 1048576:
            return {'status': 'INPUT_TOO_LARGE', 'verified': False}
        content = paths[0].read_bytes()
        reference = parse_signed_reference(content)
        if reference is None:
            return {'status': 'INVALID_REFERENCE_SCHEMA', 'verified': False}
        sig = runner(['/usr/bin/gpgv', '--status-fd', '2', '--keyring', str(paths[2]),
                      str(paths[1]), str(paths[0])], capture_output=True, timeout=20, check=False)
        if sig.returncode:
            return {'status': 'BAD_REFERENCE_SIGNATURE', 'verified': False}
        stderr = sig.stderr.decode('utf-8', 'replace') if isinstance(sig.stderr, bytes) else (sig.stderr or '')
        signers = {m.group(1).upper() for m in re.finditer(r'^\[GNUPG:\] VALIDSIG ([0-9A-Fa-f]{40,64})(?=\s)', stderr, re.M)}
        if fpr not in signers:
            return {'status': 'UNTRUSTED_REFERENCE_SIGNER', 'verified': False}
        command = BOOTC_CMD if reference['mode'] == 'bootc' else RPM_OSTREE_CMD
        observed, error = _run(command, runner=runner)
        if observed is None:
            return {'status': 'DEPLOYMENT_UNAVAILABLE', 'error': error, 'verified': False}
        result = compare_reference(reference, parse_booted_identity(reference['mode'], observed))
        result['trusted_reference_signer'] = fpr
        return result
    except (OSError, subprocess.TimeoutExpired, TypeError) as exc:
        return {'status': 'ATTESTATION_ERROR', 'error': type(exc).__name__, 'verified': False}


def main(argv=None):
    import argparse
    parser = argparse.ArgumentParser(description='Offline signed deployment reference comparison (no host changes)')
    parser.add_argument('--manifest', required=True)
    parser.add_argument('--signature', required=True)
    parser.add_argument('--keyring', required=True)
    parser.add_argument('--trusted-fingerprint', required=True)
    args = parser.parse_args(argv)
    result = verify_signed_deployment_reference(args.manifest, args.signature, args.keyring, args.trusted_fingerprint)
    print(json.dumps(result, ensure_ascii=False, sort_keys=True))
    return 0 if result['status'] == 'SIGNED_REFERENCE_MATCH' else 2


if __name__ == '__main__':
    raise SystemExit(main())


def bootc_signature_policy_observation(policy_path='/etc/containers/policy.json'):
    """Observe the default containers/image signature policy; not a signature check.

    A configured image-specific transport policy may override the default.
    Unknown and missing policies are not treated as secure.
    """
    path = Path(policy_path)
    try:
        if path.is_symlink() or not path.is_file():
            return {'status': 'POLICY_UNAVAILABLE', 'verified': False}
        if path.stat().st_size > 131072:
            return {'status': 'POLICY_TOO_LARGE', 'verified': False}
        doc = json.loads(path.read_text(encoding='utf-8'))
        if not isinstance(doc, dict):
            return {'status': 'INVALID_POLICY', 'verified': False}
        default = doc.get('default')
        transports = doc.get('transports', {})
        if not isinstance(default, list) or not isinstance(transports, dict):
            return {'status': 'INVALID_POLICY', 'verified': False}
        if not all(isinstance(x, dict) and isinstance(x.get('type'), str) for x in default):
            return {'status': 'INVALID_POLICY', 'verified': False}
        types = sorted({x['type'] for x in default})
        override = bool(transports)
        if any(t == 'insecureAcceptAnything' for t in types):
            status = 'DEFAULT_ACCEPTS_UNSIGNED_IMAGES'
        elif any(t == 'reject' for t in types):
            status = 'DEFAULT_REJECTS_IMAGES'
        elif any(t in ('signedBy', 'sigstoreSigned') for t in types):
            status = 'DEFAULT_SIGNATURE_REQUIRED_CONFIGURED'
        else:
            status = 'UNKNOWN_POLICY_REQUIREMENTS'
        return {'status': status, 'default_requirements': types,
                'transport_overrides_present': override, 'verified': False,
                'note': 'Local policy observation only; image-specific rules and trusted keys not independently verified'}
    except (OSError, UnicodeError, ValueError, TypeError):
        return {'status': 'POLICY_UNREADABLE_OR_INVALID', 'verified': False}
