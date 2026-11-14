"""Bounded, read-only observations of TPM public object identity and NV metadata.

Not an attestation and never a substitute for an independent trusted baseline.
No NV data, secrets, authorization or TPM mutation operations are requested.
"""
from __future__ import annotations

import hashlib
import json
import re
import subprocess
from pathlib import Path

from .tpm_integrity_guard import (ENV, MAX_HANDLES, _read_baseline,
                                  HEX_SHA256, collect as collect_handles)

READPUBLIC = '/usr/bin/tpm2_readpublic'
NVREADPUBLIC = '/usr/bin/tpm2_nvreadpublic'
MAX_PUBLIC_OUTPUT = 32 * 1024
MAX_NV_OUTPUT = 256 * 1024
MAX_OBJECTS = 128
# TPM2B_NAME begins with TPMI_ALG_HASH and then has the algorithm's digest.
NAME_DIGEST_BYTES = {'0004': 20, '000b': 32, '000c': 48, '000d': 64, '0012': 32}
NAME_LINE = re.compile(r'^\s*(name|qualified name):\s*([0-9a-fA-F]+)\s*$')
NV_HEADER = re.compile(r'^(0x[0-9a-fA-F]{1,8}):\s*$')
NV_FIELDS = ('hash algorithm', 'attributes', 'size', 'authorization policy')
HEX = re.compile(r'^[a-fA-F0-9]*$')


def _valid_name(text):
    if not isinstance(text, str) or len(text) < 4 or len(text) % 2 or not HEX.fullmatch(text):
        return False
    alg = text[:4].lower()
    return alg in NAME_DIGEST_BYTES and len(text) == 4 + 2 * NAME_DIGEST_BYTES[alg]


def parse_object_public(raw):
    """Only retain TPM names, not public key material or command output."""
    if not isinstance(raw, (bytes, str)) or len(raw) > MAX_PUBLIC_OUTPUT:
        raise ValueError('invalid public output size')
    value = raw.decode('ascii', 'strict') if isinstance(raw, bytes) else raw
    fields = {}
    for line in value.splitlines():
        match = NAME_LINE.fullmatch(line)
        if not match:
            continue
        key, digest = match.groups()
        if key in fields or not _valid_name(digest):
            raise ValueError('invalid or repeated TPM name')
        fields[key] = digest.lower()
    if set(fields) != {'name', 'qualified name'}:
        raise ValueError('missing TPM name or qualified name')
    return {'name': fields['name'], 'qualified_name': fields['qualified name']}


def parse_nv_public(raw, expected_handles):
    """Parse only documented public NV YAML fields; fail if entries are missing.

    The SHA-256 below is a fingerprint of *locally reported public metadata*,
    NOT a TPM signed name and NOT a hash of NV content.
    """
    if not isinstance(raw, (bytes, str)) or len(raw) > MAX_NV_OUTPUT:
        raise ValueError('invalid NV output size')
    value = raw.decode('ascii', 'strict') if isinstance(raw, bytes) else raw
    if any(ord(c) < 32 and c not in '\n\r\t' for c in value):
        raise ValueError('control in NV public output')
    expected = set(expected_handles)
    if len(expected) > MAX_OBJECTS:
        raise ValueError('too many NV handles')
    blocks = {}
    active = None
    lines = []

    def store():
        if active is None:
            return
        fields = {}
        section = None
        for line in lines:
            if not line.strip():
                continue
            top = re.fullmatch(r'  ([a-z]+(?: [a-z]+)*):(?:[ \t]*(.*))?', line)
            if top:
                name, inline = top.groups()
                if name not in NV_FIELDS or name in fields:
                    raise ValueError('unsupported or duplicate NV field')
                fields[name] = []
                section = name
                if inline:
                    fields[name].append(inline.strip())
                continue
            if not line.startswith('    ') or section is None:
                raise ValueError('invalid NV field indentation')
            part = line.strip()
            if len(part) > 256 or not re.fullmatch(r'[\w| :xX0-9a-fA-F.-]+', part):
                raise ValueError('invalid NV field content')
            fields[section].append(part)
        if set(fields) != set(NV_FIELDS):
            raise ValueError('missing NV public metadata')
        # Canonicalize reported public fields without relying on YAML implicit types.
        canonical = json.dumps(fields, sort_keys=True, separators=(',', ':'), ensure_ascii=True)
        blocks[active] = {'public_metadata_sha256': hashlib.sha256(canonical.encode('ascii')).hexdigest(),
                          'metadata_source': 'local_tpm2_nvreadpublic_not_signed'}

    for line in value.splitlines():
        match = NV_HEADER.fullmatch(line)
        if match:
            store()
            handle = f'0x{int(match.group(1), 16):08x}'
            if handle not in expected or handle in blocks:
                raise ValueError('unexpected NV index')
            active = handle
            lines = []
        elif line.strip():
            if active is None or len(line) > 512:
                raise ValueError('unexpected NV metadata')
            lines.append(line)
    store()
    if set(blocks) != expected:
        raise ValueError('incomplete NV public metadata')
    return dict(sorted(blocks.items()))


def collect_public(*, runner=subprocess.run, handle_inventory=None):
    """Read public TPM identity using fixed binaries; all failures fail closed."""
    observed = handle_inventory if handle_inventory is not None else collect_handles(runner=runner)
    result = {'status': 'UNAVAILABLE', 'verified': False, 'tpm_modified': False,
              'persistent': {}, 'nv_indices': {},
              'note': 'Local TPM public identity observation; no independent TPM attestation'}
    if observed.get('status') != 'LOCAL_INVENTORY_OBSERVED':
        result['status'] = 'HANDLE_INVENTORY_INCOMPLETE'
        return result
    caps = observed.get('capabilities', {})
    try:
        persistent = caps['handles-persistent']['handles']
        nv = caps['handles-nv-index']['handles']
        if not all(isinstance(values, list) and len(values) <= MAX_OBJECTS for values in (persistent, nv)):
            result['status'] = 'PUBLIC_INVENTORY_LIMIT'
            return result
        # Verify identifiers even when a fabricated inventory was passed in tests/caller.
        for handle in persistent:
            if not isinstance(handle, str) or not re.fullmatch(r'0x81[0-9a-f]{6}', handle):
                raise ValueError('invalid persistent handle')
        for handle in nv:
            if not isinstance(handle, str) or not re.fullmatch(r'0x01[0-9a-f]{6}', handle):
                raise ValueError('invalid NV index')
        if len(set(persistent)) != len(persistent) or len(set(nv)) != len(nv):
            raise ValueError('duplicate handle')
    except (KeyError, TypeError, ValueError):
        result['status'] = 'INVALID_HANDLE_INVENTORY'
        return result

    for handle in persistent:
        try:
            proc = runner([READPUBLIC, '-c', handle], timeout=8, capture_output=True,
                          check=False, env=ENV)
            if proc.returncode:
                result['status'] = 'PUBLIC_READ_FAILED'
                return result
            result['persistent'][handle] = parse_object_public(proc.stdout)
        except (OSError, ValueError, UnicodeError, subprocess.TimeoutExpired):
            result['status'] = 'PUBLIC_READ_FAILED'
            return result
    try:
        if nv:
            proc = runner([NVREADPUBLIC], timeout=8, capture_output=True,
                          check=False, env=ENV)
            if proc.returncode:
                result['status'] = 'NV_PUBLIC_READ_FAILED'
                return result
            result['nv_indices'] = parse_nv_public(proc.stdout, nv)
        # Re-read handle listing to detect modifications while collecting.
        after = collect_handles(runner=runner)
        if after.get('status') != 'LOCAL_INVENTORY_OBSERVED' or any(
                after['capabilities'][k]['handles'] != caps[k]['handles']
                for k in ('handles-persistent', 'handles-nv-index')):
            result['status'] = 'HANDLE_SET_CHANGED_DURING_READ'
            return result
    except (OSError, ValueError, UnicodeError, subprocess.TimeoutExpired, KeyError, TypeError):
        result['status'] = 'NV_PUBLIC_READ_FAILED'
        return result
    result['status'] = 'LOCAL_PUBLIC_INVENTORY_OBSERVED'
    return result


def compare_public_with_pin(report, baseline_path, expected_sha256):
    """External SHA-256 pin attests to bytes supplied externally, not signer identity."""
    base = {'status': 'NOT_VERIFIED', 'baseline_authenticated': False,
            'tpm_firmware_verified': False, 'trusted_boot_verified': False}
    if report.get('status') != 'LOCAL_PUBLIC_INVENTORY_OBSERVED':
        return {**base, 'status': 'PUBLIC_INVENTORY_INCOMPLETE'}
    if not isinstance(expected_sha256, str) or not HEX_SHA256.fullmatch(expected_sha256):
        return {**base, 'status': 'INVALID_EXTERNAL_BASELINE_PIN'}
    try:
        raw = _read_baseline(Path(baseline_path))
        if hashlib.sha256(raw).hexdigest() != expected_sha256.lower():
            return {**base, 'status': 'BASELINE_PIN_MISMATCH'}
        data = json.loads(raw)
        if not isinstance(data, dict) or set(data) != {'schema', 'persistent', 'nv_indices'} or data['schema'] != 2:
            raise ValueError('invalid schema')
        diffs = {}
        for key, fields in (('persistent', {'name', 'qualified_name'}),
                            ('nv_indices', {'public_metadata_sha256', 'metadata_source'})):
            ref = data[key]
            current = report[key]
            if not isinstance(ref, dict) or len(ref) > MAX_OBJECTS:
                raise ValueError('invalid reference')
            if any(not isinstance(h, str) or not isinstance(v, dict) or set(v) != fields
                   for h, v in ref.items()):
                raise ValueError('invalid entries')
            for h, v in ref.items():
                if key == 'persistent':
                    if not re.fullmatch(r'0x81[0-9a-f]{6}', h) or not all(_valid_name(x) and x == x.lower() for x in v.values()):
                        raise ValueError('invalid persistent baseline')
                else:
                    if not re.fullmatch(r'0x01[0-9a-f]{6}', h) or not HEX_SHA256.fullmatch(v['public_metadata_sha256']) or v['metadata_source'] != 'local_tpm2_nvreadpublic_not_signed':
                        raise ValueError('invalid NV baseline')
            a, b = set(current), set(ref)
            diffs[key] = {'added': sorted(a-b), 'removed': sorted(b-a),
                          'identity_changed': sorted(h for h in a & b if current[h] != ref[h])}
        changed = any(any(v.values()) for v in diffs.values())
        return {**base, 'status': 'PUBLIC_IDENTITY_CHANGE_OBSERVED' if changed else 'PUBLIC_IDENTITIES_MATCH_PINNED_BASELINE',
                'pin_matched': True, 'changes': diffs,
                'note': 'TPM public observations may be forged by compromised OS; changes alone do not prove malice'}
    except (OSError, ValueError, TypeError, KeyError, UnicodeError, json.JSONDecodeError):
        return {**base, 'status': 'INVALID_BASELINE'}


def main(argv=None):
    import argparse
    parser = argparse.ArgumentParser(description='Read-only TPM public identities; never reads NV data or changes TPM')
    parser.add_argument('--baseline')
    parser.add_argument('--expected-baseline-sha256')
    args = parser.parse_args(argv)
    if bool(args.baseline) != bool(args.expected_baseline_sha256):
        parser.error('baseline and independent SHA-256 must be provided together')
    report = collect_public()
    if args.baseline:
        report['comparison'] = compare_public_with_pin(report, args.baseline, args.expected_baseline_sha256)
    print(json.dumps(report, ensure_ascii=False, indent=2))
    return 0 if report['status'] == 'LOCAL_PUBLIC_INVENTORY_OBSERVED' else 2


if __name__ == '__main__':
    raise SystemExit(main())
