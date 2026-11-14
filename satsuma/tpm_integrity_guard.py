"""Read-only TPM persistent-object inventory; no TPM mutation operations.

An observed handle is not evidence of malware. For provenance, a baseline must
be independently pinned; local TPM firmware/OS output can itself be untrusted.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import re
import subprocess
import os
import stat
from pathlib import Path

GETCAP = '/usr/bin/tpm2_getcap'
CAPABILITIES = ('handles-persistent', 'handles-nv-index')
HEX_HANDLE = re.compile(r'^\s*-\s*(0x[0-9a-fA-F]{1,8})\s*$')
HEX_SHA256 = re.compile(r'^[0-9a-fA-F]{64}$')
MAX_OUTPUT = 64 * 1024
MAX_HANDLES = 1024
MAX_BASELINE = 64 * 1024
ENV = {'PATH': '/usr/sbin:/usr/bin:/sbin:/bin', 'LC_ALL': 'C', 'LANG': 'C'}


def _parse_handles(value, capability):
    """Strictly accept tpm2-tools YAML handle list, never shell/ANSI output."""
    if not isinstance(value, (str, bytes)) or len(value) > MAX_OUTPUT:
        raise ValueError('invalid command output')
    if isinstance(value, bytes):
        value = value.decode('ascii', 'strict')
    handles = set()
    for line in value.splitlines():
        if not line.strip():
            continue
        match = HEX_HANDLE.fullmatch(line)
        if not match:
            raise ValueError('unexpected output grammar')
        number = int(match.group(1), 16)
        if capability == 'handles-persistent':
            if not 0x81000000 <= number <= 0x81ffffff:
                raise ValueError('out of range persistent handle')
        elif capability == 'handles-nv-index':
            if not 0x01000000 <= number <= 0x01ffffff:
                raise ValueError('out of range NV index')
        else:
            raise ValueError('unsupported capability')
        if number in handles or len(handles) >= MAX_HANDLES:
            raise ValueError('duplicate or excessive handles')
        handles.add(number)
    return [f'0x{handle:08x}' for handle in sorted(handles)]


def collect(*, runner=subprocess.run, executable=GETCAP):
    """Issue only GetCapability reads. No settings or TPM authorization."""
    result = {'status': 'UNAVAILABLE', 'verified': False,
              'tpm_modified': False, 'capabilities': {},
              'note': 'Yerel TPM gozlemi; nesne kimligi ve cihaz guveni dogrulanmadi'}
    for capability in CAPABILITIES:
        try:
            proc = runner([executable, capability], timeout=8, capture_output=True,
                          check=False, env=ENV)
            if proc.returncode:
                result['capabilities'][capability] = {'status': 'COMMAND_FAILED'}
                continue
            handles = _parse_handles(proc.stdout, capability)
            result['capabilities'][capability] = {'status': 'OBSERVED',
                                                  'count': len(handles), 'handles': handles}
        except (OSError, ValueError, UnicodeError, subprocess.TimeoutExpired):
            result['capabilities'][capability] = {'status': 'UNAVAILABLE_OR_INVALID_OUTPUT'}
    if all(result['capabilities'][k]['status'] == 'OBSERVED' for k in CAPABILITIES):
        result['status'] = 'LOCAL_INVENTORY_OBSERVED'
    elif any(result['capabilities'][k]['status'] == 'OBSERVED' for k in CAPABILITIES):
        result['status'] = 'PARTIAL_INVENTORY'
    return result


def _read_baseline(path):
    """Refuse symlinks and non-regular files, bound bytes read."""
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC | os.O_NONBLOCK)
    try:
        st = os.fstat(fd)
        if not stat.S_ISREG(st.st_mode) or not 0 < st.st_size <= MAX_BASELINE:
            raise ValueError('invalid baseline')
        blob = bytearray()
        while len(blob) <= MAX_BASELINE:
            chunk = os.read(fd, min(8192, MAX_BASELINE + 1 - len(blob)))
            if not chunk:
                break
            blob.extend(chunk)
        if len(blob) != st.st_size or len(blob) > MAX_BASELINE:
            raise ValueError('baseline changed')
        return bytes(blob)
    finally:
        os.close(fd)


def compare_with_pinned_baseline(inventory, baseline_path, expected_sha256):
    """Compare handle membership only, never claim content/firmware integrity."""
    base = {'status': 'BASELINE_NOT_VERIFIED', 'trusted_boot_verified': False,
            'tpm_firmware_verified': False, 'baseline_authenticated': False}
    if not isinstance(expected_sha256, str) or not HEX_SHA256.fullmatch(expected_sha256):
        return {**base, 'status': 'INVALID_EXTERNAL_BASELINE_PIN'}
    if inventory.get('status') != 'LOCAL_INVENTORY_OBSERVED':
        return {**base, 'status': 'INVENTORY_INCOMPLETE'}
    try:
        raw = _read_baseline(Path(baseline_path))
        if hashlib.sha256(raw).hexdigest() != expected_sha256.lower():
            return {**base, 'status': 'BASELINE_PIN_MISMATCH'}
        data = json.loads(raw)
        if not isinstance(data, dict) or set(data) != {'schema', 'handles-persistent', 'handles-nv-index'} or data['schema'] != 1:
            raise ValueError('invalid baseline schema')
        delta = {}
        for key in CAPABILITIES:
            reference = data[key]
            if not isinstance(reference, list) or len(reference) > MAX_HANDLES or any(not isinstance(h,str) for h in reference):
                raise ValueError('invalid baseline handles')
            if len(reference) != len(set(reference)) or reference != _parse_handles(''.join('- '+h+'\n' for h in reference), key):
                raise ValueError('noncanonical baseline handles')
            observed = set(inventory['capabilities'][key]['handles'])
            delta[key] = {'added': sorted(observed-set(reference)),
                          'removed': sorted(set(reference)-observed)}
        changes = any(v['added'] or v['removed'] for v in delta.values())
        return {**base, 'status': 'HANDLE_CHANGE_OBSERVED' if changes else 'HANDLES_MATCH_PINNED_BASELINE',
                'baseline_authenticated': False, 'pin_matched': True, 'changes': delta,
                'note': 'Pin eslesmesi baseline kaynaginin kimligini kanitlamaz; handle farki zararli yazilim kaniti degildir'}
    except (OSError, ValueError, UnicodeError, TypeError, KeyError, json.JSONDecodeError):
        return {**base, 'status': 'INVALID_BASELINE'}


def main(argv=None):
    parser = argparse.ArgumentParser(description='Read-only TPM handle inventory and externally pinned baseline comparison')
    parser.add_argument('--baseline')
    parser.add_argument('--expected-baseline-sha256')
    args = parser.parse_args(argv)
    if bool(args.baseline) != bool(args.expected_baseline_sha256):
        parser.error('baseline and independently obtained SHA-256 pin must be given together')
    report = collect()
    if args.baseline:
        report['comparison'] = compare_with_pinned_baseline(report, args.baseline, args.expected_baseline_sha256)
    print(json.dumps(report, ensure_ascii=False, indent=2))
    return 0 if report['status'] == 'LOCAL_INVENTORY_OBSERVED' else 2


if __name__ == '__main__':
    raise SystemExit(main())
