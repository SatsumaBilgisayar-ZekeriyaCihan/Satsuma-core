"""Read-only host provenance / supervision / exposure report.

No package installation, policy mutation, network access or heuristic quarantine.
OSTree metadata and local RPM DB are observations, not a trusted attestation.
"""
from __future__ import annotations

import json
import os
import re
import shlex
import stat
import subprocess
from pathlib import Path

ENV = {'PATH': '/usr/sbin:/usr/bin:/sbin:/bin', 'LANG': 'C', 'LC_ALL': 'C'}
MAX_OUTPUT = 512 * 1024
MAX_PACKAGES = 5000


def _run(argv, *, runner=subprocess.run):
    """Constant binary arguments only; no shell and bounded output/time."""
    try:
        result = runner(argv, capture_output=True, text=True, timeout=8, check=False, env=ENV)
    except (FileNotFoundError, OSError, subprocess.TimeoutExpired) as exc:
        return None, type(exc).__name__
    output = result.stdout or ''
    if result.returncode != 0:
        return None, 'exit_'+str(result.returncode)
    if len(output) > MAX_OUTPUT:
        return None, 'output_limit'
    return output, None


def parse_os_release(text):
    result = {}
    for line in text.splitlines():
        match = re.fullmatch(r'([A-Z][A-Z0-9_]*)=(.*)', line.strip())
        if not match:
            continue
        value = match.group(2)
        if len(value) >= 2 and value[0] == value[-1] and value[0] in ('"', "'"):
            value = value[1:-1]
            if value and match.group(2).startswith('"'):
                value = value.replace('\\"', '"').replace('\\n', '\n')
        result[match.group(1)] = value[:256]
    return {key: result.get(key) for key in ('ID', 'ID_LIKE', 'NAME', 'VERSION_ID', 'VARIANT_ID', 'PRETTY_NAME')}


def _read(path, limit=16384):
    try:
        with open(path, 'r', encoding='utf-8', errors='replace') as stream:
            return stream.read(limit + 1)[:limit]
    except OSError:
        return None


def parse_rpm_ostree(text):
    doc = json.loads(text)
    deployments = doc.get('deployments', [])
    if not isinstance(deployments, list):
        raise ValueError('invalid deployments')
    items = []
    for item in deployments[:16]:
        if not isinstance(item, dict):
            continue
        overlay = {}
        for key in ('requested-packages', 'requested-local-packages', 'requested-local-fileoverride-packages',
                    'requested-base-removals', 'requested-base-local-replacements',
                    'requested-base-remote-replacements'):
            values = item.get(key, [])
            overlay[key] = values[:128] if isinstance(values, list) else []
        items.append({'booted': item.get('booted') is True, 'checksum': str(item.get('checksum') or '')[:128],
                      'origin': str(item.get('origin') or '')[:256], 'layer_changes': overlay})
    return items


def parse_bootc(text):
    doc = json.loads(text)
    booted = (doc.get('status') or {}).get('booted')
    return {'booted_present': isinstance(booted, dict),
            'image_reference': str((booted or {}).get('image', {}).get('image') or '')[:300]
            if isinstance(booted, dict) and isinstance(booted.get('image'), dict) else None}


def _supervision(pid_root=Path('/proc')):
    comm = _read(pid_root / '1' / 'comm')
    cgroup = _read(pid_root / 'self' / 'cgroup', 8192)
    return {'pid1': comm.strip() if comm else None,
            'self_cgroup': cgroup[:1024] if cgroup else None,
            'note': 'PID1 ve cgroup yerel gozlemdir; dis yonetici veya kalicilik kaniti degildir'}


def _script_exposure(paths):
    findings = []
    for path in paths:
        p = Path(path)
        try:
            info = p.lstat()
        except OSError:
            continue
        if stat.S_ISLNK(info.st_mode):
            findings.append({'path': str(p), 'signal': 'symlink', 'severity': 'review'})
        elif not stat.S_ISREG(info.st_mode):
            findings.append({'path': str(p), 'signal': 'unexpected_type', 'severity': 'review'})
        elif info.st_mode & 0o022:
            findings.append({'path': str(p), 'signal': 'group_or_world_writable', 'severity': 'high'})
        elif info.st_uid != 0:
            findings.append({'path': str(p), 'signal': 'non_root_owned', 'severity': 'review'})
    return findings


def service_entrypoints(roots=None):
    """Collect on-disk declarations, not the merged/effective unit configuration."""
    roots = roots if roots is not None else (
        Path('/etc/systemd/system'), Path('/usr/lib/systemd/system'),
        Path('/run/systemd/system'))
    records = []
    for root in roots:
        if not root.is_dir():
            continue
        candidates = list(root.glob('satsuma*.service'))[:100]
        for folder in list(root.glob('satsuma*.service.d'))[:100]:
            candidates.extend(list(folder.glob('*.conf'))[:40])
        for path in candidates[:300]:
            if path.is_symlink():
                records.append({'path': str(path), 'signal': 'unit_symlink',
                                'commands': [], 'authority': 'unknown'})
                continue
            try:
                meta = path.stat()
            except OSError:
                continue
            if not stat.S_ISREG(meta.st_mode):
                continue
            content = _read(path, 8192)
            if content is None:
                continue
            commands = []
            user = None
            for line in content.splitlines():
                stripped = line.strip()
                if stripped.startswith(('ExecStart=', 'ExecStartPre=', 'ExecStartPost=', 'ExecReload=')):
                    key, _, command = stripped.partition('=')
                    try:
                        words = shlex.split(command, posix=True)
                    except ValueError:
                        words = []
                    # Never expose arbitrary argv: it may contain passwords or tokens.
                    binary = words[0].lstrip('+-!:@') if words else ''
                    script = next((w for w in words[1:5] if w.endswith(('.py', '.pyw')) and w.startswith('/')), None)
                    commands.append(key + '=' + binary[:240] + ((' script=' + script[:240]) if script else ''))
                elif stripped.startswith('User='):
                    user = stripped.partition('=')[2][:100]
            records.append({'path': str(path), 'signal': 'writable_unit' if meta.st_mode & 0o022 else 'unit_declaration',
                            'commands': commands[:16], 'authority': 'User=' + user if user else 'User not declared in this file'})
    return records[:256]


def parse_rpm_packages(text):
    """Inventory only. Name-based guesses are NOT vulnerability findings."""
    packages = []
    for line in text.splitlines()[:MAX_PACKAGES]:
        parts = line.split('\t')
        if len(parts) != 4:
            continue
        name, version, release, vendor = parts
        if not name or any(len(value) > 256 for value in parts):
            continue
        packages.append({'name': name, 'version': version, 'release': release, 'vendor': vendor})
    return packages


def collect(*, runner=subprocess.run, reader=_read, pid_root=Path('/proc'), watch_paths=None):
    """No host changes. Does not claim ISO provenance, CVEs, or clean baseline."""
    os_data = parse_os_release(reader('/etc/os-release') or '')
    ostree_text, ostree_error = _run(['/usr/bin/rpm-ostree', 'status', '--json'], runner=runner)
    bootc_text, bootc_error = _run(['/usr/bin/bootc', 'status', '--format=json', '--format-version=1'], runner=runner)
    ostree, bootc = [], None
    errors = {}
    if ostree_text is not None:
        try: ostree = parse_rpm_ostree(ostree_text)
        except (ValueError, TypeError, AttributeError): errors['rpm_ostree'] = 'invalid_json_or_schema'
    elif ostree_error != 'FileNotFoundError':
        errors['rpm_ostree'] = ostree_error
    if bootc_text is not None:
        try: bootc = parse_bootc(bootc_text)
        except (ValueError, TypeError, AttributeError): errors['bootc'] = 'invalid_json_or_schema'
    elif bootc_error != 'FileNotFoundError':
        errors['bootc'] = bootc_error
    package_text, pkg_error = _run(['/usr/bin/rpm', '-qa', '--qf', '%{NAME}\\t%{VERSION}\\t%{RELEASE}\\t%{VENDOR}\\n'], runner=runner)
    packages = parse_rpm_packages(package_text) if package_text is not None else []
    if pkg_error: errors['rpm'] = pkg_error
    mode = ('bootc' if bootc and bootc['booted_present'] else
            'rpm-ostree' if any(item.get('booted') for item in ostree) else
            'unknown' if ostree or bootc else 'traditional_or_unknown')
    paths = watch_paths if watch_paths is not None else (
        '/usr/bin/python3', '/usr/local/bin/python3', '/etc/satsuma-core',
        '/opt/satsuma-core', '/usr/lib/systemd/system/satsuma-core.service',
        '/etc/systemd/system/satsuma-core.service')
    return {'schema': 1, 'mode': mode, 'os_release': os_data, 'supervision': _supervision(pid_root),
            'deployments': ostree, 'bootc': bootc, 'packages': {'count_observed': len(packages),
              'truncated': len(packages) >= MAX_PACKAGES, 'names': [p['name'] for p in packages],
              'trust': 'local_rpmdb_unverified', 'vulnerabilities_verified': False},
            'script_exposure': _script_exposure(paths),
            'unit_entrypoints': service_entrypoints(), 'errors': errors,
            'analysis': {'python_heuristics': 'existing satsuma.python_audit; separate scan required',
                         'boot_hooks': 'existing satsuma.boot_inventory; separate scan required',
                         'package_signatures': 'existing satsuma.package_signatures; separate scan required',
                         'external_management': 'cannot determine from PID1 alone',
                         'iso_integrity': 'cannot certify from live host alone'},
            'mutations': False}


if __name__ == '__main__':
    print(json.dumps(collect(), ensure_ascii=False, indent=2))
