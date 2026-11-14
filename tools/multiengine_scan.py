#!/usr/bin/env python3
"""Release-only VirusTotal hash verification. No file upload is implemented.

A hash lookup does not prove code safety. This gate is never imported at runtime.
"""
import argparse
import datetime as dt
import hashlib
import json
import os
from pathlib import Path
import stat
import tempfile
import urllib.error
import urllib.request

MAX_RPM_BYTES = 32 * 1024 * 1024
MIN_ENGINES = 20
MAX_AGE_DAYS = 7


class GateError(RuntimeError):
    pass


def checked_rpm(path):
    path = Path(path).absolute()
    st = path.lstat()
    if not stat.S_ISREG(st.st_mode) or st.st_nlink != 1:
        raise GateError('RPM must be a normal, single-link regular file')
    if st.st_mode & 0o022:
        raise GateError('RPM must not be group/world writable')
    if st.st_size <= 0 or st.st_size > MAX_RPM_BYTES:
        raise GateError('RPM size outside 1..32 MiB')
    fd = os.open(path, os.O_RDONLY | getattr(os, 'O_NOFOLLOW', 0) | getattr(os, 'O_NONBLOCK', 0))
    try:
        before = os.fstat(fd)
        if (before.st_ino, before.st_dev, before.st_size) != (st.st_ino, st.st_dev, st.st_size):
            raise GateError('RPM changed during open')
        digest = hashlib.sha256()
        prefix = b''
        while True:
            chunk = os.read(fd, 64 * 1024)
            if not chunk:
                break
            if not prefix:
                prefix = chunk[:4]
            digest.update(chunk)
        after = os.fstat(fd)
        if (after.st_ino, after.st_dev, after.st_size, after.st_mtime_ns, after.st_ctime_ns) != (
                before.st_ino, before.st_dev, before.st_size, before.st_mtime_ns, before.st_ctime_ns):
            raise GateError('RPM changed while hashing')
        if prefix != b'\xed\xab\xee\xdb':
            raise GateError('Not an RPM file')
        return digest.hexdigest(), before.st_size
    finally:
        os.close(fd)


def inspect_vt(payload, *, now=None):
    """Fail closed on missing, stale, incomplete, malicious or suspicious data."""
    now = dt.datetime.now(dt.timezone.utc).timestamp() if now is None else now
    try:
        attrs = payload['data']['attributes']
        stats = attrs['last_analysis_stats']
        malicious = int(stats['malicious'])
        suspicious = int(stats['suspicious'])
        clean = int(stats['undetected']) + int(stats['harmless'])
        last = int(attrs['last_analysis_date'])
        if malicious < 0 or suspicious < 0 or clean < 0:
            raise ValueError('negative count')
        if malicious or suspicious:
            raise GateError('At least one engine marked the RPM malicious or suspicious')
        if clean < MIN_ENGINES:
            raise GateError('Not enough engines have analyzed this RPM')
        if last > now + 300 or now - last > MAX_AGE_DAYS * 86400:
            raise GateError('VirusTotal analysis is stale')
    except (KeyError, ValueError, TypeError) as exc:
        raise GateError('Missing or invalid VirusTotal result') from exc
    return {'malicious': malicious, 'suspicious': suspicious, 'non_detections': clean,
            'analysis_at': dt.datetime.fromtimestamp(last, dt.timezone.utc).isoformat()}


def lookup_hash(digest, api_key):
    req = urllib.request.Request('https://www.virustotal.com/api/v3/files/' + digest,
                                 headers={'x-apikey': api_key, 'accept': 'application/json'}, method='GET')
    try:
        with urllib.request.urlopen(req, timeout=15) as response:
            if response.status != 200:
                raise GateError('VirusTotal response not successful')
            raw = response.read(1024 * 1024 + 1)
        if len(raw) > 1024 * 1024:
            raise GateError('VirusTotal response too large')
        return json.loads(raw)
    except (urllib.error.URLError, json.JSONDecodeError) as exc:
        raise GateError('VirusTotal unavailable or invalid response') from exc


def atomic_report(path, report):
    path = Path(path).absolute()
    if path.is_symlink():
        raise GateError('Report destination must not be a symlink')
    if not path.parent.is_dir():
        raise GateError('Report parent does not exist')
    if path.exists():
        raise GateError('Refusing to overwrite existing evidence')
    fd, tmp = tempfile.mkstemp(prefix='.vt-evidence-', dir=path.parent)
    try:
        os.fchmod(fd, 0o600)
        with os.fdopen(fd, 'w') as out:
            json.dump(report, out, ensure_ascii=False, sort_keys=True, indent=2)
            out.write('\n')
            out.flush()
            os.fsync(out.fileno())
        if path.exists():
            raise GateError('Evidence destination appeared during write')
        os.link(tmp, path, follow_symlinks=False)
        dir_fd = os.open(path.parent, os.O_RDONLY | getattr(os, 'O_DIRECTORY', 0))
        try:
            os.fsync(dir_fd)
        finally:
            os.close(dir_fd)
    finally:
        Path(tmp).unlink(missing_ok=True)


def run(rpm, report_path, *, api_key=None):
    result = {'status': 'BLOCKED', 'gate': 'VirusTotal hash lookup (not a security proof)',
              'checked_at': dt.datetime.now(dt.timezone.utc).isoformat(),
              'submission': False}
    try:
        digest, size = checked_rpm(rpm)
        result.update({'sha256': digest, 'size': size})
        if not api_key:
            raise GateError('VIRUSTOTAL_API_KEY is required for remote hash lookup')
        response = lookup_hash(digest, api_key)
        if response.get('data', {}).get('id', '').lower() != digest:
            raise GateError('VirusTotal digest mismatch')
        result['analysis'] = inspect_vt(response)
        result['status'] = 'HASH_ANALYSIS_ACCEPTED'
    except (GateError, OSError) as exc:
        result['reason'] = str(exc)[:300]
    atomic_report(report_path, result)
    return result['status'] == 'HASH_ANALYSIS_ACCEPTED'


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('rpm')
    parser.add_argument('--report', required=True)
    parser.add_argument('--submit', action='store_true', help='Unavailable: this tool never uploads files')
    parser.add_argument('--consent-third-party-sharing', action='store_true')
    args = parser.parse_args(argv)
    if args.submit:
        parser.error('RPM upload intentionally not implemented; --submit is unsupported')
    return 0 if run(args.rpm, args.report, api_key=os.environ.get('VIRUSTOTAL_API_KEY')) else 78


if __name__ == '__main__':
    raise SystemExit(main())
