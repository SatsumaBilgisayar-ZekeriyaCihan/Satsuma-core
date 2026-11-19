"""Ten-minute, descriptor-bound ClamAV scan of temporary directories.

Regular single-link files only; symlinks/devices are never followed. Quarantine
uses the existing fingerprint-checked path and does not enable restoration.
Budgets and inaccessible/changed files are reported, never called clean.
Files are submitted by descriptor to the system Unix-socket ClamAV daemon.
The retired RAM clamd is never used.

Geçici dizinlerin on dakikada bir, tanımlayıcıya bağlı ClamAV taraması.
Yalnızca tek bağlantılı normal dosyalar; sembolik bağ ve aygıt izlenmez.
Karantina mevcut parmak izi kontrollü yolu kullanır. Bütçe, erişilemeyen ya da
değişen dosyalar raporlanır, hiçbir zaman temiz sayılmaz. Dosyalar sistem ClamAV Unix soketine dosya tanımlayıcısıyla gönderilir.
RAM clamd kullanılmaz.
"""
import fcntl
import hashlib
import json
import os
from pathlib import Path
import stat
import time



def _system_clamd_config(path=Path('/etc/clamd.d/scan.conf')):
    """Require a local Unix socket. Never silently fall back to TCP/INSTREAM."""
    import stat as _stat
    path = Path(path)
    info = path.lstat()
    if not _stat.S_ISREG(info.st_mode) or info.st_uid != 0 or info.st_mode & 0o022:
        raise PermissionError('Untrusted system clamd configuration')
    values = {}
    for line in path.read_text(errors='strict').splitlines():
        line = line.strip()
        if not line or line.startswith('#'):
            continue
        parts = line.split(None, 1)
        if len(parts) == 2:
            values.setdefault(parts[0], []).append(parts[1].strip())
    sockets = values.get('LocalSocket', [])
    if len(sockets) != 1 or values.get('TCPSocket') or values.get('TCPAddr'):
        raise RuntimeError('File scanner requires exactly one local Unix socket and no TCP listener')
    # A duplicate socket directive can make the scanner and daemon disagree
    # about the endpoint. Never reuse the retired process-memory scanner.
    socket_path = Path(sockets[0])
    if (not socket_path.is_absolute() or '..' in socket_path.parts
            or str(socket_path).startswith('/run/satsuma-ram-clamd/')):
        raise RuntimeError('Unsafe system ClamAV socket path')
    return path


def scan_fd(fd, *, client=None, timeout=10):
    """Scan a file descriptor through system clamd; never send process RAM.

    clamdscan uses FILDES for stdin with --fdpass over the local Unix socket.
    Exit code 2, nonstandard output and timeouts are errors, not clean scans.
    """
    import re
    import subprocess
    if client is not None:
        return client(fd)
    config = _system_clamd_config()
    # fd was opened with O_NOFOLLOW and validated by run_once.
    # Duplicate to avoid modifying the offset of the caller's descriptor.
    source = os.dup(fd)
    try:
        os.lseek(source, 0, os.SEEK_SET)
        result = subprocess.run(
            ['/usr/bin/clamdscan', '--config-file=' + str(config),
             '--fdpass', '--no-summary', '-'], stdin=source,
            capture_output=True, timeout=timeout, check=False)
    except subprocess.TimeoutExpired as exc:
        raise TimeoutError('System ClamAV file scan timed out') from exc
    finally:
        os.close(source)
    if result.returncode == 0 and b'OK' in result.stdout:
        return {'status': 'NO_MATCH_IN_FILE'}
    if result.returncode == 1:
        matches = re.findall(rb'(?m)^.+?: ([^\r\n\x00-\x1f\x7f]{1,256}) FOUND$', result.stdout)
        if len(matches) == 1:
            return {'status': 'SIGNATURE_MATCH', 'signature': matches[0].decode('utf-8', 'replace')}
    raise RuntimeError('ClamAV file scan failed or returned unrecognized verdict')


from . import scan_quarantine as quarantine

TARGETS = (Path('/tmp'), Path('/var/tmp'), Path('/dev/shm'))
MAX_FILES = 10000
MAX_SECONDS = 120


def candidates(roots, onerror):
    for root in roots:
        if not root.exists():
            onerror(FileNotFoundError(str(root)))
            continue
        root_info = root.lstat()
        if not stat.S_ISDIR(root_info.st_mode) or root_info.st_uid != 0:
            raise PermissionError('Unsafe temporary scan root')
        for directory, dirs, files in os.walk(root, followlinks=False, onerror=onerror):
            # Enumerate without following links. Scanned files are opened
            # again descriptor-by-descriptor with open_parent/O_NOFOLLOW.
            if len(Path(directory).relative_to(root).parts) >= 16:
                if dirs:onerror(RuntimeError('Temporary tree depth limit reached'))
                dirs.clear()
            for name in files:
                yield Path(directory) / name


def run_once(store, *, roots=TARGETS, scanner=scan_fd, automatic=True, clock=time.monotonic):
    started = clock()
    store.set('temporary_scan_health', {'status':'RUNNING','updated_at':time.time(),'interval_seconds':600})
    previous = int(store.get('temporary_scan.cursor', 0) or 0)
    consumed = 0
    scanned = errors = skipped = matched = quarantined = 0
    partial = False
    # Round-robin offset prevents every budget-limited run restarting at the
    # first directory. A changing tree is not a consistent whole-tree snapshot.
    traversal_errors=[]
    for path in candidates(roots, traversal_errors.append):
        consumed += 1
        if clock() - started >= MAX_SECONDS:
            partial = True
            break
        if consumed <= previous:
            continue
        if scanned + skipped + errors >= MAX_FILES:
            partial = True
            break
        parent = fd = None
        scanning=False
        try:
            parent, name = quarantine.open_parent(path)
            fd = os.open(name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=parent)
            before = os.fstat(fd)
            if (not stat.S_ISREG(before.st_mode) or before.st_nlink != 1
                    or before.st_size > quarantine.MAX_FILE_BYTES):
                skipped += 1
                continue
            scanning=True
            answer = scanner(fd)
            scanning=False
            after = os.fstat(fd)
            if (before.st_dev, before.st_ino, before.st_size, before.st_mtime_ns, before.st_ctime_ns) != (
                    after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns, after.st_ctime_ns):
                raise RuntimeError('File changed during scanning')
            scanned += 1
            if answer.get('status') == 'NO_MATCH_IN_FILE':
                continue
            if answer.get('status') != 'SIGNATURE_MATCH':
                skipped += 1
                continue
            matched += 1
            target = {'path': str(path), **quarantine.fingerprint(fd)}
            stable=os.fstat(fd)
            if (before.st_size,before.st_mtime_ns,before.st_ctime_ns)!=(stable.st_size,stable.st_mtime_ns,stable.st_ctime_ns):
                raise RuntimeError('File changed before quarantine authorization')
            record = {'timestamp': time.time(), 'path': str(path), 'signature': answer['signature'],
                      'sha256': target['sha256'], 'status': 'REVIEW', 'automatic': automatic}
            if automatic:
                result = quarantine.quarantine_target(target, lambda r: store.add('quarantine_actions', r))
                record['quarantine'] = result
                if result.get('status') == 'quarantined':
                    quarantined += 1
                    record['status'] = 'QUARANTINED'
            store.add('temporary_scan_detection', record)
            ident = 'temporary-av:' + hashlib.sha256((str(path) + target['sha256']).encode()).hexdigest()
            finding = {**record, 'finding_id': ident, 'severity': 'high', 'classification': 'suspicious',
                       'rule_id': 'SATSUMA-SCAN-TEMP', 'title': 'Geçici dosyada ClamAV imza eşleşmesi'}
            store.db.execute('INSERT OR REPLACE INTO findings(finding_id,last_seen,body) VALUES(?,?,?)',
                             (ident, time.time(), json.dumps(finding)))
            store.db.commit()
        except (OSError, ValueError, RuntimeError, KeyError) as exc:
            errors += 1
            store.add('temporary_scan_error', {'timestamp': time.time(), 'path': str(path),
                                              'error': type(exc).__name__, 'reason': str(exc)[:200],
                                              'errno': getattr(exc, 'errno', None)})
            # A missing daemon is a run failure, not a negative scan of 10000
            # files. Other file-specific failures remain isolated.
            if scanning:
                partial=True
                break
            if isinstance(exc, FileNotFoundError) and not path.exists():
                pass
            elif isinstance(exc, (ConnectionError, TimeoutError)):
                partial = True
                break
        finally:
            if fd is not None: os.close(fd)
            if parent is not None: os.close(parent)
    errors+=len(traversal_errors)
    store.set('temporary_scan.cursor', max(previous, consumed - 1) if partial else 0)
    health = {'updated_at': time.time(), 'interval_seconds': 600, 'targets': [str(p) for p in roots],
              'scanned': scanned, 'errors': errors, 'skipped': skipped, 'matches': matched,
              'quarantined': quarantined, 'partial': partial or bool(errors or skipped),
              'status': 'FINDINGS' if matched else 'DEGRADED' if errors or skipped or partial else 'COMPLETED',
              'scope': 'temporary regular files; no clean-machine guarantee'}
    store.set('temporary_scan_health', health)
    return health


def main():
    from .host_store import HostStore
    from .config import load_with_policy
    config, _, _ = load_with_policy()
    selected = config['scheduled_scans']
    store = HostStore()
    try:
        if not selected['enabled']:
            store.set('temporary_scan_health', {'status': 'DISABLED', 'updated_at': time.time()})
            return
        from .protected_storage import open_directory
        parent = open_directory(Path('/var/lib/satsuma-core/host'))
        try:
            lock = os.open('temporary-scan.lock', os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW, 0o600, dir_fd=parent)
        finally:
            os.close(parent)
        try:
            info = os.fstat(lock)
            if not stat.S_ISREG(info.st_mode) or info.st_uid != 0 or info.st_nlink != 1 or info.st_mode & 0o077:
                raise PermissionError('Unsafe temporary scan lock')
            fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
            run_once(store, automatic=selected['automatic_quarantine'])
        finally:
            os.close(lock)
    finally:
        store.close()


if __name__ == '__main__':
    os.umask(0o077)
    main()
