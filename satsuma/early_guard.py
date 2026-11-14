"""Automatic application verification; no host-wide baseline or interactive enrollment."""
import json
import math
import os
from pathlib import Path
import stat
import tempfile
import time

VERDICT = Path('/run/satsuma-boot/verdict.json')
MAX_AGE = 900
MAX_BYTES = 1024 * 1024


def current_boot_id():
    return Path('/proc/sys/kernel/random/boot_id').read_text().strip()


def run_guard(verifier=None, paths=(), boot_id=None, config_checker=None, memory_checker=None,
              memory_access_checker=None):
    production = verifier is None
    if verifier is None:
        from .self_guard import verify
        verifier = verify
    checks = {}
    failures = []
    try:
        checks['application'] = {'ok': True, 'files': verifier()}
    except Exception as exc:
        code=getattr(exc,'code','INTEGRITY_CHECK_FAILED')
        checks['application'] = {'ok': False, 'status':code, 'error': str(exc)[:2000]}
        failures.append({'code': code, 'detail': str(exc)[:2000]})
    missing = [str(p) for p in paths if not Path(p).exists()]
    checks['critical_paths'] = {'ok': not missing, 'missing': missing}
    if missing:
        failures.append({'code': 'APPLICATION_PATH_MISSING', 'paths': missing})
    # File verification never parses operator policy. Keep both results visible
    # and refuse active response when either prerequisite fails.
    if production or config_checker is not None:
        if config_checker is None:
            from .config import load_with_policy
            config_checker = load_with_policy
        try:
            loaded=config_checker()
            meta=loaded[1] if isinstance(loaded,tuple) and len(loaded)>1 else {}
            fallback=meta.get('status')=='last_valid'
            checks['configuration'] = {'ok': True, 'status': 'LAST_VALID' if fallback else 'VALIDATED',
                                       'fallback_active':fallback,'detail':meta}
        except Exception as exc:
            code = getattr(exc, 'code', 'CONFIG_UNSUPPORTED')
            checks['configuration'] = {'ok': False, 'status': code, 'error': str(exc)[:2000]}
            failures.append({'code': code, 'detail': str(exc)[:2000]})
    if production or memory_checker is not None:
        if memory_checker is None:
            from .memory_mounts import check
            memory_checker = check
        try:
            checks['memory_mounts'] = memory_checker()
            if checks['memory_mounts'].get('ok') is not True:
                failures.append({'code': 'MEMORY_MOUNTS_UNSAFE', 'detail': checks['memory_mounts']})
        except Exception as exc:
            checks['memory_mounts'] = {'ok': False, 'error': str(exc)[:300]}
            failures.append({'code': 'MEMORY_MOUNT_CHECK_FAILED', 'detail': str(exc)[:300]})
    if production or memory_access_checker is not None:
        if memory_access_checker is None:
            from .memory_access import check
            memory_access_checker = check
        try:
            checks['memory_access'] = memory_access_checker()
            if checks['memory_access'].get('ok') is not True:
                failures.append({'code': 'MEMORY_ACCESS_UNSAFE', 'detail': checks['memory_access']})
        except Exception as exc:
            checks['memory_access'] = {'ok': False, 'error': str(exc)[:300]}
            failures.append({'code': 'MEMORY_ACCESS_CHECK_FAILED', 'detail': str(exc)[:300]})
    ok = not failures
    state = ('FULL_CHECKED' if ok else
             checks['configuration']['status'] if checks.get('application', {}).get('ok')
             and checks.get('configuration', {}).get('ok') is False else 'FAILED')
    return {'schema': 2, 'host_cleanliness_verified': False,
            'reference_scope': 'satsuma_package_files', 'boot_id': boot_id or current_boot_id(),
            'generated_at': time.time(), 'generated_monotonic': time.monotonic(),
            'state': state, 'mode': 'APPLICATION_MANIFEST',
            'response_unlocked': ok, 'checks': checks,
            'failure_reasons': failures, 'warning_reasons': []}


def write_verdict(payload, path=VERDICT):
    from .protected_storage import open_directory
    directory = open_directory(path.parent)
    try:
        fd, temp = tempfile.mkstemp(prefix='.verdict-', dir=path.parent)
        try:
            with os.fdopen(fd, 'w') as stream:
                json.dump(payload, stream); stream.flush(); os.fsync(stream.fileno())
            os.chmod(temp, 0o600)
            os.replace(temp, path)
            os.fsync(directory)
        finally:
            if os.path.exists(temp): os.unlink(temp)
    finally:
        os.close(directory)


def read_verdict(path=VERDICT):
    try:
        fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
        with os.fdopen(fd, 'rb') as stream:
            info = os.fstat(stream.fileno())
            if not stat.S_ISREG(info.st_mode) or info.st_uid != 0 or info.st_mode & 0o077 or info.st_nlink != 1:
                raise PermissionError('Unsafe boot verdict')
            raw = stream.read(MAX_BYTES + 1)
        if len(raw) > MAX_BYTES: raise ValueError('Oversized verdict')
        result = json.loads(raw)
        if not isinstance(result, dict) or result.get('schema') != 2:
            raise ValueError('Unsupported verdict schema')
        stamp = result.get('generated_monotonic')
        if (type(stamp) not in (int, float) or not math.isfinite(stamp)
                or not 0 <= time.monotonic() - stamp <= MAX_AGE
                or result.get('boot_id') != current_boot_id()):
            return {'state': 'STALE', 'response_unlocked': False}
        checks = result.get('checks', {})
        result['response_unlocked'] = (result.get('response_unlocked') is True
            and result.get('state') == 'FULL_CHECKED'
            and checks.get('configuration', {}).get('ok') is True
            and checks.get('memory_mounts', {}).get('ok') is True
            and checks.get('memory_access', {}).get('ok') is True
            and all(checks.get(k, {}).get('ok') is True for k in ('application', 'critical_paths')))
        return result
    except Exception as exc:
        return {'state': 'UNKNOWN', 'response_unlocked': False, 'error': str(exc)[:300]}


def main():
    if os.geteuid() != 0: raise PermissionError('Early guard requires root')
    result = run_guard()
    write_verdict(result)
    print(json.dumps(result))
    return 0 if result['response_unlocked'] else 1


if __name__ == '__main__': raise SystemExit(main())
