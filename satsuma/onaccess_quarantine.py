"""Verified on-access finding handoff to existing quarantine.

The event path is *only a hint*. Never quarantine on an untrusted clamonacc
log line, a stale path or a scanner error. Re-open via descriptor; require an
independent ClamAV file scan and stable identity. This module does not consume
journald messages or enable a background worker: event transport must be
reviewed separately before this can be active in production.
"""
import os
from pathlib import Path
import stat
import time

from . import scan_quarantine
from .temporary_scan import scan_fd


def verify_and_quarantine(path, store, *, scanner=scan_fd, mover=None, protected=('/home',)):
    """Handle one untrusted on-access path; return a precise outcome.

    The caller must separately verify that a notification came from the real
    service. A pathname by itself is never treated as an infection verdict.
    """
    path = Path(path)
    if not path.is_absolute() or '..' in path.parts or '\x00' in str(path):
        return {'status': 'rejected', 'reason': 'invalid absolute path'}
    if not any(path.is_relative_to(Path(root)) for root in protected):
        return {'status': 'rejected', 'reason': 'outside on-access scope'}
    parent = fd = None
    try:
        parent, name = scan_quarantine.open_parent(path)
        fd = os.open(name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=parent)
        before = os.fstat(fd)
        if (not stat.S_ISREG(before.st_mode) or before.st_nlink != 1
                or before.st_size > scan_quarantine.MAX_FILE_BYTES):
            return {'status': 'rejected', 'reason': 'not a bounded single-link regular file'}
        result = scanner(fd)
        after = os.fstat(fd)
        keys = ('st_dev', 'st_ino', 'st_size', 'st_mtime_ns', 'st_ctime_ns')
        if any(getattr(before, k) != getattr(after, k) for k in keys):
            return {'status': 'deferred', 'reason': 'file changed during scan'}
        if not isinstance(result, dict) or result.get('status') == 'NO_MATCH_IN_FILE':
            return {'status': 'no_match'} if isinstance(result, dict) else {'status': 'deferred', 'reason': 'invalid scanner result'}
        if result.get('status') != 'SIGNATURE_MATCH' or not isinstance(result.get('signature'), str) or not result['signature']:
            return {'status': 'deferred', 'reason': 'no verified ClamAV verdict'}
        target = {'path': str(path), **scan_quarantine.fingerprint(fd)}
        # Ensure path still points to the scanned inode (fingerprint also checks content).
        latest = scan_quarantine.inspect_target(path)
        if latest != target:
            return {'status': 'deferred', 'reason': 'path identity changed'}
        signature = result['signature'][:256]
        if mover is None:
            mover = scan_quarantine.quarantine_target
        def audit(event):
            store.add('quarantine_actions', {**event, 'automatic': True,
                                             'source_engine': 'onaccess_rescan', 'timestamp': time.time()})
        moved = mover(target, audit)
        store.add('onaccess_rescan', {'timestamp': time.time(), 'path': str(path),
                                       'sha256': target['sha256'], 'signature': signature,
                                       'quarantine_status': moved.get('status')})
        return {'status': 'verified_match', 'quarantine': moved}
    except (OSError, ValueError, RuntimeError, KeyError) as exc:
        return {'status': 'deferred', 'reason': type(exc).__name__}
    finally:
        if fd is not None:
            os.close(fd)
        if parent is not None:
            os.close(parent)
