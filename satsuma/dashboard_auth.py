# -*- coding: utf-8 -*-
"""Local dashboard administrator authentication.

Runtime credential file: ``/etc/satsuma-core/admin.hash``.  It is deliberately
not part of the source tree or Debian package.  The file contains only a
salted PBKDF2-HMAC-SHA256 digest; plaintext passwords are never stored or
logged.

Session tokens are generated with :mod:`secrets`, expire after a bounded
timeout, and are invalidated explicitly on logout.
"""
from __future__ import annotations

import hashlib
import hmac
import os
import secrets
import stat
import time
import uuid
from collections import defaultdict, deque
from pathlib import Path

ADMIN_HASH_PATH = Path('/etc/satsuma-core/admin.hash')
SESSION_TTL_SECONDS = 30 * 60
MAX_ATTEMPTS = 5
LOCKOUT_SECONDS = 5 * 60
PBKDF2_ITERATIONS = 600_000
HASH_SCHEME = 'pbkdf2_sha256'


def hash_password(password: str, *, iterations: int = PBKDF2_ITERATIONS, salt: str | None = None) -> str:
    """Return a portable salted PBKDF2-SHA256 credential string."""
    if not isinstance(password, str) or not password:
        raise ValueError('password must be a non-empty string')
    if iterations < 100_000:
        raise ValueError('iterations too low')
    salt = salt or secrets.token_hex(16)
    digest = hashlib.pbkdf2_hmac(
        'sha256', password.encode('utf-8'), bytes.fromhex(salt), iterations
    )
    return f'{HASH_SCHEME}${iterations}${salt}${digest.hex()}'


def parse_password_hash(encoded: str):
    """Parse ``pbkdf2_sha256$iterations$salt$digest``; return None on error."""
    if not isinstance(encoded, str):
        return None
    parts = encoded.strip().split('$')
    if len(parts) != 4 or parts[0] != HASH_SCHEME:
        return None
    try:
        iterations = int(parts[1])
        salt = parts[2]
        digest = parts[3]
        if iterations < 1 or not salt or not digest:
            return None
        bytes.fromhex(salt)
        bytes.fromhex(digest)
    except (ValueError, TypeError):
        return None
    return iterations, salt, digest


def verify_password(password: str, encoded: str) -> bool:
    """Constant-time password verification; never raises for bad hash data."""
    parsed = parse_password_hash(encoded)
    if parsed is None or not isinstance(password, str):
        # Still perform a dummy PBKDF2 to reduce user-enumeration timing.
        try:
            hashlib.pbkdf2_hmac('sha256', b'', b'0' * 16, PBKDF2_ITERATIONS, dklen=32)
        except Exception:
            pass
        return False
    iterations, salt, expected = parsed
    try:
        actual = hashlib.pbkdf2_hmac(
            'sha256', password.encode('utf-8'), bytes.fromhex(salt), iterations, dklen=len(bytes.fromhex(expected))
        ).hex()
    except (ValueError, TypeError):
        return False
    return hmac.compare_digest(actual, expected)


def _secure_parent_fd(path: Path, *, create: bool = False):
    """Open the credential parent without following symlinks."""
    parent = path.parent
    if create:
        try:
            parent.mkdir(mode=0o700, parents=True)
        except FileExistsError:
            pass
    fd = os.open(parent, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        info = os.fstat(fd)
        if not stat.S_ISDIR(info.st_mode) or info.st_uid != 0 or info.st_mode & 0o022:
            raise PermissionError('credential directory must be root-owned and not group/other writable')
        return fd
    except BaseException:
        os.close(fd)
        raise


def _require_root():
    if os.geteuid() != 0:
        raise PermissionError('root privileges are required to modify admin credentials')


def read_admin_hash(path: str | Path = ADMIN_HASH_PATH) -> str | None:
    """Read the runtime admin hash through a strict no-follow regular file.

    New credentials are root:root 0600. Legacy root-owned 0640 files remain
    accepted for existing installations; the GUI never reads this file.
    Any failure returns ``None`` so authentication fails closed.
    """
    source = Path(path)
    try:
        fd = os.open(source, os.O_RDONLY | os.O_NOFOLLOW)
    except OSError:
        return None
    try:
        info = os.fstat(fd)
        if not stat.S_ISREG(info.st_mode):
            return None
        # root sahipli, tek hardlink olmalı
        if info.st_uid != 0 or info.st_nlink != 1:
            return None
        # other: hiçbir izin yok
        if info.st_mode & 0o007:
            return None
        # group: yalnızca read (040) kabul edilir, write/execute yasak
        if (info.st_mode & 0o070) not in (0, 0o040):
            return None
        with os.fdopen(os.dup(fd), encoding='utf-8') as stream:
            text = stream.read().strip()
        return text or None
    except (OSError, UnicodeDecodeError):
        return None
    finally:
        os.close(fd)


def admin_hash_status(path: str | Path = ADMIN_HASH_PATH) -> dict:
    """Return non-secret status for the runtime admin credential."""
    source = Path(path)
    status = {'configured': False, 'path': str(source), 'error': None}
    try:
        encoded = read_admin_hash(source)
    except Exception as exc:  # noqa: BLE001
        status['error'] = type(exc).__name__
        return status
    if encoded is None:
        if source.is_symlink():
            status['error'] = 'symlink_rejected'
        elif not source.exists():
            status['error'] = 'missing'
        else:
            status['error'] = 'unsafe_file'
        return status
    if parse_password_hash(encoded) is None:
        status['error'] = 'malformed_hash'
        return status
    status['configured'] = True
    return status


def write_admin_hash(encoded: str, path: str | Path = ADMIN_HASH_PATH) -> None:
    """Atomically write a PBKDF2 admin credential with root:root 0600.

    The write is symlink-safe: the parent directory is opened with
    ``O_NOFOLLOW`` and the final file is replaced by rename.  Existing regular
    credentials are preserved on upgrade until explicitly replaced.
    """
    _require_root()
    if parse_password_hash(encoded) is None:
        raise ValueError('invalid PBKDF2 admin hash')
    target = Path(path)
    if target.is_symlink():
        raise PermissionError('refusing to replace symlinked admin.hash')
    parent_fd = _secure_parent_fd(target, create=True)
    temporary = '.admin.hash-' + uuid.uuid4().hex
    try:
        fd = os.open(
            temporary,
            os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW,
            0o600,
            dir_fd=parent_fd,
        )
        try:
            os.fchmod(fd, 0o600)
            os.fchown(fd, 0, 0)
            with os.fdopen(os.dup(fd), 'w', encoding='utf-8') as stream:
                stream.write(encoded.strip() + '\n')
                stream.flush()
                os.fsync(stream.fileno())
        finally:
            os.close(fd)
        os.replace(temporary, target.name, src_dir_fd=parent_fd, dst_dir_fd=parent_fd)
        os.fsync(parent_fd)
    finally:
        try:
            os.unlink(temporary, dir_fd=parent_fd)
        except FileNotFoundError:
            pass
        os.close(parent_fd)


def remove_admin_hash(path: str | Path = ADMIN_HASH_PATH) -> bool:
    """Safely remove the runtime admin credential; missing is not an error."""
    _require_root()
    target = Path(path)
    parent_fd = _secure_parent_fd(target, create=False)
    try:
        try:
            info = os.stat(target.name, dir_fd=parent_fd, follow_symlinks=False)
        except FileNotFoundError:
            return False
        if stat.S_ISDIR(info.st_mode):
            raise IsADirectoryError(str(target))
        os.unlink(target.name, dir_fd=parent_fd)
        os.fsync(parent_fd)
        return True
    finally:
        os.close(parent_fd)


def verify_admin_password(password: str, path: str | Path = ADMIN_HASH_PATH) -> bool:
    encoded = read_admin_hash(path)
    if not encoded:
        return False
    return verify_password(password, encoded)


class AuthManager:
    """Rate-limited, session-based local admin auth manager."""

    def __init__(
        self,
        *,
        hash_path: str | Path = ADMIN_HASH_PATH,
        session_ttl: int = SESSION_TTL_SECONDS,
        max_attempts: int = MAX_ATTEMPTS,
        lockout_seconds: int = LOCKOUT_SECONDS,
        clock=time.monotonic,
    ):
        self.hash_path = Path(hash_path)
        self.session_ttl = int(session_ttl)
        self.max_attempts = int(max_attempts)
        self.lockout_seconds = int(lockout_seconds)
        self.clock = clock
        self._sessions: dict[str, float] = {}
        self._failures: dict[str, deque] = defaultdict(deque)

    # -- session lifecycle -------------------------------------------------
    def _prune(self):
        now = self.clock()
        expired = [token for token, expiry in self._sessions.items() if expiry <= now]
        for token in expired:
            self._sessions.pop(token, None)
        for key in list(self._failures):
            failures = self._failures[key]
            while failures and now - failures[0] > self.lockout_seconds:
                failures.popleft()
            if not failures:
                self._failures.pop(key, None)

    def _is_locked(self, client: str) -> bool:
        self._prune()
        failures = self._failures.get(client)
        if not failures:
            return False
        return len(failures) >= self.max_attempts and (self.clock() - failures[-1]) < self.lockout_seconds

    def login(self, password: str, client: str = 'local') -> dict:
        self._prune()
        client = str(client or 'local')
        if self._is_locked(client):
            return {'ok': False, 'error': 'rate_limited', 'retry_after': self.lockout_seconds}
        if not self.hash_path.exists():
            return {'ok': False, 'error': 'admin_hash_missing'}
        if not verify_admin_password(password, self.hash_path):
            self._failures[client].append(self.clock())
            return {'ok': False, 'error': 'invalid_credentials'}
        token = secrets.token_urlsafe(32)
        expires = self.clock() + self.session_ttl
        self._sessions[token] = expires
        self._failures.pop(client, None)
        return {'ok': True, 'token': token, 'expires_at': expires}

    def logout(self, token: str) -> bool:
        return self._sessions.pop(str(token or ''), None) is not None

    def validate_session(self, token: str) -> bool:
        self._prune()
        expiry = self._sessions.get(str(token or ''))
        return bool(expiry and expiry > self.clock())

    def session_info(self, token: str) -> dict:
        self._prune()
        expiry = self._sessions.get(str(token or ''))
        if not expiry or expiry <= self.clock():
            return {'valid': False}
        return {'valid': True, 'expires_in': max(0, int(expiry - self.clock()))}
