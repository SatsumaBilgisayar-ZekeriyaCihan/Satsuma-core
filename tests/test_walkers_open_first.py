"""Folder walkers open first and create only what is missing (2.2.43).

Owner's report 2026-11-18: an audit record "mkdirat ... success=no exit=-17"
(EEXIST) on /etc from a Satsuma service, raised for every existing step.
Var olan klasörde mkdir çağrılmaz; eksik olan yine oluşturulur.
"""
import os
import shutil
import tempfile
from pathlib import Path

import pytest

from installer import remote_containment
from satsuma import browser_policy, protected_storage


def no_mkdir(*args, **kwargs):
    raise AssertionError('mkdir called for an existing folder: ' + repr(args))


def test_existing_paths_never_call_mkdir(monkeypatch):
    monkeypatch.setattr(os, 'mkdir', no_mkdir)
    remote_containment.secure_directory(Path('/usr/lib'))
    os.close(protected_storage.open_directory(Path('/usr/lib')))
    fd = browser_policy._trusted_parent('/', 'usr/lib/x')
    os.close(fd if isinstance(fd, int) else fd[0])


def test_a_missing_folder_is_still_created_with_its_mode():
    if os.geteuid() != 0:
        pytest.skip('needs root-owned parents')
    top = Path(tempfile.mkdtemp(prefix='satsuma-walk-', dir='/'))
    os.chmod(top, 0o755)
    try:
        remote_containment.secure_directory(top / 'a' / 'b')
        assert oct((top / 'a' / 'b').stat().st_mode & 0o777) == '0o700'
        os.close(protected_storage.open_directory(top / 'c'))
        assert oct((top / 'c').stat().st_mode & 0o777) == '0o700'
    finally:
        shutil.rmtree(top)
