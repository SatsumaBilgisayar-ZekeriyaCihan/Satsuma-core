"""Fedora Atomic links (/opt -> var/opt, /home -> var/home ...) in the integrity walk (2.2.39).

Owner's report 2026-11-18 from Fedora Atomic: "Kurulum bütünlüğü:
NotADirectoryError: [Errno 20] Not a directory: 'opt'" and every Satsuma
service down. A link is followed only when root alone could have placed it.
Atomic bağları yalnızca root koyabildiyse izlenir; diğer her bağ reddedilir.
"""
import os
import shutil
import tempfile
from pathlib import Path

import pytest

from installer import integrity
from satsuma import scan_quarantine


@pytest.fixture
def atomic():
    """A root-owned tree laid out like a Fedora Atomic deployment."""
    if os.geteuid() != 0:
        pytest.skip('needs root: the links must be root-owned')
    top = Path(tempfile.mkdtemp(prefix='satsuma-atomic-', dir='/'))
    os.chmod(top, 0o755)
    for folder in ('var/opt/satsuma-core', 'var/home/user/Downloads', 'var/usrlocal/bin', 'usr'):
        (top / folder).mkdir(parents=True)
        os.chmod(top / folder, 0o755)
    os.chmod(top / 'var/home/user', 0o700)
    (top / 'var/opt/satsuma-core/main.py').write_text('print("satsuma")\n')
    (top / 'var/home/user/Downloads/x.bin').write_text('payload')
    os.symlink('var/opt', top / 'opt')                    # relative, as on Atomic
    os.symlink(str(top / 'var/home'), top / 'home')        # absolute
    os.symlink('../var/usrlocal', top / 'usr/local')       # relative with ..
    yield top
    shutil.rmtree(top)


def test_integrity_reads_through_the_atomic_opt_link(atomic):
    raw, info = integrity.safe_read(atomic / 'opt/satsuma-core/main.py')
    assert raw == b'print("satsuma")\n' and info.st_uid == 0


def test_absolute_and_dotdot_links_are_followed(atomic):
    (atomic / 'var/usrlocal/bin/tool').write_text('t')
    assert integrity.safe_read(atomic / 'usr/local/bin/tool')[0] == b't'
    fd, name = integrity.open_parent(atomic / 'home/user/Downloads/x.bin', ownership=False)
    try:
        assert name == 'x.bin' and os.read(os.open(name, os.O_RDONLY, dir_fd=fd), 10) == b'payload'
    finally:
        os.close(fd)


def test_a_link_in_a_folder_others_can_write_is_refused(atomic):
    shared = atomic / 'shared'
    shared.mkdir()
    os.chmod(shared, 0o777)
    os.symlink(str(atomic / 'var/opt'), shared / 'opt')
    with pytest.raises(OSError):
        integrity.safe_read(shared / 'opt/satsuma-core/main.py', ownership=False)


def test_a_link_owned_by_another_user_is_refused(atomic):
    os.symlink('var/opt', atomic / 'opt2')
    os.lchown(atomic / 'opt2', 65534, 65534)
    with pytest.raises(OSError):
        integrity.safe_read(atomic / 'opt2/satsuma-core/main.py', ownership=False)


def test_the_file_itself_is_never_a_link(atomic):
    os.symlink('main.py', atomic / 'var/opt/satsuma-core/alias.py')
    with pytest.raises(OSError):
        integrity.safe_read(atomic / 'opt/satsuma-core/alias.py')


def test_a_link_loop_ends(atomic):
    os.symlink('loop', atomic / 'loop')
    with pytest.raises(OSError):
        integrity.safe_read(atomic / 'loop/x', ownership=False)


def test_ownership_is_still_enforced_after_a_link(atomic):
    os.chmod(atomic / 'var/opt', 0o777)
    with pytest.raises(PermissionError):
        integrity.safe_read(atomic / 'opt/satsuma-core/main.py')


def test_quarantine_opens_files_under_atomic_home_and_accepts_var_roots(atomic):
    fd, name = scan_quarantine.open_parent(atomic / 'home/user/Downloads/x.bin')
    os.close(fd)
    assert name == 'x.bin'
    assert Path('/var/home') in scan_quarantine.ALLOWED_ROOTS
    assert Path('/var/usrlocal/bin') in scan_quarantine.SYSTEM_ROOTS
