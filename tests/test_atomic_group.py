"""Desktop enrollment on Fedora Atomic, where package groups live in /usr/lib/group (2.2.41).

Owner's report 2026-11-18: the panel asked for a password and closed.
Atomic'te paket grupları /usr/lib/group'tadır; usermod yalnızca /etc/group'u düzenler.
"""
from pathlib import Path

from installer import boot_setup


def files(tmp_path, etc='root:x:0:\nwheel:x:10:alice\n', lib='satsuma-reader:x:961:\nsatsuma-core:x:962:\n'):
    paths = {'etc_group': tmp_path / 'group', 'etc_gshadow': tmp_path / 'gshadow',
             'lib_group': tmp_path / 'lib-group', 'lock': tmp_path / '.pwd.lock'}
    paths['etc_group'].write_text(etc)
    paths['etc_gshadow'].write_text('root:::\nwheel:::alice\n')
    paths['lib_group'].write_text(lib)
    return {k: str(v) for k, v in paths.items()}


def test_group_only_in_usr_lib_is_copied_to_etc(tmp_path):
    paths = files(tmp_path)
    inode = Path(paths['etc_group']).stat().st_ino
    assert boot_setup.ensure_local_group('satsuma-reader', **paths) == 'copied'
    assert Path(paths['etc_group']).read_text().endswith('satsuma-reader:x:961:\n')
    assert Path(paths['etc_gshadow']).read_text().endswith('satsuma-reader:!::\n')
    assert Path(paths['etc_group']).stat().st_ino == inode          # edited in place: label kept
    assert boot_setup.ensure_local_group('satsuma-reader', **paths) == 'present'
    assert Path(paths['etc_group']).read_text().count('satsuma-reader:') == 1


def test_group_already_in_etc_or_nowhere_is_left_alone(tmp_path):
    paths = files(tmp_path, etc='satsuma-reader:x:961:bob\n')
    assert boot_setup.ensure_local_group('satsuma-reader', **paths) == 'present'
    paths = files(tmp_path, lib='other:x:5:\n')
    assert boot_setup.ensure_local_group('satsuma-reader', **paths) == 'absent'
    assert 'satsuma-reader' not in Path(paths['etc_group']).read_text()


def test_missing_final_newline_does_not_merge_lines(tmp_path):
    paths = files(tmp_path, etc='root:x:0:')
    boot_setup.ensure_local_group('satsuma-reader', **paths)
    assert Path(paths['etc_group']).read_text().splitlines() == ['root:x:0:', 'satsuma-reader:x:961:']


def test_enrollment_copies_the_group_before_usermod(monkeypatch):
    order = []
    monkeypatch.setattr(boot_setup, 'provision', lambda: order.append('verify'))
    monkeypatch.setattr(boot_setup, 'ensure_local_group', lambda name: order.append('group:' + name))
    import pwd
    monkeypatch.setattr(pwd, 'getpwnam', lambda user: type('A', (), {'pw_uid': 1000})())
    boot_setup.enroll_user('alice', runner=lambda args, **kw: order.append(args[0]))
    assert order == ['verify', 'group:satsuma-reader', '/usr/sbin/usermod', 'verify']


def test_launcher_shows_why_it_could_not_open():
    text = (Path(__file__).parents[1] / 'packaging/root/usr/bin/satsuma-dashboard').read_text()
    assert 'show_error' in text and 'status=$?' in text
    assert "126) reason=" in text and "127) reason=" in text
