from types import SimpleNamespace as NS
import pytest
from installer import desktop_setup as desktop


def test_auto_enrollment_only_selects_active_local_graphical_users():
    def run(args,**kw):
        if 'list-sessions' in args:return NS(stdout='1 1000 user seat0\n2 1001 other\n3 0 root\n')
        ident=args[2]
        return NS(stdout={'1':'Name=user\nUser=1000\nActive=yes\nRemote=no\nType=wayland\nClass=user',
                          '2':'Name=other\nUser=1001\nActive=yes\nRemote=yes\nType=tty\nClass=user',
                          '3':'Name=root\nUser=0\nActive=yes\nRemote=no\nType=x11\nClass=user'}[ident])
    assert desktop.active_desktop_users(run)==['user']


def test_first_password_cannot_overwrite_existing_credential(monkeypatch):
    from installer import boot_setup
    from satsuma import dashboard_auth as auth
    import grp
    monkeypatch.setattr(desktop.pwd,'getpwnam',lambda user:NS(pw_uid=1000,pw_gid=1000,pw_shell='/bin/bash'))
    monkeypatch.setattr(grp,'getgrnam',lambda group:NS(gr_gid=1000,gr_mem=['user']))
    monkeypatch.setattr(boot_setup,'provision',lambda:None)
    monkeypatch.delenv('PKEXEC_UID',raising=False)
    monkeypatch.setattr(auth,'admin_hash_status',lambda:{'configured':True})
    monkeypatch.setattr(auth,'write_admin_hash',lambda *a:pytest.fail('must preserve existing credential'))
    with pytest.raises(ValueError,match='already configured'):desktop.configure('user','fixture-password')


def test_enrollment_rejects_mismatched_pkexec_caller(monkeypatch):
    monkeypatch.setattr(desktop.pwd,'getpwnam',lambda user:NS(pw_uid=1000,pw_shell='/bin/bash'))
    monkeypatch.setenv('PKEXEC_UID','1001')
    with pytest.raises(PermissionError):desktop.configure('user')
