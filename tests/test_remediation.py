"""2.2.56: undoing one-shot attacks (owner decision 2026-11-19, scope "everything")."""
import os
from pathlib import Path
from types import SimpleNamespace as NS

import pytest

from satsuma import remediation as r


def finding(rule, cmd='', path=''):
    return {'rule_id': rule, 'finding_id': 'f1', 'event': {'cmd': cmd, 'file_path': path, 'path': path}}


def test_plans():
    assert r.plan(finding('SATSUMA-LNX-EVAS-002', 'nft flush ruleset'))[0]['action'] == 'restore_firewall'
    assert r.plan(finding('SATSUMA-PERS-001', path='/etc/cron.d/x')) == [
        {'rule_id': 'SATSUMA-PERS-001', 'finding_id': 'f1', 'action': 'quarantine_file', 'path': '/etc/cron.d/x'}]
    assert r.plan(finding('SATSUMA-GAP-016', 'useradd -o -u 0 -g 0 sysbk'))[0] == {
        'rule_id': 'SATSUMA-GAP-016', 'finding_id': 'f1', 'action': 'lock_account', 'user': 'sysbk'}
    assert r.plan(finding('SATSUMA-GAP-017', 'usermod -aG wheel helper'))[0]['user'] == 'helper'
    assert r.plan(finding('SATSUMA-GAP-017', 'gpasswd -a helper wheel'))[0]['group'] == 'wheel'
    assert r.plan({**finding('SATSUMA-PRIV-017', 'modprobe x'), 'trace_only': True}) == []
    assert r.plan(finding('SATSUMA-GAP-001', 'python3 -c ...')) == []


@pytest.mark.parametrize('path', ['/etc/cron.d/x', '/etc/systemd/system/evil.service',
                                  '/etc/systemd/system/multi-user.target.wants/evil.service',
                                  '/var/home/u/.ssh/authorized_keys', '/var/home/u/.config/autostart/x.desktop',
                                  '/var/roothome/.bashrc', '/etc/ld.so.preload', '/etc/udev/rules.d/99-x.rules',
                                  '/var/spool/cron/u', '/etc/sudoers.d/99-x'])
def test_persistence_files_may_be_quarantined(path):
    assert r.allowed({'action': 'quarantine_file', 'path': path}, real=lambda p: p) == (True, '')


@pytest.mark.parametrize('path', ['/etc/passwd', '/etc/shadow', '/etc/sudoers', '/etc/pam.d/system-auth',
                                  '/etc/profile', '/etc/crontab', '/etc/selinux/config', '/etc/satsuma-core/policy.json',
                                  '/etc/systemd/system/satsuma-core.service',
                                  '/etc/systemd/system/multi-user.target.wants/satsuma-teams.service',
                                  '/etc/xdg/autostart/satsuma-notify.desktop', '/usr/bin/bash', '/var/home/u/Belgeler/x',
                                  '/etc/../etc/passwd', 'etc/cron.d/x'])
def test_protected_or_foreign_paths_are_refused(path):
    ok, _ = r.allowed({'action': 'quarantine_file', 'path': path}, real=lambda p: p)
    assert not ok


def test_accounts_root_owner_and_satsuma_are_never_touched():
    for user in ('root', 'satsuma-core', 'owner'):
        ok, reason = r.allowed({'action': 'lock_account', 'user': user}, owners={'owner'})
        assert not ok and reason == 'protected_account'
    assert r.allowed({'action': 'remove_from_group', 'user': 'nobody', 'group': 'docker'})[1] == 'bad_group'


def test_execute_locks_and_records(monkeypatch):
    calls = []
    monkeypatch.setattr(r, 'allowed', lambda action, owners=(): (True, ''))
    monkeypatch.setattr(r, '_owners', lambda store=None: set())
    runner = lambda args, **kw: calls.append(args) or NS(returncode=0, stderr='')
    out = r.execute({'action': 'lock_account', 'user': 'sysbk', 'rule_id': 'SATSUMA-GAP-016'}, runner=runner)
    assert calls == [['/usr/sbin/usermod', '-L', '-e', '1', 'sysbk']] and out['status'] == 'locked'
    assert out['action'] == 'remediation.lock_account' and 'usermod -U' in out['undo']
    calls.clear()
    out = r.execute({'action': 'restore_firewall'}, runner=runner)
    assert calls == [['/usr/bin/systemctl', 'start', '--no-block', 'satsuma-firewall-watch.service']]


def test_refused_action_is_not_run():
    out = r.execute({'action': 'quarantine_file', 'path': '/etc/passwd'}, runner=lambda *a, **k: 1 / 0)
    assert out['status'] == 'refused' and out['reason'] == 'protected_path'


def test_link_is_removed_and_restorable(tmp_path, monkeypatch):
    link = tmp_path / 'evil.service'
    link.symlink_to('/tmp/evil.service')
    records = []
    out = r._quarantine_file(str(link), records.append, runner=lambda *a, **k: NS(returncode=0, stderr=''))
    assert not link.exists() and not link.is_symlink() and out['status'] == 'link_removed'
    assert 'ln -s' in out['restore_hint']


def test_teams_remediates_only_while_policy_is_on():
    import run_satsuma_teams as T

    class Store(dict):
        def get(self, k, d=None): return super().get(k, d)
        def add(self, kind, body): self.setdefault('_added', []).append((kind, body))
    sent = []
    store = Store()
    fresh = [finding('SATSUMA-LNX-EVAS-002', 'nft flush ruleset')]
    assert T._remediate(store, fresh, request=lambda **p: sent.append(p) or {'status': 'requested'}) == 1
    assert sent[0]['action'] == 'restore_firewall'
    store['remediation_policy'] = {'enabled': False}
    assert T._remediate(store, fresh, request=lambda **p: 1 / 0) == 0


def test_privd_accepts_the_remediate_operation():
    from satsuma import privd
    message = privd.validate({'op': 'remediate', 'action': 'quarantine_file', 'path': '/etc/cron.d/x', 'reason': 'x'})
    assert message['action'] == 'quarantine_file'
    with pytest.raises(ValueError):
        privd.validate({'op': 'remediate', 'action': 'quarantine_file', 'path': ['x'], 'reason': 'x'})


def test_authorized_keys_keep_confirmed_keys(tmp_path, monkeypatch):
    import base64
    from satsuma import ssh_keys, scan_quarantine
    monkeypatch.setattr(scan_quarantine, 'QUARANTINE', tmp_path / 'q')
    blob = lambda n: base64.b64encode(b'\x00\x00\x00\x0bssh-ed25519' + bytes([n]) * 40).decode()
    own, evil = blob(1), blob(2)
    keys = tmp_path / 'authorized_keys'
    keys.write_text(f'ssh-ed25519 {own} me@pc\nssh-ed25519 {evil} attacker\n')
    known = {ssh_keys.fingerprint(own)}
    records = []
    out = r._quarantine_file(str(keys), records.append, runner=None, known_keys=known)
    # quarantine_authorized writes into the default quarantine dir; redirect it for the test
    assert out['status'] == 'keys_quarantined' and len(out['keys']) == 1
    assert own in keys.read_text() and evil not in keys.read_text()


def test_package_manager_writes_are_not_undone():
    f = finding('SATSUMA-PERS-002', path='/etc/systemd/system/x.service')
    f['event']['exe'] = '/usr/bin/rpm-ostree'
    assert r.plan(f) == []


def test_admin_switch_off_needs_the_password(monkeypatch, tmp_path):
    from satsuma import admin_cli, dashboard_auth, store as S
    saved = {}

    class Fake:
        db = None
        def get(self, k, d=None): return saved.get(k, d)
        def set(self, k, v): saved[k] = v
        def add(self, *a): pass
        def close(self): pass
    monkeypatch.setattr(S, 'Store', Fake)
    monkeypatch.setattr(admin_cli.getpass, 'getpass', lambda prompt='': 'wrong')
    monkeypatch.setattr(dashboard_auth, 'verify_admin_password', lambda p: p == 'right')
    assert admin_cli._remediation(NS(islem='kapat')) == 1 and 'remediation_policy' not in saved
    monkeypatch.setattr(admin_cli.getpass, 'getpass', lambda prompt='': 'right')
    assert admin_cli._remediation(NS(islem='kapat')) == 0 and saved['remediation_policy']['enabled'] is False
    assert admin_cli._remediation(NS(islem='ac')) == 0 and saved['remediation_policy']['enabled'] is True


def test_unreachable_privd_raises_a_critical_finding_hourly(monkeypatch):
    import run_satsuma_teams as T
    import satsuma.finding_store as fs
    found = []
    monkeypatch.setattr(fs, 'record_finding', lambda store, finding, source: found.append(finding) or {'written': True})

    class Store(dict):
        def get(self, k, d=None): return super().get(k, d)
        def set(self, k, v): self[k] = v
        def add(self, kind, body): pass
    store = Store()
    fresh = [finding('SATSUMA-PERS-001', path='/etc/cron.d/x')]
    T._remediate(store, fresh, request=lambda **p: None)
    T._remediate(store, fresh, request=lambda **p: None)
    assert len(found) == 1 and found[0]['rule_id'] == 'SATSUMA-PRIVD-001' and found[0]['severity'] == 'critical'
