"""AIDE guard: snapshot after setup, comparison, undo only on approval.

AIDE bekçisi: kurulumdan sonra örnek, karşılaştırma, yalnızca onayla geri alma.
"""
import json
import os
from pathlib import Path
from types import SimpleNamespace

import pytest

from satsuma import aide_guard as ag

PASSWORD = 'dogru-parola'


class Store:
    def __init__(self):
        self.data, self.records = {}, []
    def get(self, key, default=None): return self.data.get(key, default)
    def set(self, key, value): self.data[key] = value
    def add(self, key, value): self.records.append((key, value))


class Aide:
    """Fake aide and rpm: --init writes a database, --check returns the queued JSON report."""
    def __init__(self, base):
        self.base, self.report, self.owned, self.verified, self.calls = Path(base), {}, {}, set(), []

    def __call__(self, argv, **kwargs):
        self.calls.append(argv)
        if argv[0] == ag.AIDE and '--init' in argv:
            (self.base / 'aide.db.new.gz').write_bytes(b'db')
            return SimpleNamespace(returncode=0, stdout='', stderr='')
        if argv[0] == ag.AIDE and '--check' in argv:
            changed = sum(1 << i for i, k in enumerate(('added', 'removed', 'changed')) if self.report.get(k))
            return SimpleNamespace(returncode=changed, stdout=json.dumps(self.report), stderr='')
        if argv[0] == ag.RPM and argv[1] == '-qf':
            name = self.owned.get(argv[-1])
            return SimpleNamespace(returncode=0 if name else 1, stdout=(name or '') + '\n', stderr='')
        if argv[0] == ag.RPM and argv[1] == '-Vf':
            line = '' if argv[-1] in self.verified else 'S.5....T.    ' + argv[-1]
            return SimpleNamespace(returncode=0 if not line else 1, stdout=line, stderr='')
        return SimpleNamespace(returncode=0, stdout='', stderr='')


@pytest.fixture
def machine(tmp_path, monkeypatch):
    etc = tmp_path / 'etc'
    (etc / 'ssh').mkdir(parents=True)
    (etc / 'resolv.conf').write_text('nameserver 127.0.0.1\n')
    (etc / 'ssh/sshd_config').write_text('PermitRootLogin no\n')
    os.chmod(etc / 'resolv.conf', 0o644)
    monkeypatch.setattr(ag, 'COPY', (str(etc / 'resolv.conf'), str(etc / 'ssh')))
    monkeypatch.setattr(ag, 'PACKAGE', ('/usr/bin',))
    base = tmp_path / 'aide'
    aide = Aide(base)
    guard = ag.Guard(Store(), base=base, runner=aide, clock=lambda: 100.0, passwd=[],
                     verifier=lambda password: password == PASSWORD)
    guard.snapshot()
    return SimpleNamespace(etc=etc, base=base, aide=aide, guard=guard)


def test_profile_config_covers_dns_ca_and_users_and_excludes_are_valid():
    user = SimpleNamespace(pw_dir='/home/zeki', pw_uid=1000)
    text = ag.aide_config(Path('/b'), passwd=[user])
    assert 'database_in=file:/b/aide.db.gz' in text and 'report_format=json' in text
    for path in ('/etc/resolv.conf', '/etc/pki/ca-trust', '/etc/ld.so.preload', '/home/zeki/.ssh/authorized_keys', '/usr/bin'):
        assert ag._rx(path) + ' SATSUMA' in text
    assert all(line.startswith('!/') for line in text.splitlines() if line.startswith('!'))


def test_snapshot_copies_configuration_and_records_digests(machine):
    record = machine.guard.store.get('aide_snapshot')
    manifest = json.loads((machine.base / 'manifest.json').read_text())
    assert record['copied_files'] == 2 and str(machine.etc / 'ssh/sshd_config') in manifest
    assert oct(os.stat(machine.base).st_mode & 0o777) == '0o700'


def test_changes_are_classified_with_their_undo_path(machine):
    added = str(machine.etc / 'ssh/authorized_keys2')
    machine.aide.report = {'changed': {str(machine.etc / 'resolv.conf'): 'S5', '/usr/bin/sudo': 'S5'},
                           'added': {added: ''}}
    machine.aide.owned = {'/usr/bin/sudo': 'sudo'}
    row = machine.guard.check()
    how = {c['path']: c['restore'] for c in row['changes']}
    assert row['status'] == 'CHANGED'
    assert how == {str(machine.etc / 'resolv.conf'): 'copy', '/usr/bin/sudo': 'package', added: 'hold'}


def test_confirmed_package_update_alone_renews_the_snapshot(machine):
    machine.aide.report = {'changed': {'/usr/bin/ls': 'S5'}}
    machine.aide.owned = {'/usr/bin/ls': 'coreutils'}
    machine.aide.verified = {'/usr/bin/ls'}
    row = machine.guard.check()
    assert row['status'] == 'CLEAN' and row['renewed_after_update'] == 1


def test_changed_snapshot_is_never_trusted(machine):
    (machine.base / 'aide.db.gz').write_bytes(b'forged')
    assert machine.guard.check()['status'] == 'SNAPSHOT_CHANGED'
    with pytest.raises(RuntimeError):
        machine.guard.restore(str(machine.etc / 'resolv.conf'), PASSWORD)


def test_undo_from_copy_needs_a_listed_change_and_an_intact_copy(machine):
    path = machine.etc / 'resolv.conf'
    with pytest.raises(RuntimeError):            # not listed: no approval possible
        machine.guard.restore(str(path), PASSWORD)
    path.write_text('nameserver 203.0.113.66\n')
    os.chmod(path, 0o666)
    machine.aide.report = {'changed': {str(path): 'S5p'}}
    machine.guard.check()
    assert machine.guard.restore(str(path), PASSWORD) == {'path': str(path), 'how': 'copy'}
    assert path.read_text() == 'nameserver 127.0.0.1\n' and os.stat(path).st_mode & 0o777 == 0o644
    assert machine.guard.store.get('aide_changes')['status'] == 'CLEAN'


def test_tampered_copy_is_refused(machine):
    path = machine.etc / 'ssh/sshd_config'
    copy = machine.base / 'files' / str(path).lstrip('/')
    machine.aide.report = {'changed': {str(path): 'S5'}}
    machine.guard.check()
    copy.write_text('PermitRootLogin yes\n')
    with pytest.raises(RuntimeError, match='Kopya değişmiş'):
        machine.guard.restore(str(path), PASSWORD)


def test_added_file_is_held_not_deleted(machine):
    added = machine.etc / 'ssh/authorized_keys2'
    added.write_text('ssh-ed25519 AAAA attacker\n')
    machine.aide.report = {'added': {str(added): ''}}
    machine.guard.check()
    machine.guard.restore(str(added), PASSWORD)
    assert not added.exists()
    held = list((machine.base / 'held').rglob('authorized_keys2'))
    assert len(held) == 1 and 'attacker' in held[0].read_text()


def test_every_undo_needs_the_admin_password_and_a_refusal_is_recorded(machine):
    path = machine.etc / 'resolv.conf'
    path.write_text('nameserver 203.0.113.66\n')
    machine.aide.report = {'changed': {str(path): 'S5'}}
    machine.guard.check()
    for wrong in ('', 'yanlis', None):
        with pytest.raises(PermissionError):
            machine.guard.restore(str(path), wrong)
    assert path.read_text() == 'nameserver 203.0.113.66\n'
    refused = [r for k, r in machine.guard.store.records if k == 'aide_restores' and r['status'] == 'password_refused']
    assert len(refused) == 3
    machine.guard.restore(str(path), PASSWORD)
    assert path.read_text() == 'nameserver 127.0.0.1\n'


@pytest.fixture
def hosts_machine(tmp_path, monkeypatch):
    hosts = tmp_path / 'hosts'
    hosts.write_text('127.0.0.1 localhost localhost.localdomain\n::1 localhost\n')
    monkeypatch.setattr(ag, 'COPY', (str(hosts),))
    monkeypatch.setattr(ag, 'PACKAGE', ())
    monkeypatch.setattr(ag, 'VALIDATED', {str(hosts): 'hosts'})
    base = tmp_path / 'aide'
    aide = Aide(base)
    guard = ag.Guard(Store(), base=base, runner=aide, clock=lambda: 1.0, passwd=[],
                     verifier=lambda password: password == PASSWORD)
    guard.snapshot()
    hosts.write_text('203.0.113.66 bank.example\n')
    aide.report = {'changed': {str(hosts): 'S5'}}
    guard.check()
    return SimpleNamespace(hosts=hosts, base=base, guard=guard)


def test_hosts_is_written_back_after_every_line_is_checked(hosts_machine):
    hosts_machine.guard.restore(str(hosts_machine.hosts), PASSWORD)
    assert hosts_machine.hosts.read_text().startswith('127.0.0.1 localhost')


def test_hosts_validator_refuses_bad_lines():
    assert ag.validate_hosts(b'# yorum\n127.0.0.1 localhost # x\n\n::1 localhost\n')
    for bad in (b'999.1.1.1 a\n', b'127.0.0.1\n', b'127.0.0.1 bad_name!\n', b'127.0.0.1 b\xc3\xa4d\n'):
        with pytest.raises(RuntimeError):
            ag.validate_hosts(bad)


def test_admin_command_asks_the_password_and_stops_on_a_wrong_one(monkeypatch, capsys):
    from satsuma import admin_cli, store as store_module
    asked, given = [], []

    class FakeGuard:
        def __init__(self, store): pass
        def restore(self, path, password):
            given.append(password)
            raise PermissionError('Satsuma yönetici parolası doğrulanmadı; geri alma yapılmadı')

    class FakeStore:
        def get(self, key, default=None):
            return {'changes': [{'path': '/etc/a', 'restore': 'copy'}, {'path': '/etc/b', 'restore': 'copy'}]}
        def close(self): pass

    monkeypatch.setattr(admin_cli.getpass, 'getpass', lambda prompt: asked.append(prompt) or 'yanlis')
    monkeypatch.setattr(ag, 'Guard', FakeGuard)
    monkeypatch.setattr(store_module, 'Store', FakeStore)
    code = admin_cli._aide(SimpleNamespace(islem='hepsini-geri-al', hedef=None))
    assert code == 1 and asked == ['Satsuma yönetici parolası: '] and given == ['yanlis']
    assert 'parolası doğrulanmadı' in capsys.readouterr().err
