"""2.2.15: SSH keys are audited read-only.

2.2.15: SSH anahtarları salt okunur denetlenir.
"""
import base64
import hashlib
import json

from satsuma import ssh_keys
from satsuma.host_store import HostStore

BLOB = base64.b64encode(b'\x00\x00\x00\x0bssh-ed25519' + b'\x01' * 36).decode()
BLOB2 = base64.b64encode(b'\x00\x00\x00\x0bssh-ed25519' + b'\x02' * 36).decode()


def _openssh_key(cipher):
    raw = b'openssh-key-v1\x00' + len(cipher).to_bytes(4, 'big') + cipher + b'\x00' * 32
    body = base64.b64encode(raw).decode()
    return f'-----BEGIN OPENSSH PRIVATE KEY-----\n{body}\n-----END OPENSSH PRIVATE KEY-----\n'.encode()


def test_fingerprint_matches_ssh_keygen_format():
    expected = 'SHA256:' + base64.b64encode(hashlib.sha256(base64.b64decode(BLOB)).digest()).decode().rstrip('=')
    keys = ssh_keys.parse_authorized(f'# comment\ncommand="/bin/x",no-pty ssh-ed25519 {BLOB} eve@laptop\nbroken line\n')
    assert keys[0]['fingerprint'] == expected and keys[0]['options'] == 'command="/bin/x",no-pty'
    assert keys[0]['comment'] == 'eve@laptop' and keys[1]['error']


def test_passphrase_is_detected():
    assert ssh_keys.private_key_encrypted(_openssh_key(b'none')) is False
    assert ssh_keys.private_key_encrypted(_openssh_key(b'aes256-ctr')) is True
    assert ssh_keys.private_key_encrypted(b'-----BEGIN RSA PRIVATE KEY-----\nProc-Type: 4,ENCRYPTED\n') is True


def _home(tmp_path, keys):
    home = tmp_path / 'home' / 'satsuma'
    (home / '.ssh').mkdir(parents=True)
    (home / '.ssh').chmod(0o700)
    (home / '.ssh' / 'authorized_keys').write_text(keys)
    (home / '.ssh' / 'authorized_keys').chmod(0o600)
    (home / '.ssh' / 'id_ed25519').write_bytes(_openssh_key(b'none'))
    (home / 'Belgeler').mkdir()
    (home / 'Belgeler' / 'yedek_anahtar').write_bytes(_openssh_key(b'aes256-ctr'))
    return home


def test_every_unconfirmed_key_is_a_question_and_nothing_changes_by_itself(tmp_path):
    home = _home(tmp_path, f'ssh-ed25519 {BLOB} me@desk\n')
    store = HostStore(tmp_path / 'host', test=True)
    sshd = {'is-active': 'inactive', 'is-enabled': 'disabled', 'authorizedkeysfile': '.ssh/authorized_keys'}
    args = dict(homes=[('satsuma', home)], extra_authorized=(), sshd=sshd)
    try:
        first = ssh_keys.run(store, **args)
        kinds = sorted(p['kind'] for p in first['pending'])
        assert kinds == ['authorized', 'private', 'private'] and first['new_keys'] == []
        asks = [json.loads(b) for (b,) in store.db.execute("SELECT body FROM findings WHERE finding_id LIKE 'SATSUMA-SSH-ASK:%'")]
        authorized = next(a for a in asks if a['key']['kind'] == 'authorized')
        assert authorized['severity'] == 'high' and 'bilginiz dahilinde' in authorized['title']
        assert 'ssh karantina' in authorized['advice'] and 'ssh tanidik' in authorized['advice']
        (home / '.ssh' / 'authorized_keys').write_text(f'ssh-ed25519 {BLOB} me@desk\nssh-ed25519 {BLOB2} intruder\n')
        second = ssh_keys.run(store, **args)
        assert len(second['new_keys']) == 1
        fp = next(p['fingerprint'] for p in second['pending'] if p['kind'] == 'authorized' and p['comment'] == 'me@desk')
        ssh_keys.mark_known(store, fp)
        third = ssh_keys.run(store, **args)
        assert fp not in [p['id'] for p in third['pending']]
    finally:
        store.close()
    assert (home / '.ssh' / 'authorized_keys').read_text().count('ssh-ed25519') == 2  # never edited by the scan


def test_quarantine_takes_out_only_that_line_and_can_be_undone(tmp_path):
    from satsuma import scan_quarantine
    home = _home(tmp_path, f'# my keys\nssh-ed25519 {BLOB} me@desk\nssh-ed25519 {BLOB2} intruder\n')
    keys = home / '.ssh' / 'authorized_keys'
    intruder = ssh_keys.parse_authorized(f'ssh-ed25519 {BLOB2} intruder')[0]['fingerprint']
    audit = []
    result = ssh_keys.quarantine_authorized(keys, intruder, audit.append, directory=tmp_path / 'q')
    assert keys.read_text() == f'# my keys\nssh-ed25519 {BLOB} me@desk\n'
    assert oct(keys.stat().st_mode & 0o777) == '0o600' and result['lines_removed'] == 1
    rows = scan_quarantine.list_quarantine(tmp_path / 'q', tmp_path / 'pending')
    assert rows[0]['quarantine_id'] == result['quarantine_id'] and intruder in rows[0]['path']
    scan_quarantine.restore_target(result['quarantine_id'], audit.append, directory=tmp_path / 'q', pending=tmp_path / 'p')
    assert keys.read_text().endswith(f'ssh-ed25519 {BLOB2} intruder\n') and keys.read_text().count('ssh-ed25519') == 2
    import pytest
    with pytest.raises(ValueError):
        ssh_keys.quarantine_authorized(keys, 'SHA256:none', audit.append, directory=tmp_path / 'q')
    with pytest.raises(ValueError):
        ssh_keys.quarantine_authorized(home / 'Belgeler' / 'yedek_anahtar', intruder, audit.append, directory=tmp_path / 'q')


def test_sshd_can_be_switched_off_on_request():
    calls = []
    result = ssh_keys.disable_sshd(lambda args, **k: calls.append(args) or type('R', (), {'returncode': 0, 'stderr': ''})())
    assert calls == [['systemctl', 'disable', '--now', 'sshd.service'], ['systemctl', 'disable', '--now', 'sshd.socket']]
    assert result['units'] == {'sshd.service': 'ok', 'sshd.socket': 'ok'}


def test_writable_ssh_files_and_open_sshd_are_reported(tmp_path):
    home = _home(tmp_path, f'ssh-ed25519 {BLOB} me@desk\n')
    (home / '.ssh' / 'authorized_keys').chmod(0o666)
    store = HostStore(tmp_path / 'host', test=True)
    sshd = {'is-active': 'active', 'is-enabled': 'enabled', 'authorizedkeysfile': '/tmp/keys'}
    try:
        state = ssh_keys.run(store, homes=[('satsuma', home)], extra_authorized=(), sshd=sshd)
        assert state['permissions'] == [str(home / '.ssh' / 'authorized_keys')]
        rules = {json.loads(b)['rule_id'] for (b,) in store.db.execute('SELECT body FROM findings')}
        assert {'SATSUMA-SSH-PERM', 'SATSUMA-SSH-SSHD', 'SATSUMA-SSH-KEYFILE'} <= rules
        assert state['sshd_open'] is True
    finally:
        store.close()


def test_sshd_config_first_value_wins(tmp_path):
    config = tmp_path / 'sshd_config'
    config.write_text('# PermitRootLogin yes\nPermitRootLogin no\nPermitRootLogin yes\nPasswordAuthentication no\n')
    state = ssh_keys.sshd_state(config, runner=lambda *a, **k: type('R', (), {'stdout': 'inactive\n'})())
    assert state['permitrootlogin'] == 'no' and state['passwordauthentication'] == 'no'
    assert state['is-active'] == 'inactive'


def test_login_users_only():
    rows = [('root', 0, '/root', '/bin/bash'), ('satsuma', 1000, '/home/satsuma', '/bin/bash'),
            ('daemon', 2, '/sbin', '/sbin/nologin'), ('ghost', 1001, '/home/ghost', '/usr/sbin/nologin')]
    assert [u for u, _ in ssh_keys.login_homes(rows)] == ['root', 'satsuma']


def test_dashboard_decides_only_on_keys_the_last_audit_asked_about(tmp_path, monkeypatch):
    import pytest
    from satsuma.operator_service import OperatorController
    from satsuma.store import Store
    from satsuma import host_store, ssh_keys
    class Auth:
        def login(self, *a, **k): return {'ok': True, 'token': 't'}
        def validate_session(self, *a): return True
    asked = {'kind': 'authorized', 'id': 'SHA256:abc', 'file': '/home/u/.ssh/authorized_keys', 'fingerprint': 'SHA256:abc'}
    known = []
    class FakeHost:
        def __init__(self, *a, **k): pass
        def get(self, key, default=None): return {'pending': [asked]} if key == 'ssh_keys' else default
        def close(self): pass
    monkeypatch.setattr(host_store, 'HostStore', FakeHost)
    monkeypatch.setattr(ssh_keys, 'mark_known', lambda host, ident: known.append(ident) or {'status': 'known', 'id': ident})
    taken = []
    monkeypatch.setattr(ssh_keys, 'quarantine_authorized', lambda path, fp, audit: taken.append((path, fp)) or
                        {'status': 'quarantined', 'quarantine_id': 'q'})
    store = Store(tmp_path / 'data', test=True)
    try:
        controller = OperatorController(store, auth=Auth(), boot_provider=lambda: {})
        controller.dispatch(1000, 'login', {})
        base = {'token': 't', 'id': asked['id'], 'file': asked['file']}
        with pytest.raises(ValueError, match='onay'):
            controller.dispatch(1000, 'ssh_key_decision', {**base, 'decision': 'quarantine'})
        with pytest.raises(ValueError, match='onay bekleyenler'):
            controller.dispatch(1000, 'ssh_key_decision', {**base, 'file': '/etc/passwd', 'decision': 'quarantine',
                                                           'confirmed': True})
        assert not taken and not known
        controller.dispatch(1000, 'ssh_key_decision', {**base, 'decision': 'quarantine', 'confirmed': True})
        controller.dispatch(1000, 'ssh_key_decision', {**base, 'decision': 'known', 'confirmed': True})
        assert taken == [(asked['file'], 'SHA256:abc')] and known == ['SHA256:abc']
    finally:
        store.close()
