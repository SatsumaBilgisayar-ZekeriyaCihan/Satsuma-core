"""A write to /etc/passwd or /etc/shadow is judged by what it changed (2.2.38).

Owner's report 2026-11-18: systemd-sysusers ("systemd-sysuser" in audit) and,
on COSMIC, the cosmic-greeter account raised critical "password changed"
alarms for every write. Bir yazma, neyi değiştirdiğine göre değerlendirilir.
"""
import shutil
import subprocess
from pathlib import Path

import pytest

from satsuma import account_change, account_guard, enforcement
from satsuma.smart_rules import SmartRuleEngine

ROOT = Path(__file__).parents[1]
PASSWD = ('root:x:0:0:root:/root:/bin/bash\n'
          'gdm:x:42:42:GDM:/var/lib/gdm:/usr/sbin/nologin\n'
          'cosmic-greeter:x:973:973:Cosmic Greeter Account:/var/lib/cosmic-greeter:/usr/sbin/nologin\n'
          'alice:x:1000:1000:Alice:/home/alice:/bin/bash\n')
SHADOW = ('root:$6$r$ROOT:20000:0:99999:7:::\n'
          'gdm:!!:20000::::::\n'
          'cosmic-greeter:!*:20000::::::\n'
          'alice:$6$a$ALICE:20000:0:99999:7:::\n')


@pytest.fixture
def files(tmp_path):
    (tmp_path / 'passwd').write_text(PASSWD)
    (tmp_path / 'shadow').write_text(SHADOW)
    tracker = account_change.Tracker(tmp_path / 'passwd', tmp_path / 'shadow', tmp_path / 'snap.json')
    assert tracker.baseline()
    return tmp_path, tracker


def edit(path, old, new):
    text = path.read_text()
    assert old in text
    path.write_text(text.replace(old, new))


def test_no_change_and_new_locked_service_accounts_are_benign(files):
    path, tracker = files
    assert tracker.check()['verdict'] == 'benign'
    (path / 'passwd').write_text(PASSWD + 'satsuma-dns:x:999:999:Satsuma DNS:/:/usr/sbin/nologin\n')
    (path / 'shadow').write_text(SHADOW + 'satsuma-dns:!*:20775::::::\n')
    result = tracker.check()
    assert result['verdict'] == 'benign'
    assert 'satsuma-dns (UID 999): hesap eklendi (kilitli, parolasız)' in result['summary']
    assert tracker.check()['changes'] == []


def test_satsumas_own_lock_is_benign(files):
    path, tracker = files
    edit(path / 'shadow', 'gdm:!!:', 'gdm:$6$x$y:')
    assert tracker.check()['verdict'] == 'critical'
    edit(path / 'shadow', 'gdm:$6$x$y:', 'gdm:!$6$x$y:')   # usermod -L
    assert tracker.check()['verdict'] == 'benign'


@pytest.mark.parametrize('field', ['$6$salt$hash', 'abJnggxhB/yJU', ''])
def test_password_on_a_system_account_is_critical(files, field):
    path, tracker = files
    edit(path / 'shadow', 'cosmic-greeter:!*:', f'cosmic-greeter:{field}:')
    result = tracker.check()
    assert result['verdict'] == 'critical'
    assert 'cosmic-greeter (UID 973): parola değişti' in result['summary']


def test_user_changing_own_password_is_a_notice(files):
    path, tracker = files
    edit(path / 'shadow', 'alice:$6$a$ALICE:', 'alice:$6$b$NEW:')
    result = tracker.check()
    assert result['verdict'] == 'notice' and 'alice (UID 1000): parola değişti' in result['summary']


def test_second_root_and_uid_zero_move_are_critical(files):
    path, tracker = files
    (path / 'passwd').write_text(PASSWD + 'toor:x:0:0::/root:/bin/bash\n')
    (path / 'shadow').write_text(SHADOW + 'toor:!:20000::::::\n')
    assert tracker.check()['verdict'] == 'critical'
    edit(path / 'passwd', 'alice:x:1000:', 'alice:x:0:')
    assert tracker.check()['verdict'] == 'critical'


def test_unreadable_files_or_missing_snapshot_are_unknown(tmp_path):
    tracker = account_change.Tracker(tmp_path / 'none', tmp_path / 'none', tmp_path / 'snap.json')
    assert tracker.check()['verdict'] == 'unknown'


def test_snapshot_keeps_fingerprints_not_hashes(files):
    path, tracker = files
    text = (path / 'snap.json').read_text()
    assert 'ALICE' not in text and '$6$' not in text
    assert oct((path / 'snap.json').stat().st_mode & 0o777) == '0o600'


def test_real_systemd_sysusers_run_is_benign(files):
    binary = shutil.which('systemd-sysusers')
    if not binary:
        pytest.skip('systemd-sysusers not installed')
    path, tracker = files
    root = path / 'root'
    (root / 'etc').mkdir(parents=True)
    for name in ('passwd', 'shadow'):
        shutil.copy(path / name, root / 'etc' / name)
    (root / 'etc/group').write_text('root:x:0:\ngdm:x:42:\ncosmic-greeter:x:973:\nalice:x:1000:\n')
    (root / 'etc/gshadow').write_text('root:::\ngdm:!::\ncosmic-greeter:!::\nalice:!::\n')
    conf = ROOT / 'packaging/root/usr/lib/sysusers.d/satsuma-core.conf'
    subprocess.run([binary, '--root=' + str(root), str(conf)], check=True, capture_output=True)
    real = account_change.Tracker(root / 'etc/passwd', root / 'etc/shadow', path / 'snap.json')
    result = real.check()
    assert result['verdict'] == 'benign', result
    assert {c['kind'] for c in result['changes']} == {'added'}


def audit_write(path, exe='/usr/bin/systemd-sysusers', comm='systemd-sysuser'):
    ext = {'host.pid': 4242, 'host.uid': '0', 'host.exe': exe, 'host.path': path,
           'host.file_path': path, 'host.operation': 'write', 'host.cmd': ''}
    return {'source': 'audit', 'kind': 'file_access', 'action': 'file_access', 'timestamp': 1, 'id': 'e1',
            'pid': 4242, 'uid': '0', 'exe': exe, 'comm': comm, 'path': path, 'file_path': path,
            'nametype': 'CREATE', 'operation': 'write', 'metadata': {'extensions': ext}}


def test_engine_reports_sysusers_write_as_low_and_never_stops_it(files):
    path, tracker = files
    engine = SmartRuleEngine(ROOT / 'rules')
    engine.account_tracker = tracker
    (path / 'passwd').write_text(PASSWD + 'satsuma-dns:x:999:999::/:/usr/sbin/nologin\n')
    (path / 'shadow').write_text(SHADOW + 'satsuma-dns:!*:20775::::::\n')
    findings = [f for f in engine.match(audit_write('/etc/shadow')) if f.get('account_change')]
    assert {f['rule_id'] for f in findings} >= {'SATSUMA-PRIV-027'}
    for finding in findings:
        assert finding['account_change']['verdict'] == 'benign'
        assert (finding['classification'], finding['severity']) == ('indicator', 'low')
        assert not enforcement.eligible(finding)
        assert finding['rule_name'].startswith('Hesap dosyası yazıldı')
        assert finding['rule_name_original'] in ('Shadow degistirme', 'Parola dosyalari')


def test_engine_keeps_a_real_password_change_critical_and_stoppable(files):
    path, tracker = files
    engine = SmartRuleEngine(ROOT / 'rules')
    engine.account_tracker = tracker
    edit(path / 'shadow', 'cosmic-greeter:!*:', 'cosmic-greeter:$6$s$h:')
    findings = {f['rule_id']: f for f in engine.match(audit_write('/etc/shadow', '/usr/bin/bash', 'bash'))}
    priv = findings['SATSUMA-PRIV-027']
    assert priv['account_change']['verdict'] == 'critical'
    assert (priv['classification'], priv['severity']) == ('suspicious', 'critical')
    assert enforcement.eligible(priv)
    assert 'cosmic-greeter' in priv['summary']
    # Both rules of the same event share one comparison.
    assert findings['SATSUMA-COLL-015']['account_change']['verdict'] == 'critical'


def test_identity_team_no_longer_matches_backup_files_or_duplicates_passwd():
    from satsuma.teams.identity_team.rules import sensitive
    assert sensitive('/etc/sudoers') and sensitive('/root/.ssh/authorized_keys')
    assert not sensitive('/etc/passwd-') and not sensitive('/etc/sudoers.bak') and not sensitive('/root/.sshx')
    assert not sensitive('/etc/shadow')


# account_guard gaps closed in 2.2.38
GUARD_PASSWD = ('root:x:0:0:root:/root:/bin/bash\n'
                'toor:x:0:0:second root:/root:/bin/bash\n'
                'gdm:x:42:42:GDM:/var/lib/gdm:/usr/sbin/nologin\n'
                'bos:x:990:990::/:/bin/bash\n'
                'des:x:991:991::/:/usr/sbin/nologin\n'
                'locked:x:992:992::/:/usr/sbin/nologin\n'
                'nobody:x:65534:65534::/:/usr/sbin/nologin\n'
                'dyn:x:61200:61200::/:/usr/sbin/nologin\n'
                'alice:x:1000:1000::/home/alice:/bin/bash\n')
GUARD_SHADOW = ('root:$6$a$b:::::::\ntoor:!:::::::\ngdm:!!:::::::\nbos::::::::\n'
                'des:abJnggxhB/yJU:::::::\nlocked:!$6$x$y:::::::\nnobody:$6$n$n:::::::\n'
                'dyn:$6$d$d:::::::\nalice:$6$u$u:::::::\n')


def test_account_guard_finds_empty_des_second_root_and_high_system_uids(tmp_path):
    (tmp_path / 'passwd').write_text(GUARD_PASSWD)
    (tmp_path / 'shadow').write_text(GUARD_SHADOW)
    found = {e['name']: e for e in account_guard.find(tmp_path / 'passwd', tmp_path / 'shadow')}
    assert set(found) == {'toor', 'bos', 'des', 'nobody', 'dyn'}
    assert found['bos']['empty_password'] and found['toor']['second_root']
    assert not account_guard.usable('!$6$x$y') and not account_guard.usable('*') and not account_guard.usable(None)
