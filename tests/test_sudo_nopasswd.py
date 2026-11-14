"""2.2.13: passwordless sudo is stopped at run time and reported on disk.

2.2.13: parolasız sudo çalışırken durdurulur, diskte bildirilir.
"""
from satsuma import enforcement, sudo_nopasswd
from satsuma.response_policy import authorize_destructive
from satsuma.host_store import HostStore


def test_nopasswd_lines_are_found_with_file_and_line(tmp_path):
    main = tmp_path / 'sudoers'
    main.write_text('root ALL=(ALL) ALL\n# bob ALL=(ALL) NOPASSWD: ALL\n%wheel ALL=(ALL) ALL\n')
    drop = tmp_path / 'sudoers.d'
    drop.mkdir()
    (drop / 'zz-backdoor').write_text('eve ALL=(ALL) NOPASSWD: ALL\nalice ALL=(ALL) PASSWD: /usr/bin/dnf\n')
    (drop / 'notes~').write_text('x ALL=(ALL) NOPASSWD: ALL\n')
    found = sudo_nopasswd.grants((main, drop))
    assert found == [{'file': str(drop / 'zz-backdoor'), 'line': 1, 'text': 'eve ALL=(ALL) NOPASSWD: ALL'}]


def test_grants_become_one_critical_finding(tmp_path):
    store = HostStore(tmp_path / "host", test=True)
    try:
        assert sudo_nopasswd.record(store, []) is None
        finding = sudo_nopasswd.record(store, [{'file': '/etc/sudoers.d/x', 'line': 3, 'text': 'eve ALL=(ALL) NOPASSWD: ALL'}])
        assert finding['severity'] == 'critical' and 'visudo' in finding['advice']
        assert store.db.execute('SELECT COUNT(*) FROM findings').fetchone()[0] == 1
    finally:
        store.close()


def test_sudo_n_is_stopped_only_while_the_switch_is_on():
    finding = {'rule_id': 'SATSUMA-SUDO-004', 'classification': 'indicator', 'severity': 'high'}
    assert enforcement.eligible(finding, True) and not enforcement.eligible(finding, False)
    cfg = {'response_enabled': True, 'destructive_response_enabled': True, 'destructive_allowed_actions': ['process_kill'],
           'auto_action_process_enabled': True, 'user_enforcement': True}
    context = {'automated': True, 'pid': 4242, 'user_enforcement': True}
    assert authorize_destructive('process_kill', finding, {**cfg, 'sudo_autoblock_enabled': True}, context).allowed
    denied = authorize_destructive('process_kill', finding, {**cfg, 'sudo_autoblock_enabled': False}, context)
    assert not denied.allowed and 'activity_indicator_reports_only' in denied.reasons
