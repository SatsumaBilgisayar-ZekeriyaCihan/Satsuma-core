"""No name and no unit keeps a matched process alive (owner, 2026-11-13).

Code a remote-support peer sends through TeamViewer or AnyDesk, or malware
hiding inside sshd, the journal or Satsuma itself, is stopped like any other
process. Only PID 1 (the kernel refuses) and the caller itself are never
signalled; PID 1 raises a critical alarm instead of a silent record.

Hiçbir ad ya da birim kurala takılan süreci yaşatmaz (sahibi, 2026-11-13).
Yalnızca PID 1 (çekirdek izin vermez) ve çağıranın kendisi sinyal almaz;
PID 1 sessiz kayıt yerine kritik alarm üretir.
"""
import os
from unittest.mock import patch

from satsuma import auto_process, enforcement, process_identity


def live(name, cgroup='/system.slice/x.service'):
    return [patch.object(process_identity, 'read_proc_starttime', return_value=777),
            patch.object(process_identity, 'read_proc_exe', return_value=name),
            patch.object(process_identity, 'read_proc_comm', return_value=os.path.basename(name)),
            patch.object(process_identity, 'read_proc_cmdline', return_value=name),
            patch.object(process_identity, 'read_proc_cgroup', return_value=cgroup)]


def verify(name, cgroup='/system.slice/x.service'):
    patches = live(name, cgroup)
    for p in patches:
        p.start()
    try:
        return process_identity.verify_process_identity(4242, {'pid': 4242, 'starttime': 777, 'exe': name})
    finally:
        for p in patches:
            p.stop()


def test_formerly_protected_names_can_be_stopped():
    for name in ('/usr/sbin/sshd', '/usr/lib/systemd/systemd-journald', '/usr/lib/systemd/systemd-logind',
                 '/usr/bin/dbus-daemon', '/usr/lib/systemd/systemd', '/opt/teamviewer/tv_bin/teamviewerd',
                 '/usr/bin/anydesk'):
        result = verify(name)
        assert result['ok'] is True, (name, result)


def test_a_satsuma_process_can_be_stopped():
    result = verify('/usr/bin/python3', '/system.slice/satsuma-teams.service')
    assert result['ok'] is True, result


def test_pid_one_and_the_caller_are_never_targets():
    assert process_identity.verify_process_identity(1, {})['reason'] == 'protected_pid'
    assert process_identity.verify_process_identity(os.getpid(), {})['reason'] == 'self_pid'


class Store:
    def __init__(self):
        self.rows = {'findings': [], 'actions': []}
        self.state = {}

    def add(self, kind, row):
        self.rows.setdefault(kind, []).append(row)

    def get(self, key, default=None):
        return self.state.get(key, default)

    def set(self, key, value):
        self.state[key] = value


def test_pid_one_matching_a_rule_is_a_critical_alarm_not_a_silent_record():
    store = Store()
    finding = {'finding_id': 'f1', 'rule_id': 'SATSUMA-RAM-001', 'classification': 'indicator',
               'severity': 'medium', 'event': {'pid': 1, 'exe': '/usr/lib/systemd/systemd',
                                               'timestamp': 0, 'source': 'memory'}}
    with patch('satsuma.process_followup.decision', lambda *a, **k: None):
        record = auto_process.respond(store, {'user_enforcement': True}, finding, response=None)
    assert record['status'] == 'exempt' and record['exemption'] == 'init_cannot_be_stopped'
    alarm = store.rows['findings'][-1]
    assert alarm['severity'] == 'critical' and alarm['automatic_action'] == 'init_cannot_be_stopped'
    assert 'PID 1' in alarm['title']


def test_every_ram_detection_is_an_attack_indicator_that_stops():
    # 2.2.38: no RAM rule only records. Hiçbir RAM kuralı yalnızca kaydetmez.
    import yaml
    from pathlib import Path
    rules = []
    for name in ('ram_defense.yaml', 'memory_injection.yaml', 'memory_integrity.yaml'):
        rules += [r for r in yaml.safe_load((Path(__file__).resolve().parents[1] / 'rules' / name).read_text())
                  if str(r.get('id', '')).startswith('SATSUMA-RAM')]
    assert len(rules) == 7
    for rule in rules:
        finding = {'rule_id': rule['id'], 'classification': rule['classification'], 'severity': rule['severity']}
        assert enforcement.eligible(finding) and enforcement.automatic_allowed(finding), rule['id']


