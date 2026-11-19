"""2.2.56: kernel guard restores and SELinux at run time."""
import json
import os

from satsuma import kernel_guard as kg
from satsuma import kernel_guard_findings as kf


class Store(dict):
    def __init__(self):
        super().__init__()
        import sqlite3
        self.db = sqlite3.connect(':memory:')
        self.added = []

    def get(self, k, d=None):
        return super().get(k, d)

    def set(self, k, v):
        self[k] = v

    def add(self, kind, body):
        self.added.append((kind, body))


def test_guard_events_become_findings_after_the_first_read(tmp_path):
    path = tmp_path / 'events.jsonl'
    path.write_text(json.dumps({'kind': 'kernel_setting_changed', 'key': 'kernel/unprivileged_bpf_disabled'}) + '\n')
    store = Store()
    assert kf.collect(store, path) == []          # history at install time is not news
    with open(path, 'a') as s:
        s.write(json.dumps({'kind': 'selinux_permissive', 'key': 'selinux/enforce', 'actual': '0',
                            'restored': True, 'time': 5}) + '\n')
        s.write('{"kind": "selinux_perm')   # half-written line waits
    found = kf.collect(store, path)
    assert [f['rule_id'] for f in found] == ['SATSUMA-KGUARD-SELINUX_PERMISSIVE']
    assert found[0]['severity'] == 'critical' and found[0]['enforcement_eligible'] is False
    assert kf.collect(store, path) == []


def test_unrestored_medium_event_is_raised_to_high():
    f = kf.to_finding({'kind': 'unit_changed', 'key': 'satsuma-teams.service', 'restored': False, 'reason': 'x'})
    assert f['severity'] == 'high' and 'Geri alınamadı' in f['advice']
    assert kf.to_finding({'kind': 'something_else'}) is None


def _guard(tmp_path, enforce, config='SELINUX=enforcing\n', cmdline='BOOT_IMAGE=x quiet'):
    (tmp_path / 'enforce').write_text(enforce)
    (tmp_path / 'config').write_text(config)
    (tmp_path / 'cmdline').write_text(cmdline)
    g = kg.Guard.__new__(kg.Guard)
    g.selinux_paths = {k: str(tmp_path / k) for k in ('enforce', 'config', 'cmdline')}
    g.selinux_wanted = None
    g.can_write = True
    g.paused = lambda: False
    g.counts = {'settings_changed': 0, 'settings_restored': 0, 'restore_failed': 0}
    g.emitted = []
    g.emit = lambda kind, key, **f: g.emitted.append((kind, f))
    return g


def test_selinux_is_put_back_to_enforcing(tmp_path):
    g = _guard(tmp_path, '0')
    assert g.check_selinux() == '1' and (tmp_path / 'enforce').read_text() == '1'
    assert g.emitted[0][0] == 'selinux_permissive' and g.emitted[0][1]['restored'] is True


def test_deliberate_permissive_boot_is_left_alone(tmp_path):
    for config, cmdline in (('SELINUX=permissive\n', 'x'), ('SELINUX=enforcing\n', 'x enforcing=0')):
        g = _guard(tmp_path, '0', config, cmdline)
        assert g.check_selinux() == '0' and (tmp_path / 'enforce').read_text() == '0' and not g.emitted


def test_io_uring_is_off_in_the_profile():
    from satsuma import kernel_profile as kp
    assert kp.STRICT['kernel/io_uring_disabled'] == '2'
    assert kp.acceptable('kernel/io_uring_disabled', '2', '2') and not kp.acceptable('kernel/io_uring_disabled', '1', '2')
