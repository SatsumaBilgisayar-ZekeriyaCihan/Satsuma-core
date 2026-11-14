"""The kernel guard reads a fixed table of security settings and writes back only what was weakened.

Fake /proc/sys tree and fake systemctl; the files are real files, so the writes are real.

Çekirdek bekçisi sabit bir güvenlik tablosunu okur ve yalnızca zayıflatılanı geri yazar.
Sahte /proc/sys ağacı ve sahte systemctl; dosyalar gerçek, yani yazımlar gerçek.
"""
import json
import os
import re
from pathlib import Path
from types import SimpleNamespace

import pytest

from satsuma import kernel_guard as kg
from satsuma import memory_mounts

INTERFACES = ('all', 'default', 'lo', 'enp3s0')


@pytest.fixture
def proc(tmp_path):
    root = tmp_path / 'sys'
    for name in INTERFACES:
        (root / 'net/ipv4/conf' / name).mkdir(parents=True)
    for key, value in kg.table(root).items():
        path = root / key
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(value + '\n')
    return root


def put(root, key, value):
    (root / key).write_text(str(value) + '\n')


def get(root, key):
    return (root / key).read_text().strip()


class Systemd:
    """Just enough systemctl: show, mask, start, restart."""
    def __init__(self, **units):
        self.units = {name: dict(load='loaded', active='inactive', file='enabled') for name in kg.NEVER_RUN + kg.REQUIRED_RUNNING}
        self.units.update({n: dict(load='loaded', active='inactive', file='masked') for n in kg.NEVER_RUN})
        self.units.update({n: dict(load='loaded', active='active', file='enabled') for n in kg.REQUIRED_RUNNING})
        for name, state in units.items():
            self.units[name].update(state)
        self.calls = []

    def __call__(self, argv, **kwargs):
        if not argv[0].endswith('systemctl'):
            # The boot-entry reading (grubby --info=ALL): no installed kernel here.
            return SimpleNamespace(stdout='', returncode=0)
        self.calls.append(argv[1:])
        verb = argv[1]
        names = argv[argv.index('--') + 1:] if '--' in argv else []
        if verb == 'show':
            out = ''.join(f"Id={n}\nLoadState={self.units[n]['load']}\nActiveState={self.units[n]['active']}\n"
                          f"UnitFileState={self.units[n]['file']}\n\n" for n in names if n in self.units)
            return SimpleNamespace(stdout=out, returncode=0)
        if verb == 'mask':
            self.units[names[0]].update(active='inactive', file='masked')
        elif verb == 'start':
            self.units[names[0]]['active'] = 'active'
        return SimpleNamespace(stdout='', returncode=0)

    def verbs(self):
        return [c for c in self.calls if c[0] != 'show']


def good_mounts():
    return {'/dev': {'fstype': 'devtmpfs', 'options': {'rw', 'nosuid', 'noexec'}},
            '/dev/shm': {'fstype': 'tmpfs', 'options': {'rw', 'nosuid', 'nodev', 'noexec'}}}


def make(tmp_path, proc, systemd=None, mounts=None, pm=False, root=True, clock=None):
    now = [0.0]
    guard = kg.Guard(root=proc, runner=systemd or Systemd(), clock=clock or (lambda: now[0]), wall=lambda: 1000.0,
                     state_dir=tmp_path / 'state', mount_reader=lambda: mounts or good_mounts(),
                     pm_running=lambda: pm, can_write=root, echo=lambda *_: None)
    guard.now = now
    return guard


# --- the kernel reading ------------------------------------------------------

def test_the_table_covers_network_memory_and_ipv6_and_every_interface(proc):
    keys = kg.table(proc)
    assert keys['net/ipv4/conf/all/rp_filter'] == '1' and keys['net/ipv4/conf/enp3s0/route_localnet'] == '0'
    assert keys['kernel/yama/ptrace_scope'] == '2' and keys['kernel/kptr_restrict'] == '2'
    assert keys['net/ipv6/conf/all/disable_ipv6'] == '1' and keys['kernel/core_pattern'] == '|/usr/bin/false'


def test_a_clean_system_has_no_drift_and_the_reading_says_ok(proc):
    assert kg.drift(proc) == []
    assert all(row['ok'] for row in kg.read_settings(proc).values())


def test_ptrace_scope_other_than_two_is_drift_three_included(proc):
    # 2.2.37: 3 blinds the RAM scanner (owner's decision 2026-11-10); it is not "stronger".
    put(proc, 'kernel/yama/ptrace_scope', 3)
    assert kg.drift(proc) == [{'key': 'kernel/yama/ptrace_scope', 'expected': '2', 'actual': '3'}]
    put(proc, 'kernel/yama/ptrace_scope', 1)
    assert kg.drift(proc) == [{'key': 'kernel/yama/ptrace_scope', 'expected': '2', 'actual': '1'}]


def test_an_unreadable_setting_is_listed_not_guessed(proc):
    (proc / 'kernel/dmesg_restrict').unlink()
    rows = kg.read_settings(proc)
    assert rows['kernel/dmesg_restrict']['value'] is None and rows['kernel/dmesg_restrict']['ok'] is False
    assert kg.drift(proc) == []          # nothing to write back for a key that cannot be read


# --- writing back --------------------------------------------------------------

def test_every_weakened_setting_is_written_back_to_the_required_value(proc, tmp_path):
    for key, value in (('net/ipv4/conf/all/rp_filter', 0), ('net/ipv4/conf/enp3s0/route_localnet', 1),
                       ('kernel/kptr_restrict', 0), ('net/ipv6/conf/all/disable_ipv6', 0),
                       ('kernel/core_pattern', 'core')):
        put(proc, key, value)
    guard = make(tmp_path, proc)
    guard.cycle()
    assert kg.drift(proc) == []
    assert get(proc, 'net/ipv4/conf/enp3s0/route_localnet') == '0' and get(proc, 'kernel/core_pattern') == '|/usr/bin/false'
    assert guard.counts['settings_changed'] == 5 and guard.counts['settings_restored'] == 5


def test_nothing_outside_the_fixed_table_can_be_written(proc):
    outside = proc / 'vm/swappiness'
    outside.parent.mkdir(parents=True, exist_ok=True)
    outside.write_text('60\n')
    result = kg.restore([{'key': 'vm/swappiness', 'expected': '0', 'actual': '60'},
                         {'key': '../etc/passwd', 'expected': 'x', 'actual': 'y'},
                         {'key': 'kernel/kptr_restrict', 'expected': '0', 'actual': '2'}], proc)   # wrong value
    assert result['restored'] == [] and len(result['failed']) == 3
    assert outside.read_text() == '60\n' and get(proc, 'kernel/kptr_restrict') == '2'


def test_each_change_is_recorded_with_what_it_was_and_whether_it_was_undone(proc, tmp_path):
    put(proc, 'kernel/kptr_restrict', 0)
    guard = make(tmp_path, proc)
    guard.cycle()
    event = json.loads((tmp_path / 'state/events.jsonl').read_text().splitlines()[0])
    assert (event['kind'], event['key'], event['actual'], event['expected'], event['restored']) == (
        'kernel_setting_changed', 'kernel/kptr_restrict', '0', '2', True)
    state = json.loads((tmp_path / 'state/state.json').read_text())
    assert state['writing_back'] is True and state['counts']['settings_restored'] == 1


def test_a_setting_that_keeps_being_changed_is_recorded_but_throttled(proc, tmp_path):
    guard = make(tmp_path, proc)
    for _ in range(5):
        put(proc, 'kernel/kptr_restrict', 0)
        guard.cycle()
        guard.now[0] += 1
    assert len((tmp_path / 'state/events.jsonl').read_text().splitlines()) == 1      # once per 10 s
    assert guard.counts['settings_restored'] == 5                                    # but all undone
    guard.now[0] += 20
    put(proc, 'kernel/kptr_restrict', 0)
    guard.cycle()
    assert len((tmp_path / 'state/events.jsonl').read_text().splitlines()) == 2


def test_a_pause_file_does_not_stop_the_guard(proc, tmp_path):
    (tmp_path / 'state').mkdir()
    (tmp_path / 'state/PAUSE').write_text('')
    put(proc, 'kernel/kptr_restrict', 0)
    guard = make(tmp_path, proc)
    state = guard.cycle()
    assert get(proc, 'kernel/kptr_restrict') == '2' and state['paused'] is False


def test_without_root_it_only_reads(proc, tmp_path):
    put(proc, 'kernel/kptr_restrict', 0)
    guard = make(tmp_path, proc, root=False)
    guard.cycle()
    assert get(proc, 'kernel/kptr_restrict') == '0' and guard.counts['settings_restored'] == 0


def test_a_failed_write_is_reported_not_hidden(proc, tmp_path):
    (proc / 'kernel/kptr_restrict').write_text('0\n')
    os.chmod(proc / 'kernel/kptr_restrict', 0o444)
    guard = make(tmp_path, proc)
    if os.geteuid() == 0:
        pytest.skip('root can write read-only files')
    guard.cycle()
    assert guard.counts['restore_failed'] == 1


# --- units --------------------------------------------------------------------

def test_a_never_run_unit_that_runs_or_lost_its_mask_is_masked_and_stopped(proc, tmp_path):
    systemd = Systemd(**{'avahi-daemon.service': dict(active='active', file='enabled'),
                         'ModemManager.service': dict(file='disabled')})
    guard = make(tmp_path, proc, systemd)
    guard.cycle()
    masked = sorted(c[-1] for c in systemd.verbs() if c[0] == 'mask')
    assert masked == ['ModemManager.service', 'avahi-daemon.service']
    assert all(c[:3] == ['mask', '--now', '--no-block'] for c in systemd.verbs() if c[0] == 'mask')
    assert guard.counts['units_restored'] == 2


def test_units_that_are_already_masked_or_absent_are_left_alone(proc, tmp_path):
    systemd = Systemd(**{'tuned.service': dict(load='not-found', file='')})
    guard = make(tmp_path, proc, systemd)
    guard.cycle()
    assert systemd.verbs() == []


def test_a_required_unit_stopped_while_enabled_is_started_again(proc, tmp_path):
    systemd = Systemd(**{'satsuma-suricata-ips.service': dict(active='failed')})
    guard = make(tmp_path, proc, systemd)
    guard.cycle()
    assert systemd.verbs() == [['start', '--no-block', '--', 'satsuma-suricata-ips.service']]


def test_a_required_unit_the_operator_disabled_is_not_forced_back(proc, tmp_path):
    systemd = Systemd(**{'usbguard.service': dict(active='inactive', file='disabled')})
    guard = make(tmp_path, proc, systemd)
    guard.cycle()
    assert systemd.verbs() == []


def test_nothing_is_started_while_a_package_manager_runs(proc, tmp_path):
    systemd = Systemd(**{'satsuma-suricata-ips.service': dict(active='inactive'),
                         'avahi-daemon.service': dict(active='active', file='enabled')})
    guard = make(tmp_path, proc, systemd, pm=True)
    guard.cycle()
    assert [c[-1] for c in systemd.verbs()] == ['avahi-daemon.service']     # masking is still done; no restart


def test_a_unit_is_started_at_most_every_thirty_seconds(proc, tmp_path):
    systemd = Systemd(**{'usbguard.service': dict(active='inactive')})
    guard = make(tmp_path, proc, systemd)
    starts = []
    for step in range(8):
        systemd.units['usbguard.service']['active'] = 'inactive'
        guard.cycle()
        starts.append(len([c for c in systemd.verbs() if c[0] == 'start']))
        guard.now[0] += 10
    assert starts[-1] == 3        # t=0, 30 and 60 of the 80 s


def test_units_are_read_every_ten_seconds_not_every_second(proc, tmp_path):
    systemd = Systemd()
    guard = make(tmp_path, proc, systemd)
    for _ in range(25):
        guard.cycle()
        guard.now[0] += 1
    assert len([c for c in systemd.calls if c[0] == 'show']) == 3


def test_the_package_manager_probe_sees_a_running_rpm(tmp_path):
    proc = tmp_path / 'p'
    (proc / '10').mkdir(parents=True)
    (proc / '10/exe').symlink_to('/usr/bin/rpm')
    (proc / '11').mkdir()
    (proc / '11/exe').symlink_to('/usr/bin/bash')
    assert kg.package_manager_running(str(proc)) is True
    (proc / '10/exe').unlink()
    (proc / '10/exe').symlink_to('/usr/bin/vim')
    assert kg.package_manager_running(str(proc)) is False


# --- mounts -------------------------------------------------------------------

def test_a_lost_noexec_runs_the_boot_hardening_unit_again(proc, tmp_path):
    systemd = Systemd()
    mounts = good_mounts()
    mounts['/dev/shm']['options'].discard('noexec')
    guard = make(tmp_path, proc, systemd, mounts)
    guard.cycle()
    assert systemd.verbs() == [['restart', '--no-block', 'satsuma-memory-hardening.service']]
    event = json.loads((tmp_path / 'state/events.jsonl').read_text().splitlines()[-1])
    assert event['kind'] == 'mount_changed' and event['key'] == '/dev/shm' and event['restored'] is True


def test_healthy_mounts_cause_no_action(proc, tmp_path):
    systemd = Systemd()
    make(tmp_path, proc, systemd).cycle()
    assert systemd.verbs() == []


# --- the read-only report and the packaging -----------------------------------

def test_the_report_marks_changed_settings(proc, monkeypatch):
    put(proc, 'kernel/kptr_restrict', 0)
    text = kg.report(proc)
    assert 'kernel/kptr_restrict' in text and 'DEĞİŞMİŞ' in text and 'tamam' in text


ROOT = Path(__file__).resolve().parents[1]


def test_the_unit_runs_as_a_never_giving_up_root_loop_without_blocking_proc_sys_writes():
    text = (ROOT / 'systemd/satsuma-kernel-guard.service').read_text()
    for needle in ('Restart=always', 'StartLimitIntervalSec=0', 'User=root', 'satsuma.kernel_guard --loop',
                   'After=', 'systemd-sysctl.service', 'CAP_SYS_ADMIN', 'CAP_SYS_PTRACE', 'CAP_NET_ADMIN'):
        assert needle in text, needle
    assert not re.search(r'^ProtectKernelTunables=', text, re.M)     # it must be able to write /proc/sys
    assert 'WantedBy=sysinit.target' in text or 'WantedBy=multi-user.target' in text


def test_the_unit_is_installed_enabled_and_started_by_the_package():
    spec = (ROOT / 'packaging/satsuma-core.spec').read_text()
    assert 'satsuma-kernel-guard.service|' in spec
    assert 'systemctl enable satsuma-kernel-guard.service' in spec
    assert 'systemctl start satsuma-kernel-guard.service' in spec
    assert "'satsuma-kernel-guard.service'" in (ROOT / 'installer/service_setup.py').read_text()


def test_the_cekirdek_command_reads_without_root_and_shows_the_guard_state(proc, tmp_path, monkeypatch, capsys):
    from satsuma import admin_cli
    put(proc, 'kernel/kptr_restrict', 0)
    guard = make(tmp_path, proc)
    guard.cycle()
    monkeypatch.setattr(kg, 'PROC_SYS', proc)
    monkeypatch.setattr(kg, 'STATE_DIR', tmp_path / 'state')
    assert admin_cli._parser().parse_args(['cekirdek']).command == 'cekirdek'
    assert admin_cli.main(['cekirdek']) == 0
    out = capsys.readouterr().out
    assert 'kernel/kptr_restrict' in out and 'geri yazıyor' in out and 'geri alındı' in out
