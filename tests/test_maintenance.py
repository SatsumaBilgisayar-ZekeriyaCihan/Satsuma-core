"""Maintenance kit (2.2.38): the whole product checked, safe things repaired.

Owner's request 2026-11-18. Bakım kiti: ürünün tamamı denetlenir, güvenli olan onarılır.
"""
import json
import os
import re
import subprocess
from pathlib import Path
from types import SimpleNamespace as NS

import pytest

from satsuma import maintenance

ROOT = Path(__file__).parents[1]
SPEC = (ROOT / 'packaging/satsuma-core.spec').read_text()


class Systemd:
    """A fake systemctl: unit -> props; start/restart/enable change them."""

    def __init__(self, units):
        self.units = {name: {'ActiveState': 'active', 'UnitFileState': 'enabled', 'Type': 'simple',
                             'RemainAfterExit': 'no', 'Result': 'success', 'LoadState': 'loaded', **props}
                      for name, props in units.items()}
        self.calls = []
        self.broken = set()

    def __call__(self, argv, **kwargs):
        self.calls.append(list(argv))
        if argv[0] != maintenance.SYSTEMCTL:
            return NS(returncode=0, stdout='', stderr='')
        verb, *rest = argv[1:]
        if verb == 'show':
            props = self.units.get(rest[0], {})
            return NS(returncode=0 if props else 1, stdout=''.join(f'{k}={v}\n' for k, v in props.items()), stderr='')
        unit = rest[-1]
        if verb in ('start', 'restart') and unit not in self.broken:
            self.units[unit]['ActiveState'] = 'active'
        if verb == 'enable':
            self.units[unit]['UnitFileState'] = 'enabled'
            self.units[unit]['ActiveState'] = 'active'
        return NS(returncode=1 if unit in self.broken and verb != 'reset-failed' else 0, stdout='', stderr='broken')

    def acted(self, verb, unit):
        return [maintenance.SYSTEMCTL, verb, unit] in self.calls or [maintenance.SYSTEMCTL, verb, '--now', unit] in self.calls


@pytest.fixture
def env(tmp_path, monkeypatch):
    units = tmp_path / 'units'
    units.mkdir()
    monkeypatch.setattr(maintenance, 'DEEP_EVENTS', tmp_path / 'events.sock')
    monkeypatch.setattr(maintenance, 'DEEP_RESULTS', tmp_path / 'results.sock')
    monkeypatch.setattr(maintenance, 'KERNEL_GUARD_STATE', tmp_path / 'kg.json')
    (tmp_path / 'events.sock').write_text('')
    (tmp_path / 'results.sock').write_text('')
    (tmp_path / 'kg.json').write_text(json.dumps({'updated_at': 1000}))
    data = tmp_path / 'data'
    data.mkdir()
    return tmp_path, units, data


def kit(env, systemd, names, **kwargs):
    tmp_path, units, data = env
    for name in names:
        (units / name).write_text('')
    return maintenance.Kit(runner=systemd, state=tmp_path / 'state', clock=lambda: 1000.0, unit_dir=units,
                           data=data, verify=kwargs.pop('verify', lambda: 7), reader_ping=kwargs.pop('ping', lambda: True),
                           modes=kwargs.pop('modes', ()), identities=kwargs.pop('identities', {}),
                           ostree_marker=tmp_path / 'no-ostree', accounts=kwargs.pop('accounts', None), **kwargs)


def test_enabled_list_matches_what_the_package_enables():
    posttrans = SPEC.split('\n%posttrans\n', 1)[1].split('\n%postun', 1)[0]
    enabled = set()
    for line in posttrans.splitlines():
        line = line.strip()
        if line.startswith('systemctl enable'):
            enabled |= set(re.findall(r'satsuma-[\w.-]+\.(?:service|timer|path)', line.split('||')[0]))
    assert enabled == set(maintenance.ENABLED)
    for name in maintenance.ENABLED:
        assert (ROOT / 'systemd' / name).exists(), name


def test_a_failed_unit_is_started_after_its_start_limit_is_cleared(env):
    systemd = Systemd({'satsuma-deep-engine.service': {'ActiveState': 'failed', 'Result': 'start-limit-hit'}})
    summary = kit(env, systemd, ['satsuma-deep-engine.service']).check()
    assert systemd.acted('reset-failed', 'satsuma-deep-engine.service')
    assert systemd.acted('start', 'satsuma-deep-engine.service')
    unit_row = next(r for r in summary['rows'] if r['name'] == 'Birim satsuma-deep-engine.service')
    assert unit_row['repaired'] and unit_row['ok']
    assert 'ONARILDI' in maintenance.report(summary)


def test_nothing_is_repaired_when_the_installation_does_not_verify(env):
    systemd = Systemd({'satsuma-teams.service': {'ActiveState': 'failed'},
                       'satsuma-reader.service': {'UnitFileState': 'disabled', 'ActiveState': 'inactive'}})
    def bad():
        raise RuntimeError('Integrity mismatch: /opt/satsuma-core/x.py')
    summary = kit(env, systemd, ['satsuma-teams.service', 'satsuma-reader.service'], verify=bad,
                  ping=lambda: False).check()
    assert not summary['integrity_ok'] and summary['critical'] >= 1 and summary['repaired'] == 0
    assert not any(c[1] in ('start', 'restart', 'enable', 'reset-failed') for c in systemd.calls if c[0] == maintenance.SYSTEMCTL)
    assert 'hiçbir onarım yapılmadı' in maintenance.report(summary)


def test_a_masked_unit_is_reported_never_unmasked(env):
    systemd = Systemd({'satsuma-kernel-guard.service': {'UnitFileState': 'masked', 'ActiveState': 'inactive'}})
    summary = kit(env, systemd, ['satsuma-kernel-guard.service']).check()
    masked = next(r for r in summary['rows'] if r['name'] == 'Birim satsuma-kernel-guard.service')
    assert masked['severity'] == 'critical' and 'unmask' in masked['detail']
    assert not any(c[1] in ('unmask', 'start', 'enable') for c in systemd.calls if c[0] == maintenance.SYSTEMCTL)


def test_a_disabled_protection_unit_is_enabled_again(env):
    systemd = Systemd({'satsuma-exec-guard.service': {'UnitFileState': 'disabled', 'ActiveState': 'inactive'}})
    summary = kit(env, systemd, ['satsuma-exec-guard.service']).check()
    assert systemd.acted('enable', 'satsuma-exec-guard.service')
    assert next(r for r in summary['rows'] if r['name'] == 'Birim satsuma-exec-guard.service')['repaired']


def test_a_finished_oneshot_is_not_started(env):
    systemd = Systemd({'satsuma-boot-lockdown.service': {'Type': 'oneshot', 'ActiveState': 'inactive'}})
    kit(env, systemd, ['satsuma-boot-lockdown.service']).check()
    assert not systemd.acted('start', 'satsuma-boot-lockdown.service')


def test_unit_starts_are_never_capped(env, monkeypatch):
    # 2.2.62 (owner: "ürün zayıflıyor"): a cap let a killer keep a unit down; the shared ledger
    # spaces repeats out instead (its timing has its own test, test_repair_budget).
    from satsuma import repair_budget
    monkeypatch.setattr(repair_budget, 'SETTLE', 0)
    systemd = Systemd({'satsuma-teams.service': {'ActiveState': 'failed'}})
    systemd.broken.add('satsuma-teams.service')
    for _ in range(4):
        kit(env, systemd, ['satsuma-teams.service']).check()
    starts = [c for c in systemd.calls if c[:2] == [maintenance.SYSTEMCTL, 'start'] and c[-1] == 'satsuma-teams.service']
    assert len(starts) == 4
    history = json.loads((env[0] / 'state/history.json').read_text())
    assert len(history['start:satsuma-teams.service']) == 4


def test_report_only_mode_changes_nothing(env):
    systemd = Systemd({'satsuma-teams.service': {'ActiveState': 'failed'}})
    summary = kit(env, systemd, ['satsuma-teams.service'], repair=False).check()
    assert summary['repaired'] == 0 and not systemd.acted('start', 'satsuma-teams.service')


def test_unresponsive_reader_is_restarted(env, monkeypatch):
    monkeypatch.setattr(maintenance.time, 'sleep', lambda s: None)
    answers = iter([False, True])
    systemd = Systemd({'satsuma-reader.service': {}})
    summary = kit(env, systemd, ['satsuma-reader.service'], ping=lambda: next(answers)).check()
    reader = next(r for r in summary['rows'] if r['name'] == 'Panel okuyucusu (reader)')
    assert reader['repaired'] and systemd.acted('restart', 'satsuma-reader.service')


def test_missing_deep_engine_socket_starts_the_engine(env):
    (env[0] / 'events.sock').unlink()
    systemd = Systemd({'satsuma-deep-engine.service': {'ActiveState': 'inactive', 'UnitFileState': 'enabled'}})
    summary = kit(env, systemd, []).check()
    deep = next(r for r in summary['rows'] if r['name'] == 'Derin motor bağlantısı')
    assert deep['repaired'] and systemd.acted('start', 'satsuma-deep-engine.service')


def test_system_account_with_password_is_locked_with_evidence(env):
    tmp_path = env[0]
    (tmp_path / 'passwd').write_text('root:x:0:0::/root:/bin/bash\ncosmic-greeter:x:973:973::/:/usr/sbin/nologin\n')
    (tmp_path / 'shadow').write_text('root:$6$a$b:::::::\ncosmic-greeter:$6$c$d:::::::\n')
    systemd = Systemd({})
    accounts = {'passwd': tmp_path / 'passwd', 'shadow': tmp_path / 'shadow', 'evidence': tmp_path / 'evidence',
                'snapshot': tmp_path / 'snap.json'}
    summary = kit(env, systemd, [], accounts=accounts).check()
    assert ['/usr/sbin/usermod', '-L', 'cosmic-greeter'] in systemd.calls
    assert list((tmp_path / 'evidence').iterdir())
    assert next(r for r in summary['rows'] if r['name'] == 'Hesap özeti')['ok']


def test_wrong_mode_is_put_back_but_a_foreign_owner_is_only_reported(env):
    tmp_path = env[0]
    if os.geteuid() != 0:
        pytest.skip('needs root to create a file owned by another user')
    good = tmp_path / 'satsuma-admin'; good.write_text('#!/bin/sh\n'); os.chmod(good, 0o644)
    foreign = tmp_path / 'satsuma-other'; foreign.write_text('#!/bin/sh\n'); os.chown(foreign, 65534, 65534)
    systemd = Systemd({})
    summary = kit(env, systemd, [], modes=((str(tmp_path / 'satsuma-*'), 0o755, 'file'),)).check()
    assert oct(good.stat().st_mode & 0o777) == '0o755'
    assert foreign.stat().st_uid == 65534 and oct(foreign.stat().st_mode & 0o777) != '0o755'
    owner = next(r for r in summary['rows'] if r['name'] == 'Dosya sahipliği')
    assert owner['severity'] == 'critical' and 'satsuma-other' in owner['detail']


def test_results_are_kept_private(env):
    summary = kit(env, Systemd({}), []).check()
    state = env[0] / 'state'
    assert oct(state.stat().st_mode & 0o777) == '0o700'
    for name in ('last.json', 'history.jsonl'):
        assert oct((state / name).stat().st_mode & 0o777) == '0o600'
    assert json.loads((state / 'last.json').read_text())['rows'] == summary['rows']


def test_cli_and_timer_are_wired():
    from satsuma import admin_cli
    assert admin_cli._parser().parse_args(['bakim', '--yalniz-kontrol']).command == 'bakim'
    source = (ROOT / 'satsuma/admin_cli.py').read_text()
    assert 'from .maintenance import Kit' in source.split('def _full_check', 1)[1].split('def _aide', 1)[0]
    timer = (ROOT / 'systemd/satsuma-maintenance.timer').read_text()
    assert 'OnBootSec=15min' in timer and 'Unit=satsuma-maintenance.service' in timer
    assert 'systemctl enable --now satsuma-maintenance.timer' in SPEC


def test_a_unit_whose_condition_does_not_hold_is_not_a_problem(env):
    # Field log 2026-11-18: quarantine-rollback has ConditionDirectoryNotEmpty=
    # and nothing pending; "başlatılamadı: inactive" was a false alarm.
    systemd = Systemd({'satsuma-quarantine-rollback.service': {
        'Type': 'oneshot', 'RemainAfterExit': 'yes', 'ActiveState': 'inactive',
        'ConditionResult': 'no', 'ConditionTimestampMonotonic': '123456'}})
    summary = kit(env, systemd, ['satsuma-quarantine-rollback.service']).check()
    assert not any(r['name'] == 'Birim satsuma-quarantine-rollback.service' for r in summary['rows'])
    assert not systemd.acted('start', 'satsuma-quarantine-rollback.service')


def test_condition_checked_again_after_a_start(env):
    systemd = Systemd({'satsuma-quarantine-rollback.service': {
        'Type': 'oneshot', 'RemainAfterExit': 'yes', 'ActiveState': 'inactive', 'ConditionResult': 'no',
        'ConditionTimestampMonotonic': '0'}})
    original = systemd.__call__

    def runner(argv, **kwargs):
        result = original(argv, **kwargs)
        if argv[1:2] == ['start']:   # systemd evaluates the condition and leaves it inactive
            systemd.units[argv[-1]].update(ActiveState='inactive', ConditionTimestampMonotonic='999')
        return result
    summary = kit(env, runner, ['satsuma-quarantine-rollback.service']).check()
    row = next(r for r in summary['rows'] if r['name'] == 'Birim satsuma-quarantine-rollback.service')
    assert row['ok'] and 'koşulu' in row['detail']


def test_a_failed_unit_outside_the_enabled_list_is_repaired(env):
    systemd = Systemd({'satsuma-core-dns.service': {'ActiveState': 'failed', 'UnitFileState': 'enabled'}})
    summary = kit(env, systemd, ['satsuma-core-dns.service']).check()
    assert systemd.acted('reset-failed', 'satsuma-core-dns.service') and systemd.acted('start', 'satsuma-core-dns.service')
    assert next(r for r in summary['rows'] if r['name'] == 'Birim satsuma-core-dns.service')['repaired']


def test_first_boot_clears_start_limits_before_posttrans():
    script = (ROOT / 'installer/ostree_firstboot.sh').read_text()
    reset = script.index("systemctl reset-failed 'satsuma-*'")
    assert script.index('run_step PREIN pre') < reset < script.index('run_step POSTTRANS posttrans')
    subprocess.run(['sh', '-n', str(ROOT / 'installer/ostree_firstboot.sh')], check=True)
