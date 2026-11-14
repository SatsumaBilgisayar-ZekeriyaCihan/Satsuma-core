"""Hardening trial: a passing unit stays hardened, a broken one is rolled back.

systemctl, journalctl and systemd-analyze are replaced by a small fake; the
drop-in files are real files in a temporary directory.

Sertleştirme denemesi: geçen birim sertleşmiş kalır, bozulan geri alınır.
systemctl, journalctl ve systemd-analyze küçük bir taklitle değiştirilir;
eklenti dosyaları geçici dizindeki gerçek dosyalardır.
"""
from pathlib import Path
from types import SimpleNamespace

import pytest

from satsuma import hardening as hd

UNIT = 'satsuma-suricata-otx-guard'


class FakeSystemd:
    def __init__(self, runtime, behaviour='fine', active=True):
        self.runtime, self.behaviour, self.active = Path(runtime), behaviour, 'active' if active else 'inactive'
        self.calls = []

    def hardened(self):
        return (self.runtime / (UNIT + '.service.d') / hd.DROPIN).exists()

    def __call__(self, argv, **kwargs):
        self.calls.append(argv)
        out, code = '', 0
        if argv[0] == 'systemctl':
            if argv[1] == 'is-active':
                out = self.active
            elif argv[1] == 'restart':
                if self.hardened() and self.behaviour == 'restart_fails':
                    code = 1
                elif self.hardened() and self.behaviour == 'dies':
                    self.active = 'failed'
                else:
                    self.active = 'active'
        elif argv[0] == 'journalctl':
            out = ('guard started\n' + ('open /proc/1/mem: Operation not permitted\n'
                                        if self.hardened() and self.behaviour == 'denied' else ''))
        elif argv[0] == 'systemd-analyze':
            out = 'Overall exposure level for %s: %s\n' % (UNIT + '.service', '4.5 OK' if self.hardened() else '8.7 EXPOSED')
        return SimpleNamespace(stdout=out, stderr='', returncode=code)


@pytest.fixture
def env(tmp_path):
    source = tmp_path / 'source'
    source.mkdir()
    (source / 'tier1.conf').write_text('[Service]\nProtectKernelModules=yes\n')
    (source / (UNIT + '.tier2.conf')).write_text('[Service]\nProtectSystem=strict\n')
    return SimpleNamespace(source=source, runtime=tmp_path / 'run', persistent=tmp_path / 'etc',
                           state=tmp_path / 'state', tmp=tmp_path)


def run_trial(env, systemd, **kw):
    return hd.trial(UNIT, runner=systemd, source=env.source, runtime=env.runtime, state=env.state,
                    wait=3, sleep=lambda s: None, **kw)


def test_dropin_is_tier1_plus_the_units_own_tier2(env):
    text = hd.dropin_text(UNIT, env.source)
    assert 'ProtectKernelModules=yes' in text and 'ProtectSystem=strict' in text
    assert 'ProtectSystem' not in hd.dropin_text('satsuma-reader', env.source)


def test_unknown_or_path_like_units_are_refused(env):
    for bad in ('sshd', '../../etc/passwd', 'satsuma-core', ''):
        with pytest.raises(ValueError):
            hd.dropin_text(bad, env.source)


def test_passing_trial_keeps_the_dropin_and_reports_the_score(env):
    systemd = FakeSystemd(env.runtime)
    report = run_trial(env, systemd)
    assert report['ok'] is True and report['rolled_back'] is False
    assert (report['score_before'], report['score_after']) == ('8.7 EXPOSED', '4.5 OK')
    assert systemd.hardened()


@pytest.mark.parametrize('behaviour,reason', [('restart_fails', 'restart_failed'), ('dies', 'unit_left_active_state'),
                                              ('denied', 'permission_errors_in_journal')])
def test_every_kind_of_failure_removes_the_dropin_and_restarts_the_unit(env, behaviour, reason):
    systemd = FakeSystemd(env.runtime, behaviour)
    report = run_trial(env, systemd)
    assert report['ok'] is False and report['rolled_back'] is True and report['reason'] == reason
    assert not systemd.hardened()
    assert systemd.active == 'active'  # restarted as shipped
    assert systemd.calls[-1][:2] == ['systemctl', 'restart']
    if behaviour == 'denied':
        assert 'Operation not permitted' in report['journal'][0]


def test_a_unit_that_is_not_running_is_not_touched(env):
    systemd = FakeSystemd(env.runtime, active=False)
    report = run_trial(env, systemd)
    assert report['reason'] == 'unit_not_active_before_trial'
    assert not systemd.hardened() and not any(c[1] == 'restart' for c in systemd.calls if c[0] == 'systemctl')


def test_persist_needs_a_passed_trial_in_this_boot_with_the_same_text(env):
    systemd = FakeSystemd(env.runtime)
    args = dict(runner=systemd, source=env.source, runtime=env.runtime, persistent=env.persistent, state=env.state)
    assert hd.persist(UNIT, **args)['reason'] == 'no_passed_trial'
    run_trial(env, systemd)
    (env.source / 'tier1.conf').write_text('[Service]\nProtectKernelModules=yes\nRestrictRealtime=yes\n')
    assert hd.persist(UNIT, **args)['reason'] == 'trial_not_valid_for_this_boot_and_text'
    (env.source / 'tier1.conf').write_text('[Service]\nProtectKernelModules=yes\n')
    result = hd.persist(UNIT, **args)
    assert result['ok'] is True
    assert (env.persistent / (UNIT + '.service.d') / hd.DROPIN).read_text() == hd.dropin_text(UNIT, env.source)
    assert not systemd.hardened()  # the runtime copy was replaced by the permanent one


def test_persist_refuses_a_trial_from_another_boot(env):
    systemd = FakeSystemd(env.runtime)
    run_trial(env, systemd)
    record = env.state / (UNIT + '.json')
    record.write_text(record.read_text().replace(hd._boot_id() or 'x', 'another-boot') if hd._boot_id()
                      else '{"ok": true, "sha256": "x", "boot": "other"}')
    args = dict(runner=systemd, source=env.source, runtime=env.runtime, persistent=env.persistent, state=env.state)
    assert hd.persist(UNIT, **args)['ok'] is False


def test_rollback_removes_everything_and_restarts(env):
    systemd = FakeSystemd(env.runtime)
    run_trial(env, systemd)
    hd._write(env.persistent, UNIT, 'x')
    result = hd.rollback(UNIT, runner=systemd, runtime=env.runtime, persistent=env.persistent, state=env.state)
    assert result == {'unit': UNIT, 'ok': True, 'active': 'active'}
    assert not systemd.hardened() and not (env.persistent / (UNIT + '.service.d') / hd.DROPIN).exists()
    assert not (env.state / (UNIT + '.json')).exists()


def test_status_lists_every_unit_with_its_dropin_and_score(env):
    systemd = FakeSystemd(env.runtime)
    run_trial(env, systemd)
    rows = {r['unit']: r for r in hd.status(runner=systemd, persistent=env.persistent, runtime=env.runtime)}
    assert set(rows) == set(hd.UNITS)
    assert rows[UNIT]['dropin'] == ['runtime'] and rows['satsuma-privd']['dropin'] == ['none']


ROOT = Path(__file__).resolve().parents[1]


def test_shipped_dropins_exist_for_every_unit_and_are_packaged():
    assert (ROOT / 'packaging/hardening/tier1.conf').is_file()
    for unit in hd.UNITS:
        assert (ROOT / 'systemd' / (unit + '.service')).is_file(), unit
        text = hd.dropin_text(unit, ROOT / 'packaging/hardening')
        assert text.lstrip().splitlines()[0].startswith('#') and '[Service]' in text
    spec = (ROOT / 'packaging/satsuma-core.spec').read_text()
    assert 'install -m 0644 packaging/hardening/* %{buildroot}/usr/share/satsuma-core/hardening/' in spec
    assert '\n/usr/share/satsuma-core/hardening\n' in spec
    # `install systemd/*` fails on a sub-directory, so the drop-ins must not live there.
    assert not [p for p in (ROOT / 'systemd').iterdir() if p.is_dir()]


def test_tier1_only_has_restrictions_that_cannot_break_a_satsuma_service():
    text = (ROOT / 'packaging/hardening/tier1.conf').read_text()
    keys = {line.split('=')[0] for line in text.splitlines() if '=' in line and not line.startswith('#')}
    assert keys == {'ProtectKernelModules', 'ProtectKernelLogs', 'ProtectControlGroups', 'ProtectClock',
                    'ProtectHostname', 'RestrictRealtime', 'RestrictSUIDSGID', 'LockPersonality',
                    'RestrictNamespaces', 'SystemCallArchitectures'}


def test_admin_cli_accepts_the_hardening_commands():
    from satsuma.admin_cli import _parser
    parser = _parser()
    for argv in (['sertlestirme', 'durum'], ['sertlestirme', 'dene', 'hepsi'],
                 ['sertlestirme', 'uygula', 'satsuma-reader'], ['sertlestirme', 'geri-al', 'satsuma-reader']):
        assert parser.parse_args(argv).command == 'sertlestirme'
