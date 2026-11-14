"""satsuma-kur asks every setup step in order and runs only fixed commands.

satsuma-kur her kurulum adımını sırayla sorar ve yalnızca sabit komutlar çalıştırır.
"""
from pathlib import Path
from types import SimpleNamespace
import importlib.util

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location('kurulum', ROOT / 'installer/kurulum.py')
kurulum = importlib.util.module_from_spec(spec)
spec.loader.exec_module(kurulum)


class Runner:
    def __init__(self, failing=()):
        self.calls, self.failing = [], set(failing)

    def __call__(self, argv, **kwargs):
        assert isinstance(argv, list) and 'shell' not in kwargs
        self.calls.append(argv)
        bad = any(' '.join(argv).startswith(f) for f in self.failing)
        return SimpleNamespace(returncode=1 if bad else 0, stdout='', stderr='hata' if bad else '')


def setup(answers, runner, aide_exists=True):
    replies = iter(answers)
    return kurulum.Setup(runner=runner, ask=lambda q: next(replies), say=lambda *a: None,
                         exists=lambda p: aide_exists, environ={'SUDO_USER': 'zeki'},
                         user_exists=lambda name: name == 'zeki')


def test_full_run_in_order_with_defaults():
    runner = Runner()
    s = setup(['', 'h', 'h'], runner)   # user, OTX, keep the earlier AIDE snapshot
    assert s.all() == 0
    commands = [' '.join(c[:3]) for c in runner.calls]
    assert commands[:3] == ['/usr/bin/freshclam --quiet', '/usr/bin/suricata-update --no-test',
                            '/usr/bin/systemctl enable --now']
    assert ['/usr/bin/satsuma-setup', '--user', 'zeki'] in runner.calls
    assert ['/usr/bin/satsuma-admin', 'modem'] in runner.calls
    assert ['/usr/bin/systemctl', 'start', 'satsuma-kernel-profile.service'] in runner.calls
    assert runner.calls[-1] == ['/usr/bin/satsuma-admin', 'tam-kontrol']
    assert ['/usr/bin/satsuma-admin', 'set-otx-key'] not in runner.calls


def test_modem_falls_back_to_the_typed_mac_and_rejects_bad_input():
    runner = Runner(failing=['/usr/bin/satsuma-admin modem'])
    s = setup(['zz', 'A8:9A:93:12:34:56'], runner)
    s.modem()
    assert runner.calls[-1] == ['/usr/bin/satsuma-admin', 'modem', '--mac', 'A8:9A:93:12:34:56']


def test_root_or_unknown_user_is_asked_again_and_otx_when_wanted():
    runner = Runner()
    s = setup(['root', 'yok', 'zeki', 'e'], runner)
    s.account()
    s.otx()
    assert ['/usr/bin/satsuma-setup', '--user', 'zeki'] in runner.calls
    assert runner.calls[-1] == ['/usr/bin/satsuma-admin', 'set-otx-key']


def test_aide_snapshot_is_taken_last_and_only_after_every_step_passed():
    runner = Runner()
    s = setup(['', 'h'], runner, aide_exists=False)
    s.all()
    init = runner.calls.index(['/usr/bin/satsuma-admin', 'aide', 'ornek-al'])
    assert init > runner.calls.index(['/usr/bin/satsuma-admin', 'tam-kontrol'])
    assert init > runner.calls.index(['/usr/bin/systemctl', 'start', 'satsuma-kernel-profile.service'])


def test_a_failed_step_blocks_the_snapshot_and_is_in_the_summary():
    runner = Runner(failing=['/usr/bin/suricata-update'])
    s = setup(['', 'h'], runner, aide_exists=False)
    assert s.all() == 1
    assert ['/usr/bin/satsuma-admin', 'aide', 'ornek-al'] not in runner.calls
    failed = [name for name, ok, _ in s.results if not ok]
    assert failed == ['Suricata kuralları', 'AIDE örneği']


def test_an_existing_snapshot_is_replaced_only_when_asked():
    runner = Runner()
    s = setup(['', 'h', 'h'], runner, aide_exists=True)
    s.all()
    assert ['/usr/bin/satsuma-admin', 'aide', 'ornek-al'] not in runner.calls


def test_command_is_packaged_and_announced():
    wrapper = ROOT / 'packaging/root/usr/bin/satsuma-kur'
    assert wrapper.stat().st_mode & 0o111 and '/opt/satsuma-core/installer/kurulum.py' in wrapper.read_text()
    spec_text = (ROOT / 'packaging/satsuma-core.spec').read_text()
    assert 'sudo satsuma-kur' in spec_text and 'Requires: aide' in spec_text


def test_browser_policies_are_written_before_the_full_check():
    runner = Runner()
    setup(['', 'h', 'h'], runner).all()
    browser = next(i for i, c in enumerate(runner.calls) if 'satsuma.browser_policy' in c)
    assert browser < runner.calls.index(['/usr/bin/satsuma-admin', 'tam-kontrol'])
