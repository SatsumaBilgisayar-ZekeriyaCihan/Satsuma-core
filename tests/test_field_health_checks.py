"""2.2.54: health checks for problems found on the field machine (2026-11-19)."""
from pathlib import Path

from satsuma.self_health import onaccess_check, ostree_cleanup_check, CHECK_LABELS

ROOT = Path(__file__).resolve().parents[1]


def test_onaccess_not_running_is_reported():
    assert onaccess_check({'LoadState': 'loaded', 'ActiveState': 'active'})['ok'] is True
    bad = onaccess_check({'LoadState': 'loaded', 'ActiveState': 'failed', 'Result': 'start-limit-hit'})
    assert bad['ok'] is False and 'journalctl -u satsuma-clamonacc' in bad['error']
    assert onaccess_check({'LoadState': 'not-found'})['ok'] is False


def test_failed_ostree_cleanup_is_reported_only_on_ostree():
    failed = {'ActiveState': 'failed', 'Result': 'exit-code'}
    assert ostree_cleanup_check(failed, True)['ok'] is False
    assert ostree_cleanup_check(failed, False)['ok'] is True
    assert ostree_cleanup_check({'ActiveState': 'active'}, True)['ok'] is True
    assert {'onaccess', 'ostree_cleanup'} <= set(CHECK_LABELS)


def test_clamonacc_unit_can_reach_the_clamd_socket():
    unit = (ROOT / 'systemd/satsuma-clamonacc.service').read_text()
    assert 'SupplementaryGroups=virusgroup' in unit


def test_selinux_boolean_is_enabled_once(tmp_path):
    import importlib.util
    spec = importlib.util.spec_from_file_location('onaccess_setup', ROOT / 'installer/onaccess_setup.py')
    mod = importlib.util.module_from_spec(spec); spec.loader.exec_module(mod)
    calls = []

    class R:
        def __init__(self, out='', rc=0): self.stdout, self.returncode, self.stderr = out, rc, ''

    def runner(args, **kw):
        calls.append(args)
        return R({'getenforce': 'Enforcing\n', 'getsebool': 'antivirus_can_scan_system --> off\n'}.get(Path(args[0]).name, ''))
    assert mod.allow_selinux_scan(runner) == 'enabled'
    assert calls[-1] == ['/usr/sbin/setsebool', '-P', 'antivirus_can_scan_system', '1']
    on = lambda args, **kw: R('Enforcing' if 'getenforce' in args[0] else 'antivirus_can_scan_system --> on')
    assert mod.allow_selinux_scan(on) == 'already_on'
    assert mod.allow_selinux_scan(lambda a, **k: R('Disabled')) == 'selinux_disabled'


def test_coredump_socket_is_not_ordered_after_memory_hardening():
    unit = (ROOT / 'systemd/satsuma-memory-hardening.service').read_text()
    assert 'Before=systemd-coredump.socket' not in [l.strip() for l in unit.splitlines()]
    assert 'After=systemd-sysctl.service' in unit


def test_harmless_boot_messages_do_not_become_a_kernel_problem():
    from satsuma.boot_correlator import correlate, relevant
    start = 1000.0
    noise = [{'time': start + 6, 'priority': 3, 'message': m, 'pid': '', 'exe': '', 'comm': '', 'unit': '', 'kernel': True}
             for m in ('pinctrl core: failed to create debugfs directory for AMDI0030:00',
                       'virt/tdx: TDX not supported by the host platform',
                       'pci 0000:00:01.1: bridge has subordinate 01 but max busn 02')]
    real = {'time': start + 7, 'priority': 3, 'message': 'BUG: unable to handle page fault', 'pid': '', 'exe': '',
            'comm': '', 'unit': '', 'kernel': True}
    finding = {'_time': start + 12, 'severity': 'critical', 'title': 'x', 'rule_id': 'R'}
    problems, _ = correlate(start, relevant(noise), [finding])
    assert not any(p['key'] == 'kernel' for p in problems)
    problems, _ = correlate(start, relevant(noise + [real]), [finding])
    assert any(p['key'] == 'kernel' for p in problems)


def test_userns_dropins_for_every_shipped_privateusers_service():
    strict = (ROOT / 'packaging/root/usr/lib/sysctl.d/93-satsuma-strict.conf').read_text()
    assert 'user.max_user_namespaces = 0' in strict
    spec = (ROOT / 'packaging/satsuma-core.spec').read_text()
    for name in ('accounts-daemon', 'chrony-wait', 'colord', 'fstrim', 'nm-priv-helper', 'pcscd'):
        rel = f'usr/lib/systemd/system/{name}.service.d/90-satsuma-userns.conf'
        assert 'PrivateUsers=no' in (ROOT / 'packaging/root' / rel).read_text()
        assert '/' + rel in spec
