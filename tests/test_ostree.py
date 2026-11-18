"""Fedora Atomic (rpm-ostree) installation paths (2.2.38).

These are unit tests only: an rpm-ostree install on a Silverblue/Kinoite/COSMIC
Atomic device has not been tried and must be before anyone is told it works.
Yalnızca birim testleri; gerçek ostree cihazında kurulum denenmedi.
"""
import subprocess
from pathlib import Path
from types import SimpleNamespace as NS

import pytest

from satsuma import definitions, kernel_guard, ostree, ptrace_guard

ROOT = Path(__file__).parents[1]
SPEC = (ROOT / 'packaging/satsuma-core.spec').read_text()


@pytest.fixture
def atomic(tmp_path, monkeypatch):
    marker = tmp_path / 'ostree-booted'
    marker.write_text('')
    monkeypatch.setattr(ostree, 'MARKER', marker)
    return tmp_path


@pytest.fixture
def classic(tmp_path, monkeypatch):
    monkeypatch.setattr(ostree, 'MARKER', tmp_path / 'absent')
    return tmp_path


class Runner:
    def __init__(self, stdout=''):
        self.calls, self.stdout = [], stdout

    def __call__(self, args, **kwargs):
        self.calls.append(list(args))
        return NS(returncode=0, stdout=self.stdout, stderr='')


def test_detection_and_sysctl_folder(atomic):
    assert ostree.booted()
    assert ostree.sysctl_dir() == Path('/etc/sysctl.d')


def test_classic_fedora_is_unchanged(classic):
    assert not ostree.booted()
    assert ostree.sysctl_dir() == Path('/usr/lib/sysctl.d')
    runner = Runner()
    ostree.update_args(add=['lockdown=integrity'], runner=runner)
    assert runner.calls == [['/usr/sbin/grubby', '--update-kernel=ALL', '--args=lockdown=integrity']]


def test_kernel_arguments_use_rpm_ostree_kargs(atomic):
    runner = Runner('rhgb quiet root=UUID=x lockdown=integrity\n')
    assert ostree.boot_entries(runner) == {'ostree-default-deployment': {'rhgb', 'quiet', 'root=UUID=x', 'lockdown=integrity'}}
    assert runner.calls == [['/usr/bin/rpm-ostree', 'kargs']]
    runner = Runner()
    ostree.update_args(add=['a=1', 'b'], remove=['sysctl.kernel.yama.ptrace_scope=3'], runner=runner)
    assert runner.calls == [['/usr/bin/rpm-ostree', 'kargs', '--append-if-missing=a=1', '--append-if-missing=b',
                             '--delete-if-present=sysctl.kernel.yama.ptrace_scope=3']]


def test_nothing_to_change_runs_nothing(atomic):
    runner = Runner()
    assert ostree.update_args(runner=runner).returncode == 0 and runner.calls == []


def test_kernel_profile_reads_and_writes_through_ostree(atomic, tmp_path):
    from satsuma import kernel_profile
    modules = tmp_path / 'modules'; modules.write_text('')
    seen = {'kargs': 'rhgb quiet'}

    def runner(args, **kwargs):
        if args[:2] == ['/usr/bin/rpm-ostree', 'kargs'] and len(args) == 2:
            return NS(returncode=0, stdout=seen['kargs'], stderr='')
        if args[:2] == ['/usr/bin/rpm-ostree', 'kargs']:
            seen['kargs'] += ' ' + ' '.join(a.split('=', 1)[1] for a in args[2:] if a.startswith('--append-if-missing='))
            return NS(returncode=0, stdout='', stderr='')
        raise AssertionError('grubby must not run on ostree: ' + ' '.join(args))
    result = kernel_profile.apply_boot(runner, modules_path=str(modules))
    assert result['ok'] and result['updated_kernels'] == ['ostree-default-deployment']
    assert all(a in seen['kargs'].split() for a in result['args'])


def test_ptrace_guard_overrides_a_read_only_usr_file_from_etc(atomic, tmp_path, monkeypatch):
    usr = tmp_path / 'usr/lib/sysctl.d'; usr.mkdir(parents=True)
    bad = usr / '95-vendor.conf'; bad.write_text('kernel.yama.ptrace_scope = 3\nvm.x = 1\n')
    etc = tmp_path / 'etc/sysctl.d'
    monkeypatch.setattr(ostree, 'SYSCTL_DIR_ETC', etc)
    original = ptrace_guard._override_target

    def target(real, marker=None):
        # The test tree is not under /usr: pretend it is.
        return etc / real.name if str(real).startswith(str(tmp_path / 'usr')) else original(real, marker)
    monkeypatch.setattr(ptrace_guard, '_override_target', target)
    ptrace_guard._neutralize_file(str(bad), [1], tmp_path / 'evidence', lambda: 1)
    assert bad.read_text() == 'kernel.yama.ptrace_scope = 3\nvm.x = 1\n'      # /usr untouched
    override = (etc / '95-vendor.conf').read_text()
    assert override.startswith(ptrace_guard.MARK) and 'vm.x = 1' in override


def test_override_target_only_redirects_usr_on_ostree(atomic, classic):
    assert ptrace_guard._override_target(Path('/usr/lib/sysctl.d/x.conf'), marker=atomic / 'ostree-booted') \
        == Path('/etc/sysctl.d/x.conf')
    assert ptrace_guard._override_target(Path('/usr/lib/sysctl.d/x.conf'), marker=classic / 'absent') \
        == Path('/usr/lib/sysctl.d/x.conf')
    assert ptrace_guard._override_target(Path('/etc/sysctl.d/x.conf'), marker=atomic / 'ostree-booted') \
        == Path('/etc/sysctl.d/x.conf')


def test_definitions_fall_back_to_the_packaged_copy(tmp_path, monkeypatch):
    import os
    packaged = tmp_path / 'share'; packaged.mkdir()
    (packaged / definitions.FILES['kev']).write_text('schema: satsuma/definitions-v1\nvulnerabilities: [{cve: CVE-1}]\n')
    monkeypatch.setattr(definitions, 'DIRECTORY', tmp_path / 'var-missing')
    monkeypatch.setattr(definitions, 'PACKAGED', packaged)
    assert definitions.kev('CVE-1', owner=os.geteuid()) == {'cve': 'CVE-1'}
    assert 'install -m 0644 data/tanim/*.yaml %{buildroot}/usr/share/satsuma-core/tanim/' in SPEC


def test_rpm_ostree_counts_as_a_package_manager():
    assert 'rpm-ostree' in kernel_guard.PACKAGE_MANAGERS


@pytest.mark.parametrize('section', ['%pre\n', '%preun\n', '%posttrans\n'])
def test_every_package_script_steps_aside_under_rpm_ostree(section):
    body = SPEC.split(section, 1)[1].split('\n%', 1)[0]
    head = body.split('\nfi\n', 1)[0]
    assert '[ -e /run/ostree-booted ]' in head and '[ ! -d /run/systemd/system ]' in head
    assert 'SATSUMA_OSTREE_FIRSTBOOT' in head and 'exit 0' in head


def test_first_boot_unit_runs_the_deferred_scripts_once_per_version():
    unit = (ROOT / 'systemd/satsuma-ostree-firstboot.service').read_text()
    assert 'ConditionPathExists=/run/ostree-booted' in unit
    script = (ROOT / 'installer/ostree_firstboot.sh').read_text()
    assert 'run_step PREIN pre' in script and 'run_step POSTTRANS posttrans' in script
    assert 'export SATSUMA_OSTREE_FIRSTBOOT=1' in script
    assert '.ostree-installed' in script
    subprocess.run(['sh', '-n', str(ROOT / 'installer/ostree_firstboot.sh')], check=True)


def test_image_mount_check_asks_for_the_real_path():
    source = (ROOT / 'installer/image_runtime.py').read_text()
    assert "'--mountpoint',os.path.realpath(MOUNT)" in source
