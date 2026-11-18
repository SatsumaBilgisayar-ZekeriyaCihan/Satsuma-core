"""USBGuard from the first instant of boot, without locking the user out.

Açılışın ilk anından itibaren USBGuard; kullanıcıyı dışarıda bırakmadan.
"""
import json
from pathlib import Path
from types import SimpleNamespace as NS

import pytest

from satsuma import usb_guard as ug

ROOT = Path(__file__).parents[1]


def usb(sysfs, name, removable, keyboard=False):
    dev = sysfs / name
    dev.mkdir(parents=True)
    (dev / 'idVendor').write_text('046d\n')
    (dev / 'removable').write_text(removable + '\n')
    iface = sysfs / (name + ':1.0')
    iface.mkdir()
    (iface / 'bInterfaceClass').write_text('03\n')
    (iface / 'bInterfaceProtocol').write_text(('01' if keyboard else '02') + '\n')
    # sysfs lists interfaces inside the device directory too
    (dev / (name + ':1.0')).symlink_to(iface)


class Host:
    def __init__(self, root_tran='nvme'):
        self.calls, self.root_tran = [], root_tran

    def runner(self, args, **kw):
        self.calls.append(args)
        if args[0].endswith('usbguard'):
            return NS(returncode=0, stdout='allow id 046d:c31c name "Keyboard"\n', stderr='')
        if args[0].endswith('findmnt'):
            return NS(returncode=0, stdout='/dev/nvme0n1p3\n', stderr='')
        if args[0].endswith('lsblk'):
            return NS(returncode=0, stdout=self.root_tran + '\n', stderr='')
        return NS(returncode=0, stdout='', stderr='')


@pytest.fixture
def fs(tmp_path):
    sysfs = tmp_path / 'sys'; sysfs.mkdir()
    etc = tmp_path / 'etc'; etc.mkdir()
    return sysfs, etc


def setup(host, fs, crypttab='', cmdline='ro quiet'):
    sysfs, etc = fs
    (etc / 'crypttab').write_text(crypttab)
    return ug.setup(host.runner, sysfs, str(etc / 'crypttab'), etc / 'usbguard-daemon.conf', etc / 'rules.conf', cmdline,
                    original=etc / 'usbguard-original.json')


def test_fresh_install_allows_only_keyboard_mouse_and_hubs_and_sets_kernel_arg(fs):
    usb(fs[0], '1-1', 'removable', keyboard=True)
    host = Host()
    report = setup(host, fs)
    assert report['status'] == 'REBOOT_REQUIRED'
    rules = [l for l in (fs[1] / 'rules.conf').read_text().splitlines() if not l.startswith('#')]
    assert rules == ['allow with-interface match-all { 09:*:* }', 'allow with-interface match-all { 03:*:* }']
    assert not any(c[:2] == ['/usr/bin/usbguard', 'generate-policy'] for c in host.calls)
    assert ['/usr/bin/systemctl', 'restart', 'usbguard.service'] in host.calls
    conf = (fs[1] / 'usbguard-daemon.conf').read_text()
    for key, value in ug.DAEMON_SETTINGS.items():
        assert f'{key}={value}\n' in conf
    assert ['/usr/sbin/grubby', '--update-kernel=ALL', '--args=usbcore.authorized_default=2'] in host.calls
    assert ['/usr/bin/systemctl', 'enable', '--now', 'usbguard.service'] in host.calls


def test_an_old_policy_allowing_a_usb_disk_is_replaced_and_kept_aside(fs):
    # A policy generated while a USB disk was plugged in would allow that disk.
    (fs[1] / 'rules.conf').write_text('allow id 1234:5678 with-interface { 08:06:50 }\n')
    (fs[1] / 'usbguard-daemon.conf').write_text('RuleFile=/etc/usbguard/rules.conf\nImplicitPolicyTarget=allow\n# AuthorizedDefault=all\n')
    host = Host()
    setup(host, fs)
    assert (fs[1] / 'rules.conf').read_text() == ug.POLICY
    original = json.loads((fs[1] / 'usbguard-original.json').read_text())
    assert original['rules'] == 'allow id 1234:5678 with-interface { 08:06:50 }\n'
    report = ug.restore(host.runner, fs[0], fs[1] / 'usbguard-daemon.conf', fs[1] / 'usbguard-original.json', fs[1] / 'rules.conf')
    assert 'rules_restored' in report['actions']
    assert (fs[1] / 'rules.conf').read_text() == 'allow id 1234:5678 with-interface { 08:06:50 }\n'


def test_other_daemon_lines_are_kept(fs):
    (fs[1] / 'rules.conf').write_text(ug.POLICY)
    (fs[1] / 'usbguard-daemon.conf').write_text('RuleFile=/etc/usbguard/rules.conf\nImplicitPolicyTarget=allow\n# AuthorizedDefault=all\n')
    host = Host()
    setup(host, fs)
    conf = (fs[1] / 'usbguard-daemon.conf').read_text()
    assert conf.startswith('RuleFile=/etc/usbguard/rules.conf\nImplicitPolicyTarget=block\n# AuthorizedDefault=all\n')
    assert not any(c[0].endswith('usbguard') for c in host.calls)


def test_encrypted_disk_with_external_keyboard_keeps_the_passphrase_typable(fs):
    usb(fs[0], '1-2', 'unknown', keyboard=True)
    host = Host()
    report = setup(host, fs, crypttab='luks-abc UUID=x none discard\n')
    assert report['status'] == 'ACTIVE_WITHOUT_EARLY_BOOT'
    assert report['reason'] == 'disk_passphrase_needs_external_usb_keyboard'
    assert not any(c[0].endswith('grubby') for c in host.calls)


def test_encrypted_disk_with_internal_keyboard_still_gets_early_protection(fs):
    usb(fs[0], '1-3', 'fixed', keyboard=True)
    report = setup(Host(), fs, crypttab='luks-abc UUID=x none\n')
    assert report['status'] == 'REBOOT_REQUIRED'


def test_root_on_usb_is_never_locked_out(fs):
    report = setup(Host(root_tran='usb'), fs)
    assert report['reason'] == 'root_filesystem_on_usb'


def test_already_active_kernel_arg_is_not_set_again(fs):
    host = Host()
    report = setup(host, fs, cmdline='ro usbcore.authorized_default=2')
    assert report['status'] == 'ACTIVE_FROM_EARLY_BOOT'
    assert not any(c[0].endswith('grubby') for c in host.calls)


def test_package_requires_usbguard_and_install_runs_setup():
    spec = (ROOT / 'packaging/satsuma-core.spec').read_text()
    assert 'Requires: usbguard\n' in spec
    assert '/opt/satsuma-core/main.py --usbguard-setup ||' in spec


def test_full_removal_drops_the_usb_kernel_argument():
    # Field report 2026-10-25: after uninstalling, USB keyboard and mouse were
    # dead because usbcore.authorized_default=2 stayed on every kernel.
    from pathlib import Path
    from satsuma.usb_guard import KERNEL_ARG
    spec = (Path(__file__).parents[1] / 'packaging/satsuma-core.spec').read_text()
    preun = spec.split('%preun\n', 1)[1].split('\n%', 1)[0]
    # 2.2.38: an ostree guard comes first (rpm-ostree's sandbox can do nothing);
    # on ostree the argument is never set (satsuma.usb_guard), so nothing is left.
    guard, preun = preun.split('\nfi\n', 1)
    assert 'satsuma_ostree' in guard and 'exit 0' in guard
    assert preun.startswith('if [ "$1" -eq 0 ]')
    assert f'/usr/sbin/grubby --update-kernel=ALL --remove-args={KERNEL_ARG} || exit 1' in preun
    assert preun.rstrip().endswith('fi')


def test_original_state_is_recorded_once_and_restored_on_removal(fs):
    sysfs, etc = fs
    conf = etc / 'usbguard-daemon.conf'
    conf.write_text('RuleFile=/etc/usbguard/rules.conf\nImplicitPolicyTarget=allow\n')
    host = Host()
    setup(host, fs)
    original = json.loads((etc / 'usbguard-original.json').read_text())
    assert original['daemon_settings']['ImplicitPolicyTarget'] == 'allow'
    assert original['daemon_settings']['AuthorizedDefault'] is None
    setup(host, fs)  # a second run must not overwrite the true original
    assert json.loads((etc / 'usbguard-original.json').read_text()) == original
    usb(sysfs, '1-4', 'removable', keyboard=True)
    (sysfs / '1-4' / 'authorized').write_text('0\n')
    (sysfs / 'usb1').mkdir(); (sysfs / 'usb1' / 'authorized_default').write_text('2\n')
    report = ug.restore(host.runner, sysfs, conf, etc / 'usbguard-original.json', etc / 'rules.conf')
    assert report['status'] == 'RESTORED', report
    assert (sysfs / '1-4' / 'authorized').read_text() == '1'
    assert (sysfs / 'usb1' / 'authorized_default').read_text() == '1'
    assert conf.read_text() == 'RuleFile=/etc/usbguard/rules.conf\nImplicitPolicyTarget=allow\n'
    assert ['/usr/sbin/grubby', '--update-kernel=ALL', '--remove-args=usbcore.authorized_default=2'] in host.calls
    assert ['/usr/bin/systemctl', 'disable', '--now', 'usbguard.service'] in host.calls


def test_removal_gives_usb_back_before_anything_that_can_abort():
    spec = (ROOT / 'packaging/satsuma-core.spec').read_text()
    preun = spec.split('%preun\n', 1)[1].split('%posttrans\n', 1)[0]
    restore = preun.index('main.py --usbguard-restore')
    assert restore < preun.index('grubby --update-kernel=ALL --remove-args=usbcore.authorized_default=2')
    assert restore < preun.index('|| exit 1') and restore < preun.index('satsuma-image unmount')
    # The flag is handled by satsuma/app.py in this source (main.py only forwards to it).
    assert "'--usbguard-restore'" in (ROOT / 'satsuma' / 'app.py').read_text()



def test_ostree_never_sets_the_kernel_argument_removal_could_not_undo(fs, monkeypatch, tmp_path):
    # 2.2.38: rpm-ostree's sandbox cannot remove it on uninstall; USB input would stay dead.
    from satsuma import ostree
    marker = tmp_path / 'ostree-booted'; marker.write_text('')
    monkeypatch.setattr(ostree, 'MARKER', marker)
    usb(fs[0], '1-1', 'removable', keyboard=True)
    host = Host()
    report = setup(host, fs)
    assert report['status'] == 'ACTIVE_WITHOUT_EARLY_BOOT'
    assert report['reason'] == 'ostree_removal_cannot_undo_kernel_argument'
    assert not any('kargs' in ' '.join(c) or c[0].endswith('grubby') for c in host.calls)
    assert any(c[-1] == 'usbguard.service' for c in host.calls)   # the daemon still enforces


def test_normal_fedora_still_sets_the_argument_with_grubby(fs, monkeypatch, tmp_path):
    from satsuma import ostree
    monkeypatch.setattr(ostree, 'MARKER', tmp_path / 'absent')
    usb(fs[0], '1-1', 'removable', keyboard=True)
    host = Host()
    assert setup(host, fs)['status'] == 'REBOOT_REQUIRED'
    assert ['/usr/sbin/grubby', '--update-kernel=ALL', '--args=' + ug.KERNEL_ARG] in host.calls
