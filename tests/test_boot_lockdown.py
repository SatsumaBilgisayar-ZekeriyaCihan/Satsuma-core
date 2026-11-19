import subprocess
"""Radios off, USB modem, PPP and tuned masked at every boot.

Her açılışta radyolar kapalı; USB modem, PPP ve tuned maskeli.
"""
import os
import re
from pathlib import Path
from types import SimpleNamespace as NS

from satsuma import boot_lockdown as bl

ROOT = Path(__file__).parents[1]


class Host:
    def __init__(self):
        self.calls = []

    def runner(self, args, **kw):
        self.calls.append(args)
        return NS(returncode=0, stdout='', stderr='')


def test_one_change_all_event_blocks_every_radio_and_saved_states(tmp_path):
    device = tmp_path / 'rfkill'
    device.write_bytes(b'')
    saved = tmp_path / 'saved'
    saved.mkdir()
    (saved / 'pci-0000:00:14.3:wlan').write_text('0\n')
    (saved / 'platform-bt:bluetooth').write_text('1\n')
    report = bl.block_radios(device, saved)
    assert report['radios'] == 'blocked'
    assert bl.RFKILL_EVENT.unpack(device.read_bytes()) == (0, 0, 3, 1, 0)  # all types, CHANGE_ALL, soft block
    assert (saved / 'pci-0000:00:14.3:wlan').read_text() == '1\n'
    assert report['saved_states_set_blocked'] == ['pci-0000:00:14.3:wlan']


def test_missing_rfkill_device_is_reported_not_hidden(tmp_path):
    report = bl.block_radios(tmp_path / 'missing' / 'rfkill', tmp_path)
    assert report['radios'] == 'failed' and 'rfkill' in report['radios_error']


def test_unmasked_units_are_masked_and_already_masked_left_alone(tmp_path):
    os.symlink('/dev/null', tmp_path / 'tuned.service')
    host = Host()
    found = bl.mask_units(bl.MASKED_UNITS, tmp_path, host.runner)
    assert found == ['ModemManager.service', 'tuned-ppd.service']
    assert ['/usr/bin/systemctl', 'mask', '--now', '--no-block', 'ModemManager.service'] in host.calls
    assert not any('tuned.service' in c for c in host.calls)


def test_ppp_modules_cannot_load_and_loaded_ones_are_removed(tmp_path):
    modules = tmp_path / 'modules'
    modules.write_text('pppoe 24576 0 - Live 0x0\npppox 12288 1 pppoe, Live 0x0\nppp_generic 53248 2 pppoe,pppox, Live 0x0\next4 1 0 - Live 0x0\n')
    host = Host()
    report = bl.block_ppp(tmp_path / 'satsuma-no-ppp.conf', modules, host.runner)
    text = (tmp_path / 'satsuma-no-ppp.conf').read_text()
    for module in ('ppp_generic', 'ppp_async', 'pppoe', 'pptp', 'l2tp_ppp'):
        assert f'install {module} /bin/true\n' in text
    assert report['modules_unloaded'] == ['pppox', 'pppoe', 'ppp_generic']
    assert bl.block_ppp(tmp_path / 'satsuma-no-ppp.conf', tmp_path / 'none', host.runner)['modprobe_file_repaired'] is False


def unit(key):
    return re.findall(rf'^{key}=(.*)$', (ROOT / 'systemd/satsuma-boot-lockdown.service').read_text(), re.M)


def test_runs_every_boot_before_network_radios_and_modems():
    before = ' '.join(unit('Before')).split()
    for target in ('network-pre.target', 'NetworkManager.service', 'bluetooth.service', 'ModemManager.service', 'tuned.service'):
        assert target in before
    assert unit('WantedBy') == ['sysinit.target'] and unit('DefaultDependencies') == ['no']
    spec = (ROOT / 'packaging/satsuma-core.spec').read_text()
    assert 'systemctl enable satsuma-boot-lockdown.service || exit 1' in spec
    assert "'satsuma-boot-lockdown.service'" in (ROOT / 'installer/service_setup.py').read_text()


def test_unused_modules_from_the_inventory_cannot_load(tmp_path):
    """Owner decision 2026-11-20: loaded modules nothing used (lsmod 0) are kept out."""
    modules = tmp_path / 'modules'
    modules.write_text('amdgpu 1 0 - Live 0x0\ngpu_sched 1 1 amdgpu, Live 0x0\nradeon 1 40 - Live 0x0\nuinput 1 0 - Live 0x0\n')
    host = Host()
    report = bl.block_unused(tmp_path / 'unused.conf', modules, host.runner)
    text = (tmp_path / 'unused.conf').read_text()
    for module in ('amdgpu', 'uinput', 'slhc', 'iptable_filter', 'br_netfilter', 'joydev', 'pcspkr'):
        assert f'install {module} /bin/true\n' in text
    for kept in ('radeon', 'kvm', 'kvm_amd', 'tun', 'nf_tables', 'wireguard', 'veth', 'bridge', 'stp', 'llc'):
        assert f'install {kept} ' not in text
    assert report['unused_unloaded'] == ['amdgpu', 'gpu_sched', 'uinput']     # users first


def test_fwupd_boot_loads_are_voided(tmp_path):
    report = bl.void_boot_loads(tmp_path)
    assert sorted(report['boot_loads_voided']) == ['fwupd-i2c.conf', 'fwupd-msr.conf']
    assert (tmp_path / 'fwupd-msr.conf').read_text().startswith('#')
    assert bl.void_boot_loads(tmp_path) == {'boot_loads_voided': []}
    text = bl.UNUSED_TEXT
    assert 'install msr /bin/true' in text and 'install i2c_dev /bin/true' in text


def _kernel(root, kernel, names):
    d = root / kernel
    d.mkdir(parents=True)
    (d / 'modules.dep').write_text(''.join(f'kernel/x/{n.replace("_", "-")}.ko.xz:\n' for n in names))


def test_only_modules_this_computer_loaded_may_load(tmp_path):
    root, record, conf = tmp_path / 'lib', tmp_path / 'rec.json', tmp_path / 'allow.conf'
    _kernel(root, 'k1', ['radeon', 'r8169', 'snd_hda_intel', 'usb_storage', 'sr_mod', 'cfg80211', 'wireguard', 'amdgpu'])
    with open(root / 'k1' / 'modules.dep', 'a') as dep:
        dep.write('kernel/drivers/bluetooth/btusb.ko.xz:\nkernel/net/bluetooth/bluetooth.ko.xz:\n')
    assert bl.allow_only(conf, record, 'k1', root)['module_allowlist'] == 'learning' and not conf.exists()
    modules = tmp_path / 'modules'
    modules.write_text('radeon 1 40 - Live 0\nr8169 1 0 - Live 0\nsnd_hda_intel 1 2 - Live 0\namdgpu 1 0 - Live 0\n')
    bl.record_allowlist(record, modules, 'k1', root)
    assert oct(record.stat().st_mode & 0o777) == '0o600'
    report = bl.allow_only(conf, record, 'k1', root)
    text = conf.read_text()
    for blocked in ('usb_storage', 'sr_mod', 'cfg80211', 'amdgpu'):
        assert f'install {blocked} /bin/true\n' in text
    for allowed in ('radeon', 'r8169', 'snd_hda_intel', 'wireguard', 'btusb', 'bluetooth'):   # Bluetooth: off, not removed
        assert f'install {allowed} ' not in text
    assert report == {'module_allowlist': 'enforced', 'modules_blocked': 4}


def test_a_new_kernel_allows_only_its_new_names_for_one_boot(tmp_path):
    root, record, conf = tmp_path / 'lib', tmp_path / 'rec.json', tmp_path / 'allow.conf'
    _kernel(root, 'k1', ['radeon', 'snd_hda_codec_realtek', 'usb_storage'])
    _kernel(root, 'k2', ['radeon', 'snd_hda_codec_realtek_lib', 'usb_storage'])
    modules = tmp_path / 'modules'
    modules.write_text('radeon 1 40 - Live 0\nsnd_hda_codec_realtek 1 0 - Live 0\n')
    bl.record_allowlist(record, modules, 'k1', root)
    report = bl.allow_only(conf, record, 'k2', root)
    text = conf.read_text()
    assert report['module_allowlist'] == 'enforced_new_kernel'
    assert 'install usb_storage /bin/true' in text and 'snd_hda_codec_realtek_lib' not in text


def test_the_initramfs_carries_the_same_rules_and_resyncs_only_on_change(tmp_path):
    files = []
    for name in ('satsuma-module-allowlist.conf', 'fwupd-msr.conf'):
        f = tmp_path / name
        f.write_text('install usb_storage /bin/true\n')
        files.append(f)
    calls = []
    runner = lambda cmd, **kw: (calls.append(cmd), subprocess.CompletedProcess(cmd, 0, '', ''))[1]
    state = tmp_path / 'state.json'
    assert bl.sync_initramfs(runner, state, files)['initramfs'] == 'synced_takes_effect_next_boot'
    assert calls[0][:3] == ['/usr/bin/rpm-ostree', 'initramfs-etc', '--force-sync']
    assert f'--track={files[0]}' in calls[0]
    assert bl.sync_initramfs(runner, state, files)['initramfs'] == 'in_sync' and len(calls) == 1
    files[0].write_text('install usb_storage /bin/true\ninstall btusb /bin/true\n')
    bl.sync_initramfs(runner, state, files)
    assert len(calls) == 2
    busy = lambda cmd, **kw: subprocess.CompletedProcess(cmd, 1, '', 'Transaction in progress')
    files[1].write_text('x')
    assert bl.sync_initramfs(busy, state, files)['initramfs'] == 'error'


def test_open_vm_tools_is_blocked_but_other_vm_pieces_are_not():
    """Owner 2026-11-20: "sanal makineyi maskeleme", "open-vm-tools'u engelle"."""
    assert 'open-vm-tools.conf' not in bl.MODULES_LOAD_OVERRIDES     # it only loads fuse (inventory)
    assert set(bl.OPEN_VM_TOOLS_UNITS) == {'vmtoolsd.service', 'vgauthd.service'}
    every = bl.MASKED_UNITS + bl.OPEN_VM_TOOLS_UNITS
    assert not any(u.startswith(('qemu', 'vbox', 'libvirt')) for u in every)


def test_bridged_vm_network_stays_available(tmp_path):
    """Owner 2026-11-20: "bridge bağlantı aktif kalacak"."""
    from satsuma import module_lock
    assert {'bridge', 'tun'} <= set(module_lock.PRELOAD)
    root, record, conf = tmp_path / 'lib', tmp_path / 'rec.json', tmp_path / 'allow.conf'
    _kernel(root, 'k1', ['radeon', 'bridge', 'stp', 'llc', 'tun', 'br_netfilter', 'ebtables'])
    modules = tmp_path / 'modules'
    modules.write_text('radeon 1 40 - Live 0\n')
    bl.record_allowlist(record, modules, 'k1', root)
    bl.allow_only(conf, record, 'k1', root)
    text = conf.read_text()
    for kept in ('bridge', 'stp', 'llc', 'tun'):
        assert f'install {kept} ' not in text
    assert 'install br_netfilter /bin/true' in text and 'install ebtables /bin/true' in text
