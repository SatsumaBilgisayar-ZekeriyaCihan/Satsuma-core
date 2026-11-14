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
        assert f'install {module} /bin/false\n' in text
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
