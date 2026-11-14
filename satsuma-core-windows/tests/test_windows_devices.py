"""Windows device guard: not-allowed devices are disabled at once (owner's decision 2026-11-11).

Windows aygıt bekçisi: izin verilmeyen aygıtlar hemen kapatılır.
"""
import json
from types import SimpleNamespace

from satsuma_win import devices, firewall

DEVICES = [
    {'id': 'BTH\\RADIO', 'class': 'Bluetooth', 'name': 'Intel Wireless Bluetooth', 'service': 'BTHUSB', 'code': 0},
    {'id': 'SWD\\MSRRAS\\MS_PPPOEMINIPORT', 'class': 'Net', 'name': 'WAN Miniport (PPPOE)', 'service': 'RasPppoe',
     'code': 0},
    {'id': 'VMBUS\\NIC', 'class': 'Net', 'name': 'Microsoft Hyper-V Network Adapter', 'service': 'netvsc', 'code': 0},
    {'id': 'VMBUS\\DISK', 'class': 'SCSIAdapter', 'name': 'Microsoft Hyper-V SCSI Controller', 'service': 'storvsc',
     'code': 0},
    {'id': 'PCI\\ETH', 'class': 'Net', 'name': 'Intel Ethernet', 'service': 'e1d', 'code': 0},
]


class Machine:
    def __init__(self, fails=()):
        self.devices = [dict(d) for d in DEVICES]
        self.fails, self.disabled = set(fails), []

    def __call__(self, argv, **kwargs):
        assert argv[:-1] == firewall.POWERSHELL
        script = argv[-1]
        if 'Disable-PnpDevice' in script:
            device_id = script.split("-InstanceId '")[1].split("'")[0]
            if device_id in self.fails:
                return SimpleNamespace(returncode=1, stdout='', stderr='Access denied')
            self.disabled.append(device_id)
            for d in self.devices:
                if d['id'] == device_id:
                    d['code'] = 22
            return SimpleNamespace(returncode=0, stdout=json.dumps({'code': 22}), stderr='')
        return SimpleNamespace(returncode=0, stdout=json.dumps({'devices': self.devices, 'internet': ['VMBUS\\NIC']}),
                               stderr='')


class Key:
    def sign(self, data):
        return 'S' + data.hex()

    def verify(self, data, signature):
        return signature == 'S' + data.hex()


def test_listed_devices_are_disabled_internet_and_windows_essentials_are_kept(tmp_path):
    machine = Machine()
    events = []
    g = devices.Devices(tmp_path, Key(), machine, lambda k, **f: events.append((k, f)) or f)
    g.check()
    assert machine.disabled == ['BTH\\RADIO', 'SWD\\MSRRAS\\MS_PPPOEMINIPORT']
    kinds = {f['id']: k for k, f in events}
    assert kinds['VMBUS\\NIC'] == 'device_not_allowed_kept' and kinds['VMBUS\\DISK'] == 'device_not_allowed_kept'
    assert 'PCI\\ETH' not in kinds
    events.clear()
    g.check()
    assert events == [] and machine.disabled == ['BTH\\RADIO', 'SWD\\MSRRAS\\MS_PPPOEMINIPORT']


def test_an_approved_device_stays_enabled_and_a_forged_approval_does_not(tmp_path):
    devices.approve_device(tmp_path, 'BTH\\RADIO', Key())
    machine = Machine()
    devices.Devices(tmp_path, Key(), machine).check()
    assert 'BTH\\RADIO' not in machine.disabled
    (tmp_path / devices.APPROVED).write_text(json.dumps([{'id': 'BTH\\RADIO', 'signature': 'forged'}]))
    machine = Machine()
    devices.Devices(tmp_path, Key(), machine).check()
    assert 'BTH\\RADIO' in machine.disabled


def test_a_failed_disable_is_recorded(tmp_path):
    events = []
    g = devices.Devices(tmp_path, Key(), Machine(fails={'BTH\\RADIO'}), lambda k, **f: events.append(k) or f)
    g.check()
    assert 'device_disable_failed' in events and g.counts['disable_failed'] == 1


def test_device_ids_cannot_break_out_of_the_powershell_string():
    assert "'BTH\\X''; calc; ''Y'" in devices.disable_script("BTH\\X'; calc; 'Y")


def test_uninstall_enables_exactly_what_satsuma_disabled(tmp_path):
    machine = Machine()
    devices.Devices(tmp_path, Key(), machine).check()
    calls = []
    run = lambda argv, **kw: calls.append(argv[-1]) or SimpleNamespace(returncode=0, stdout='', stderr='')
    result = devices.restore(tmp_path, run)
    assert result['devices'] == ['BTH\\RADIO', 'SWD\\MSRRAS\\MS_PPPOEMINIPORT']
    assert all('Enable-PnpDevice' in c for c in calls) and len(calls) == 2
    assert devices.restore(tmp_path, run)['status'] == 'NOTHING_DISABLED'


def test_a_device_that_refuses_is_disabled_with_pnputil_at_the_next_restart(tmp_path):
    events = []
    def run(argv, **kw):
        script = argv[-1]
        if 'Disable-PnpDevice' in script:
            return SimpleNamespace(returncode=0, stdout=json.dumps({'code': 0, 'how': 'pnputil', 'exit': 3010}),
                                   stderr='')
        return SimpleNamespace(returncode=0, stdout=json.dumps({'devices': [DEVICES[0]], 'internet': []}), stderr='')
    g = devices.Devices(tmp_path, Key(), run, lambda k, **f: events.append(k) or f)
    g.check()
    g.check()
    assert events == ['device_disabled_after_restart']
    assert 'pnputil.exe /disable-device' in devices.disable_script('USB\\VID_2357&PID_0604\\E848B8C82000')
