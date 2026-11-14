"""Shared device decision (owner's decision 2026-11-11). Ortak aygıt kararı."""
import pytest

from satsuma import device_policy as dp


@pytest.mark.parametrize('device,kind', [
    ({'id': 'BTH\\1', 'class': 'Bluetooth', 'name': 'Intel(R) Wireless Bluetooth(R)'}, 'bluetooth'),
    ({'id': 'BTHENUM\\2', 'class': 'BTHLEDevice', 'name': 'Bluetooth LE Generic Attribute Service'}, 'bluetooth'),
    ({'id': 'SWD\\3', 'class': 'SmartCardReader', 'name': 'Microsoft Usbccid Smartcard Reader'}, 'smart_card'),
    ({'id': 'USB\\4', 'class': 'Net', 'name': 'Qualcomm WWAN Adapter'}, 'wwan'),
    ({'id': 'SWD\\MSRRAS\\MS_PPPOEMINIPORT', 'class': 'Net', 'name': 'WAN Miniport (PPPOE)'}, 'pppoe_vpn_ipsec'),
    ({'id': 'SWD\\MSRRAS\\MS_AGILEVPNMINIPORT', 'class': 'Net', 'name': 'WAN Miniport (IKEv2)'}, 'pppoe_vpn_ipsec'),
    ({'id': 'ROOT\\NET\\0001', 'class': 'Net', 'name': 'TAP-Windows Adapter V9'}, 'pppoe_vpn_ipsec'),
    ({'id': '{5d6}\\VWIFIMP', 'class': 'Net', 'name': 'Microsoft Wi-Fi Direct Virtual Adapter'}, 'wireless_transmitter'),
    ({'id': 'ROOT\\VMS_MP\\0000', 'class': 'Net', 'name': 'Hyper-V Virtual Ethernet Adapter'}, 'virtual_machine'),
    ({'id': 'ROOT\\VBOX', 'class': 'Net', 'name': 'VirtualBox Host-Only Ethernet Adapter', 'service': 'VBoxNetAdp'},
     'virtual_machine'),
])
def test_owner_listed_devices_are_named(device, kind):
    assert dp.category(device) == kind
    assert dp.decide(device)['disable'] is True


@pytest.mark.parametrize('device', [
    {'id': 'PCI\\1', 'class': 'Net', 'name': 'Intel(R) Ethernet Connection I219-V'},
    {'id': 'USB\\2', 'class': 'Keyboard', 'name': 'HID Keyboard Device'},
    {'id': 'SWD\\MSRRAS\\MS_NDISWANIP', 'class': 'Net', 'name': 'WAN Miniport (IP)'},
    {'id': 'PCI\\3', 'class': 'Net', 'name': 'Intel(R) Wi-Fi 6 AX201 160MHz'},
])
def test_ordinary_devices_are_allowed(device):
    assert dp.decide(device) is None


def test_the_internet_adapter_approved_devices_and_windows_essentials_are_never_disabled():
    nic = {'id': 'VMBUS\\NIC', 'class': 'Net', 'name': 'Microsoft Hyper-V Network Adapter', 'service': 'netvsc'}
    assert dp.decide(nic, internet_adapters={'vmbus\\nic'}) == {
        'category': 'virtual_machine', 'id': 'VMBUS\\NIC', 'name': nic['name'], 'disable': False,
        'kept': 'internet_adapter'}
    disk = {'id': 'VMBUS\\DISK', 'class': 'SCSIAdapter', 'name': 'Microsoft Hyper-V SCSI Controller', 'service': 'storvsc'}
    assert dp.decide(disk)['kept'] == 'windows_needs_it'
    bt = {'id': 'BTH\\1', 'class': 'Bluetooth', 'name': 'Bluetooth Radio'}
    assert dp.decide(bt, approved={'bth\\1'})['kept'] == 'approved_by_owner'
