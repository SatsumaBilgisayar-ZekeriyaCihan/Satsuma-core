"""Shared device decision: which devices are not allowed and are disabled (owner's decision 2026-11-11).

The owner's list of devices that are not allowed: virtual machine devices,
mobile broadband (WWAN), PPPoE, VPN and IPsec adapters, smart card readers,
wireless transmitters (Wi-Fi Direct, Miracast, infrared) and Bluetooth
devices. Such a device is disabled at once and recorded; it is enabled again
only when the owner approves it in the panel with the administrator password
(the approval is signed with the machine key). Two limits keep the machine
usable: the network adapter that reaches the approved modem (the internet
connection, also needed for remote support) is never disabled, only
recorded; disks, disk controllers, processors, displays and system buses are
never disabled, because Windows would not start. This module only decides;
reading and disabling are platform specific (Windows: satsuma_win.devices).

Ortak aygıt kararı: hangi aygıtlara izin verilmez ve kapatılır (sahibinin
kararı 2026-11-11). Sahibinin izin vermediği aygıtlar: sanal makine
aygıtları, mobil geniş bant (WWAN), PPPoE, VPN ve IPsec bağdaştırıcıları,
akıllı kart okuyucuları, kablosuz aktarıcılar (Wi-Fi Direct, Miracast,
kızılötesi) ve Bluetooth aygıtları. Böyle bir aygıt hemen kapatılır ve
kaydedilir; ancak sahibi panelde yönetici parolasıyla onaylarsa yeniden
açılır (onay makine anahtarıyla imzalanır). İki sınır makineyi kullanılır
tutar: onaylı modeme ulaşan ağ bağdaştırıcısı (internet bağlantısı, uzak
destek için de gerekli) asla kapatılmaz, yalnızca kaydedilir; diskler, disk
denetleyicileri, işlemciler, ekranlar ve sistem veri yolları asla kapatılmaz,
çünkü Windows açılmaz. Bu modül yalnızca karar verir.
"""
import re

NEVER_DISABLED_CLASSES = frozenset(c.lower() for c in (
    'System', 'SCSIAdapter', 'HDC', 'DiskDrive', 'Volume', 'VolumeSnapshot', 'Processor', 'Computer',
    'Display', 'Monitor', 'SoftwareDevice', 'Firmware', 'SecurityDevices', 'Keyboard', 'Mouse'))

CATEGORIES = (
    ('bluetooth', lambda d: d['class'] in ('bluetooth', 'bthle', 'bthenum') or 'bluetooth' in d['name']),
    ('smart_card', lambda d: d['class'] in ('smartcardreader', 'smartcard', 'smartcardfilter')
     or 'smart card' in d['name'] or 'akıllı kart' in d['name']),
    ('wwan', lambda d: d['class'] in ('modem', 'mobilebroadband')
     or re.search(r'\bwwan\b|mobile broadband|mobil geniş bant', d['name']) is not None),
    ('pppoe_vpn_ipsec', lambda d: re.search(r'wan miniport \((pppoe|ikev2|l2tp|pptp|sstp|gre)\)'
                                            r'|tap-windows|wintun|wireguard|openvpn|ipsec|\bvpn\b', d['name']) is not None),
    ('wireless_transmitter', lambda d: re.search(r'wi-fi direct|wifi direct|miracast|infrared|kızılötesi'
                                                 r'|hosted network', d['name']) is not None
     or d['class'] in ('infrared',)),
    ('virtual_machine', lambda d: d['service'] in ('vmbus', 'vmbushid', 'netvsc', 'storvsc', 'vmgid', 'hypervideo',
                                                    'vboxguest', 'vboxnetadp', 'vboxnetlwf', 'vboxusb', 'vmci',
                                                    'vmhgfs', 'vmx86', 'vmnetadapter', 'vmnetbridge', 'vmnetuserif')
     or re.search(r'hyper-v|vmware|virtualbox|virtual machine bus|parallels', d['name']) is not None),
)


def normalise(device):
    return {'id': str(device.get('id') or ''), 'class': str(device.get('class') or '').lower(),
            'name': str(device.get('name') or '').lower(), 'service': str(device.get('service') or '').lower()}


def category(device):
    """The not-allowed category a device belongs to, or None."""
    d = normalise(device)
    for name, test in CATEGORIES:
        if test(d):
            return name
    return None


def decide(device, approved=frozenset(), internet_adapters=frozenset()):
    """None for an allowed device; otherwise the category and whether it is disabled now."""
    kind = category(device)
    if kind is None:
        return None
    device_id = str(device.get('id') or '')
    result = {'category': kind, 'id': device_id, 'name': device.get('name'), 'disable': True}
    if device_id.upper() in {a.upper() for a in approved}:
        result.update(disable=False, kept='approved_by_owner')
    elif device_id.upper() in {a.upper() for a in internet_adapters}:
        result.update(disable=False, kept='internet_adapter')
    elif normalise(device)['class'] in NEVER_DISABLED_CLASSES:
        result.update(disable=False, kept='windows_needs_it')
    return result
