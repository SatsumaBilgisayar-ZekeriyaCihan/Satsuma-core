"""Windows MITM guard: pin the approved modem; write back routes, DNS and proxy (owner's decision 2026-11-11).

Windows MITM bekçisi: onaylı modem sabitlenir; rota, DNS ve proxy geri yazılır.
"""
import json
from types import SimpleNamespace

import pytest

from satsuma_win import dns, firewall, gateway

ROUTES = """===========================================================================
IPv4 Yönlendirme Tablosu
===========================================================================
Etkin Yollar:
Ağ Hedefi        Ağ Maskesi         Ağ Geçidi        Arabirim     Ölçüm
          0.0.0.0          0.0.0.0      192.168.1.1    192.168.1.5     25
{extra}        127.0.0.0        255.0.0.0         Bağlantıda         127.0.0.1    331
===========================================================================
Kalıcı Yollar:
  Ağ Adresi          Ağ Maskesi  Ağ Geçidi Adresi  Ölçüm
          0.0.0.0          0.0.0.0      10.9.9.9  Varsayılan
"""
ARP = """
Arabirim: 192.168.1.5 --- 0xc
  İnternet Adresi       Fiziksel Adres        Tür
  192.168.1.1           {mac}     dinamik
  192.168.1.255         ff-ff-ff-ff-ff-ff     statik
"""


class Machine:
    """Windows answering route, arp and PowerShell; records every command."""
    def __init__(self, mac='aa-bb-cc-dd-ee-ff', extra='', dns_servers=dns.SERVERS, proxies=()):
        self.mac, self.extra, self.dns, self.proxies, self.calls = mac, extra, list(dns_servers), list(proxies), []

    def __call__(self, argv, **kwargs):
        self.calls.append(argv)
        out = ''
        if argv[0] == 'route.exe' and argv[1] == 'print':
            out = ROUTES.format(extra=self.extra)
        elif argv[0] == 'route.exe' and argv[1] == 'delete':
            self.extra = ''
        elif argv[0] == 'arp.exe':
            out = ARP.format(mac=self.mac)
        elif argv[:-1] == firewall.POWERSHELL:
            script = argv[-1]
            if 'New-NetNeighbor' in script:
                self.mac = 'aa-bb-cc-dd-ee-ff'
                out = json.dumps({'state': 'Permanent', 'mac': 'AA-BB-CC-DD-EE-FF'})
            elif 'Set-DnsClientServerAddress' in script:
                self.dns = list(dns.SERVERS)
                out = json.dumps({'interfaces': [{'index': 12, 'servers': list(dns.SERVERS)}], 'resolves': True})
            elif 'winhttp reset proxy' in script:
                self.proxies = []
                out = json.dumps({'proxies': [], 'dns': self.dns})
            elif 'WinHttpSettings' in script:
                out = json.dumps({'proxies': self.proxies, 'dns': self.dns})
        return SimpleNamespace(returncode=0, stdout=out, stderr='')


class Key:
    def sign(self, data):
        return 'S' + data.hex()

    def verify(self, data, signature):
        return signature == 'S' + data.hex()


def guard(tmp_path, machine):
    events = []
    g = gateway.Gateway(tmp_path, Key(), machine, lambda kind, **f: events.append((kind, f)) or f, clock=lambda: 0.0)
    return g, events


def test_turkish_windows_tables_are_read_by_numbers_only():
    assert gateway.parse_routes(ROUTES.format(extra='')) == [
        {'ip': '192.168.1.1', 'interface': '192.168.1.5', 'metric': 25}]
    assert gateway.parse_neighbours(ARP.format(mac='AA-BB-CC-DD-EE-FF'))['192.168.1.1'] == 'aa-bb-cc-dd-ee-ff'


def test_the_modem_is_approved_signed_and_a_hand_edited_approval_is_ignored(tmp_path):
    g, _ = guard(tmp_path, Machine())
    assert g.approve_now() == {'gateway': '192.168.1.1', 'mac': 'aa-bb-cc-dd-ee-ff', 'interface': '192.168.1.5'}
    assert gateway.Gateway(tmp_path, Key(), Machine()).load() == g.approved
    row = json.loads((tmp_path / gateway.APPROVED).read_text())
    row['mac'] = '11-22-33-44-55-66'
    (tmp_path / gateway.APPROVED).write_text(json.dumps(row))
    assert gateway.Gateway(tmp_path, Key(), Machine()).load() is None


def test_arp_spoofing_is_recorded_and_the_approved_mac_is_pinned_back(tmp_path):
    machine = Machine()
    g, events = guard(tmp_path, machine)
    g.approve_now()
    g.check()
    assert any('New-NetNeighbor' in c[-1] for c in machine.calls if c[:-1] == firewall.POWERSHELL)
    machine.mac = '66-55-44-33-22-11'
    events.clear()
    g.check()
    kinds = [k for k, _ in events]
    assert kinds == ['mitm_arp_spoofing', 'mitm_written_back'] and events[0][1]['severity'] == 'critical'
    assert machine.mac == 'aa-bb-cc-dd-ee-ff'


def test_an_extra_default_route_dns_change_and_proxy_are_written_back(tmp_path):
    machine = Machine()
    g, events = guard(tmp_path, machine)
    g.approve_now()
    g.check()
    machine.extra = '          0.0.0.0          0.0.0.0      192.168.1.66    192.168.1.5     5\n'
    machine.dns = ['6.6.6.6']
    machine.proxies = ['user:S-1-5-21-1:10.0.0.5:8080']
    events.clear()
    g.slow_at = None
    g.check()
    kinds = [k for k, _ in events]
    assert kinds[:3] == ['mitm_default_gateway_added', 'mitm_dns_server_changed', 'mitm_proxy_set']
    assert kinds.count('mitm_written_back') == 3
    assert ['route.exe', 'delete', '0.0.0.0', 'mask', '0.0.0.0', '192.168.1.66'] in machine.calls
    assert machine.dns == list(dns.SERVERS) and machine.proxies == []


@pytest.mark.parametrize('bad', [("192.168.1.1'; Remove-Item C:\\ -Recurse; '", 'aa-bb-cc-dd-ee-ff', '192.168.1.5'),
                                 ('192.168.1.1', "aa-bb-cc-dd-ee-ff'; calc; '", '192.168.1.5')])
def test_nothing_but_validated_addresses_reach_powershell(bad):
    with pytest.raises(ValueError):
        gateway.pin_script(*bad)


def test_uninstall_removes_the_pinned_entry(tmp_path):
    machine = Machine()
    g, _ = guard(tmp_path, machine)
    g.approve_now()
    calls = []
    def run(argv, **kw):
        calls.append(argv[-1])
        return SimpleNamespace(returncode=0, stdout='{"removed": 1}', stderr='')
    assert gateway.unpin(tmp_path, run) == {'ok': True, 'status': 'UNPINNED', 'gateway': '192.168.1.1', 'removed': 1}
    assert "'192.168.1.1'" in calls[0] and 'Remove-NetNeighbor' in calls[0]
    assert gateway.unpin(tmp_path / 'none', run)['status'] == 'NOTHING_PINNED'
