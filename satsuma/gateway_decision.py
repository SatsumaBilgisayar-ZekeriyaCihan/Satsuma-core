"""Shared man-in-the-middle decision: compare the network with the approved modem and say what to write back.

Owner's decision 2026-11-11: the modem approved at installation is pinned
(its MAC address as a permanent neighbour entry) and every change to the
default route, the DNS servers or the proxy is written back at once and
recorded. This module only decides; reading and writing are platform
specific (Windows: satsuma_win.gateway). Linux keeps its read-only watch
until its own writer is built (docs/PLATFORM-PARITY.md).

Severity follows the Linux network identity guard: the approved gateway
address answering from another MAC is ARP spoofing (critical); another or an
additional default gateway is high; a proxy or DNS change is high; an
approved gateway whose MAC is not visible is a warning, not a change.

Ortak ortadaki adam kararı: ağı onaylı modemle karşılaştırır ve neyin geri
yazılacağını söyler. Sahibinin kararı 2026-11-11: kurulumda onaylanan
modem sabitlenir (MAC adresi kalıcı komşu kaydı olarak), varsayılan rota,
DNS sunucuları ya da proxy her değiştiğinde hemen geri yazılır ve
kaydedilir. Bu modül yalnızca karar verir; okuma ve yazma platforma
özgüdür. Önem dereceleri Linux ağ kimliği bekçisiyle aynıdır: onaylı ağ
geçidi adresinin başka bir MAC'ten yanıt vermesi ARP sahteciliğidir
(kritik); başka ya da ek varsayılan ağ geçidi yüksek; proxy ya da DNS
değişikliği yüksek; onaylı ağ geçidinin MAC'i görünmüyorsa değişiklik
değil, uyarıdır.
"""
import ipaddress
import re

MAC = re.compile(r'^(?:[0-9a-f]{2}-){5}[0-9a-f]{2}$')


def mac(value):
    """A MAC address in one form (lower case, dashes); None when it is not one."""
    text = str(value or '').strip().lower().replace(':', '-')
    if not MAC.match(text) or text in ('00-00-00-00-00-00', 'ff-ff-ff-ff-ff-ff'):
        return None
    return text


def approve(observation):
    """The approved identity taken from one observation: the gateway, its MAC and the interface."""
    gateways = observation.get('gateways') or []
    if len(gateways) != 1:
        raise ValueError('exactly one default gateway is needed to approve the modem, found %d' % len(gateways))
    gateway = gateways[0]
    address = str(ipaddress.ip_address(gateway['ip']))
    hardware = mac(observation.get('neighbours', {}).get(address))
    if hardware is None:
        raise ValueError('the gateway MAC address is not visible yet')
    return {'gateway': address, 'mac': hardware, 'interface': gateway.get('interface')}


def decide(approved, observation, dns_servers=(), allowed_proxies=()):
    """Findings and the write-backs that undo them."""
    findings, actions = [], []
    gateway, wanted_mac = approved['gateway'], approved['mac']
    seen_mac = mac(observation.get('neighbours', {}).get(gateway))
    if seen_mac is None:
        findings.append({'kind': 'gateway_mac_unobserved', 'severity': 'warning', 'gateway': gateway})
        actions.append({'action': 'pin_gateway_mac', 'gateway': gateway, 'mac': wanted_mac,
                        'interface': approved.get('interface')})
    elif seen_mac != wanted_mac:
        findings.append({'kind': 'arp_spoofing', 'severity': 'critical', 'gateway': gateway,
                         'expected_mac': wanted_mac, 'seen_mac': seen_mac})
        actions.append({'action': 'pin_gateway_mac', 'gateway': gateway, 'mac': wanted_mac,
                        'interface': approved.get('interface')})
    elif not observation.get('pinned', {}).get(gateway):
        actions.append({'action': 'pin_gateway_mac', 'gateway': gateway, 'mac': wanted_mac,
                        'interface': approved.get('interface')})
    others = sorted({g['ip'] for g in observation.get('gateways') or () if g['ip'] != gateway})
    for other in others:
        findings.append({'kind': 'default_gateway_added', 'severity': 'high', 'gateway': other})
        actions.append({'action': 'remove_default_route', 'gateway': other})
    if gateway not in {g['ip'] for g in observation.get('gateways') or ()}:
        findings.append({'kind': 'approved_gateway_missing', 'severity': 'high', 'gateway': gateway})
        actions.append({'action': 'restore_default_route', 'gateway': gateway, 'interface': approved.get('interface')})
    if dns_servers:
        wrong = sorted(set(observation.get('dns') or ()) - set(dns_servers))
        if wrong:
            findings.append({'kind': 'dns_server_changed', 'severity': 'high', 'servers': wrong})
            actions.append({'action': 'lock_dns'})
    proxies = sorted(p for p in observation.get('proxies') or () if p not in allowed_proxies)
    if proxies:
        findings.append({'kind': 'proxy_set', 'severity': 'high', 'proxies': proxies})
        actions.append({'action': 'remove_proxy'})
    return findings, actions
