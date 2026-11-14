"""Addresses Satsuma never blocks on Windows, because blocking them cuts the user off.

* this machine's default gateway (the modem) and the DNS servers it uses;
* loopback, unspecified, multicast and link-local addresses;
* the peers of the remote support programs the owner works with
  (TeamViewer, AnyDesk): outgoing support must keep working.

Nothing here allows incoming connections; it only keeps Satsuma from cutting
its own way out.

Satsuma'nın Windows'ta asla engellemediği adresler; engellemek kullanıcıyı
keser: varsayılan ağ geçidi (modem) ve kullanılan DNS sunucuları; geri
döngü, belirsiz, çoklu yayın ve bağlantı yerel adresleri; sahibinin çalıştığı
uzak destek programlarının (TeamViewer, AnyDesk) uçları. Buradaki hiçbir şey
gelen bağlantıya izin vermez; yalnızca Satsuma'nın kendi çıkış yolunu
kesmesini önler.
"""
import ipaddress
import json
import subprocess

from .firewall import run_powershell, safe_run

SUPPORT_PROGRAMS = frozenset(('teamviewer.exe', 'teamviewer_service.exe', 'tv_w32.exe', 'tv_x64.exe',
                              'anydesk.exe'))
INFRASTRUCTURE_SCRIPT = (
    "$g = @(Get-NetRoute -AddressFamily IPv4 -DestinationPrefix '0.0.0.0/0' -ErrorAction SilentlyContinue "
    "| ForEach-Object { $_.NextHop }); "
    "$d = @(Get-DnsClientServerAddress -AddressFamily IPv4 -ErrorAction SilentlyContinue "
    "| ForEach-Object { $_.ServerAddresses }); "
    "@{gateways=$g; dns=$d} | ConvertTo-Json -Compress")


def _valid(values):
    found = set()
    for value in values or []:
        try:
            found.add(str(ipaddress.ip_address(str(value))))
        except ValueError:
            continue
    found.discard('0.0.0.0')
    return found


def infrastructure(runner=safe_run):
    """Gateway and DNS server addresses of this machine, read from Windows."""
    data = json.loads(run_powershell(INFRASTRUCTURE_SCRIPT, runner) or '{}')
    return _valid(data.get('gateways')) | _valid(data.get('dns'))


def support_peers(connections):
    """Remote addresses currently held by TeamViewer or AnyDesk."""
    return {c['remote'] for c in connections if (c.get('process') or '').lower() in SUPPORT_PROGRAMS}


def protected_reason(ip, infrastructure_ips, support_ips):
    """Why ``ip`` must not be blocked, or None."""
    address = ipaddress.ip_address(ip)
    if address.is_loopback or address.is_unspecified or address.is_multicast or address.is_link_local:
        return 'protected_address'
    if str(address) in infrastructure_ips:
        return 'gateway_or_dns'
    if str(address) in support_ips:
        return 'remote_support'
    return None
