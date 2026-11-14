"""Audit NetworkManager connection profiles for ways into the middle.

A profile can quietly hand traffic to someone else: a proxy, a VPN, a
static route, or DNS servers of its own. Profiles are read through nmcli
(secrets are never requested) and every profile is inventoried, so a new
or removed profile shows up in the log. Reported per profile:

* VPN, WireGuard, tun and tap profiles: high. All traffic or chosen
  networks go through them.
* A proxy (manual or auto-configured): high.
* Static routes: high, critical when one covers a watched DNS resolver.
* DNS servers outside the pinned set: high. With servers pinned, a
  profile that still accepts DNS from DHCP: medium.

Taken from the yeni-yazim branch (netd/profiles.py).

NetworkManager bağlantı profillerini araya girme yollarına karşı denetler
(yeni-yazim dalından). Profiller nmcli ile okunur, parolalar istenmez.
VPN, WireGuard, tun ve tap profilleri yüksek; proxy yüksek; sabit rotalar
yüksek, izlenen bir DNS sunucusunu kapsayan rota kritik; sabitlenen
sunucular dışındaki DNS yüksek; sunucular sabitliyken DHCP'den DNS kabul
eden profil orta önemdedir.
"""
import ipaddress
import subprocess

from .route_watch import PUBLIC_RESOLVERS

NMCLI = '/usr/bin/nmcli'
_ENV = {'PATH': '/usr/sbin:/usr/bin', 'LC_ALL': 'C'}
TUNNEL_TYPES = {'vpn', 'wireguard', 'tun', 'tap'}
FIELDS = ('connection.id', 'connection.uuid', 'connection.type', 'connection.autoconnect',
          'connection.interface-name', 'proxy.method', 'proxy.pac-url',
          'ipv4.method', 'ipv4.dns', 'ipv4.ignore-auto-dns', 'ipv4.routes', 'ipv4.gateway',
          'ipv6.method', 'ipv6.dns', 'ipv6.ignore-auto-dns', 'ipv6.routes', 'ipv6.gateway',
          'vpn.service-type')


def _pairs(text):
    """Parse `nmcli -t` "key:value" lines; values escape ':' as '\\:'."""
    values = {}
    for line in text.splitlines():
        key, sep, value = line.partition(':')
        if sep:
            values[key] = value.replace('\\:', ':').replace('\\\\', '\\')
    return values


def _nmcli(args, runner):
    try:
        result = runner([NMCLI, '-t', *args], capture_output=True, text=True, timeout=5, env=_ENV)
    except (OSError, subprocess.SubprocessError):
        return None
    return result.stdout if result.returncode == 0 else None


def read_profiles(runner=subprocess.run):
    """Every profile's audited settings; None when NetworkManager cannot be asked."""
    listing = _nmcli(['-f', 'UUID', 'connection', 'show'], runner)
    if listing is None:
        return None
    profiles = []
    for uuid in listing.split():
        text = _nmcli(['-f', ','.join(FIELDS), 'connection', 'show', 'uuid', uuid], runner)
        if text is not None:
            profiles.append(_pairs(text))
    return profiles


def _addresses(value):
    found = set()
    for item in (value or '').replace(' ', ',').split(','):
        try:
            found.add(ipaddress.ip_address(item.split('/', 1)[0]))
        except ValueError:
            pass
    return found


def _route_targets(value):
    """Destinations of nmcli's route list, e.g. "{ ip = 8.8.8.8/32, nh = 192.168.1.66 }"."""
    targets = []
    for token in (value or '').replace('{', ' ').replace('}', ' ').replace(',', ' ').split():
        try:
            targets.append(ipaddress.ip_network(token, strict=False))
        except ValueError:
            pass
    return targets


def _is_set(value):
    return value not in (None, '', '--')


def audit(profile, pinned=frozenset(), resolvers=PUBLIC_RESOLVERS):
    name = profile.get('connection.id')
    base = {'profile': name, 'uuid': profile.get('connection.uuid')}
    kind = profile.get('connection.type') or ''
    findings = [{'code': 'network_profile', 'severity': 'info', **base, 'type': kind,
                 'autoconnect': profile.get('connection.autoconnect'),
                 'interface': profile.get('connection.interface-name')}]
    if kind in TUNNEL_TYPES:
        findings.append({'code': 'network_profile_tunnel', 'severity': 'high', **base, 'type': kind,
                         'service': profile.get('vpn.service-type')})
    if profile.get('proxy.method') not in (None, '', '--', 'none'):
        findings.append({'code': 'network_profile_proxy', 'severity': 'high', **base,
                         'method': profile.get('proxy.method'), 'pac_url': profile.get('proxy.pac-url')})
    watched = set(resolvers) | set(pinned)
    for family in ('ipv4', 'ipv6'):
        routes = profile.get(family + '.routes')
        if _is_set(routes):
            covered = sorted(str(a) for net in _route_targets(routes) for a in watched
                             if a.version == net.version and a in net and net.prefixlen > 1)
            findings.append({'code': 'network_profile_routes', 'severity': 'critical' if covered else 'high',
                             **base, 'family': family, 'routes': routes, 'resolvers': covered})
        servers = _addresses(profile.get(family + '.dns'))
        if pinned:
            for server in sorted(servers - set(pinned), key=str):
                findings.append({'code': 'network_profile_dns_not_pinned', 'severity': 'high', **base,
                                 'server': str(server)})
            method = profile.get(family + '.method')
            if (method in ('auto', 'dhcp') and profile.get(family + '.ignore-auto-dns') != 'yes'
                    and kind not in TUNNEL_TYPES):
                findings.append({'code': 'network_profile_accepts_dhcp_dns', 'severity': 'medium', **base,
                                 'family': family})
    return findings


def findings(pinned=frozenset(), read=read_profiles):
    profiles = read()
    if profiles is None:
        return []
    found = []
    for profile in profiles:
        found += audit(profile, pinned)
    return found
