"""Watch routing tables and policy rules for loopback and interception tricks.

Things that look harmless in `ip route` but redirect traffic:

* A route for 127.0.0.0/8 or ::1 through a real interface: loopback
  traffic leaves the machine, or outside traffic is accepted as local.
* A "local" route for an address this machine does not own, e.g.
  `ip route add local 8.8.8.8 dev lo`: connections to that server are
  silently delivered to whatever program listens here.
* Extra policy rules (`ip rule`) that send traffic to another table.
* A targeted route for a public DNS resolver (1.1.1.1, 8.8.8.8, 9.9.9.9,
  OpenDNS, or a server pinned in dns.json), e.g.
  `ip route add 8.8.8.8 via 192.168.1.66`: queries meant for the
  resolver go to whoever sits at that gateway. Only routes at least /16
  (IPv4) or /32 (IPv6) long count as targeted, so a VPN's 0.0.0.0/1 and
  128.0.0.0/1 are not reported. A blackhole route only blocks the
  resolver and is reported at info level.

Normal entries are not reported. In particular the kernel always creates
`broadcast 127.255.255.255 dev lo` in the local table; it is only
reported if it points at an interface other than lo.

Taken from the yeni-yazim branch (netd/routes.py). The upstream of
Satsuma's own DNS filter (dns_policy) is watched like the public
resolvers.

Yönlendirme tablolarını ve politika kurallarını loopback ve araya girme
hilelerine karşı izler (yeni-yazim dalından). Gerçek bir arayüzden geçen
127.0.0.0/8 rotası, bu makineye ait olmayan bir adres için "local" rota
(ör. ip route add local 8.8.8.8 dev lo), fazladan ip rule kayıtları ve
bir DNS sunucusuna özel rota (ör. ip route add 8.8.8.8 via 192.168.1.66)
bildirilir. Varsayılan rotanın değişmesi orta önemdedir. Satsuma DNS
filtresinin üst sunucusu da izlenir.
"""
import ipaddress
import json
import subprocess

IP = '/usr/bin/ip'
_ENV = {'PATH': '/usr/sbin:/usr/bin', 'LC_ALL': 'C'}
LOOPBACK_NETS = (ipaddress.ip_network('127.0.0.0/8'), ipaddress.ip_network('::1/128'))
DEFAULT_RULE_TABLES = {'local', 'main', 'default'}
PUBLIC_RESOLVERS = tuple(ipaddress.ip_address(a) for a in (
    '1.1.1.1', '1.0.0.1', '2606:4700:4700::1111', '2606:4700:4700::1001',      # Cloudflare
    '8.8.8.8', '8.8.4.4', '2001:4860:4860::8888', '2001:4860:4860::8844',      # Google
    '9.9.9.9', '149.112.112.112', '2620:fe::fe', '2620:fe::9',                 # Quad9
    '208.67.222.222', '208.67.220.220', '2620:119:35::35', '2620:119:53::53',  # OpenDNS
))
_TARGETED_PREFIX = {4: 16, 6: 32}
_KEEP = ('type', 'dst', 'gateway', 'dev', 'table', 'protocol', 'scope', 'prefsrc')


def local_addresses(runner=subprocess.run):
    """Addresses this machine owns; a "local" route for one of them is normal."""
    try:
        result = runner([IP, '-j', 'address', 'show'], capture_output=True, text=True, timeout=5, env=_ENV)
        interfaces = json.loads(result.stdout or '[]') if result.returncode == 0 else None
    except (OSError, subprocess.SubprocessError, ValueError):
        interfaces = None
    if interfaces is None:
        return None
    found = set()
    for interface in interfaces:
        for entry in interface.get('addr_info', []):
            try:
                found.add(ipaddress.ip_address(entry['local']))
            except (KeyError, ValueError):
                pass
    return frozenset(found)


def _network(dst):
    if dst in (None, 'default'):
        return None
    try:
        return ipaddress.ip_network(dst, strict=False)
    except ValueError:
        return None


def _in_loopback(network):
    return any(network.version == net.version and network.subnet_of(net) for net in LOOPBACK_NETS)


def snapshot(runner=subprocess.run):
    unavailable = []

    def query(*args):
        # IPv6 may be disabled on the host; the other family is still watched.
        try:
            result = runner([IP, '-j', *args], capture_output=True, text=True, timeout=5, env=_ENV)
            if result.returncode == 0:
                return json.loads(result.stdout or '[]')
        except (OSError, subprocess.SubprocessError, ValueError):
            pass
        unavailable.append(' '.join(args))
        return []
    routes = query('-4', 'route', 'show', 'table', 'all') + query('-6', 'route', 'show', 'table', 'all')
    rules = query('-4', 'rule', 'show') + query('-6', 'rule', 'show')
    return {'routes': [{key: route.get(key) for key in _KEEP} for route in routes],
            'rules': rules, 'unavailable': unavailable}


def inspect(snap, own_addresses, resolvers=()):
    """Findings in one snapshot, independent of any earlier state.

    `resolvers` adds the pinned DNS servers to the public resolvers watched.
    """
    findings = []
    watched = set(PUBLIC_RESOLVERS) | set(resolvers)
    for route in snap['routes']:
        network = _network(route.get('dst'))
        if network is None:
            continue
        kind, dev = route.get('type') or 'unicast', route.get('dev')
        if _in_loopback(network) and dev not in (None, 'lo'):
            findings.append({'code': 'loopback_route_off_lo', 'severity': 'critical', 'route': route})
        elif kind == 'local' and not _in_loopback(network):
            owned = network.num_addresses == 1 and network.network_address in own_addresses
            if not owned:
                findings.append({'code': 'local_route_for_foreign_address', 'severity': 'critical',
                                 'route': route})
        elif network.prefixlen >= _TARGETED_PREFIX[network.version]:
            hit = sorted(str(a) for a in watched if a.version == network.version and a in network)
            if hit and kind in ('blackhole', 'unreachable', 'prohibit'):
                # Blocks the resolver instead of redirecting it, e.g. to forbid it on purpose.
                findings.append({'code': 'dns_resolver_blocked', 'severity': 'info',
                                 'resolvers': hit, 'route': route})
            elif hit:
                findings.append({'code': 'dns_resolver_route', 'severity': 'critical',
                                 'resolvers': hit, 'route': route})
    for rule in snap['rules']:
        if rule.get('table') not in DEFAULT_RULE_TABLES:
            findings.append({'code': 'extra_policy_rule', 'severity': 'high', 'rule': rule})
    return findings


def _default_routes(snap):
    return sorted(json.dumps(r, sort_keys=True) for r in snap['routes']
                  if r.get('dst') == 'default' and r.get('table') in (None, 'main'))


def changes(previous, current):
    """Changes worth reporting between two snapshots."""
    if previous is None:
        return []
    found = []
    if _default_routes(previous) != _default_routes(current):
        found.append({'code': 'default_route_changed', 'severity': 'medium',
                      'before': _default_routes(previous), 'after': _default_routes(current)})
    return found
