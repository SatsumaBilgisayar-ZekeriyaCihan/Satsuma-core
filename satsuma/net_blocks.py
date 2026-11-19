"""Address ranges the administrator blocks by hand, such as 192.168.0.0/16 (2.2.47).

Owner's request 2026-11-18: a field in the panel to block a whole range.
satsuma_core's block sets hold single addresses and are checked strictly, so
ranges live in their own owned table, satsuma_netblock: one interval set and
drop rules in input, output and forward. A drop in any base chain is final,
so a range is dropped whatever satsuma_core would let through; nothing here
accepts anything (policy accept, only drop rules).

A range is refused when it would cut this machine off: loopback, the DNS
filter's link (169.254.53.0/30), the pinned resolver, the default gateway or
one of this machine's own addresses; or when it is wider than /8. IPv6 is
off entirely (satsuma.ipv6_off). The list is kept in the store and restored
at boot (installer/network_setup.py).

Yöneticinin elle engellediği adres aralıkları (ör. 192.168.0.0/16). Aralıklar
ayrı bir Satsuma tablosunda (satsuma_netblock) tutulur; her tablodaki düşürme
kesindir. Makineyi kesecek aralık (loopback, DNS filtresi bağlantısı, sabit
çözümleyici, varsayılan ağ geçidi, kendi adresleri) ya da /8'den geniş aralık
reddedilir. Liste saklanır ve açılışta geri yüklenir.
"""
import ipaddress
import json
import subprocess
import time

TABLE = 'satsuma_netblock'
OWNER = 'Satsuma manual network blocks'
STATE = 'manual_network_blocks'
MIN_PREFIX = 8
LIMIT = 256
PROTECTED = (('127.0.0.0/8', 'loopback'), ('169.254.53.0/30', 'Satsuma DNS filtresi bağlantısı'),
             ('208.67.222.222/32', 'DNS çözümleyici (OpenDNS)'), ('208.67.220.220/32', 'DNS çözümleyici (OpenDNS)'))
PRIORITY = -10


def parse(text):
    """'192.168.0.0/16', '10.1.2.3' or '10.1.2.0/24' -> IPv4Network; host bits are cleared."""
    text = str(text or '').strip()
    if not text:
        raise ValueError('Bir adres ya da aralık yazın, ör. 192.168.0.0/16')
    try:
        network = ipaddress.ip_network(text, strict=False)
    except ValueError:
        raise ValueError('Geçerli bir IPv4 adresi ya da aralığı değil: ' + text[:60]) from None
    if network.version != 4:
        raise ValueError('IPv6 bu bilgisayarda tamamen kapalı; ayrıca engellemeye gerek yok.')
    if network.prefixlen < MIN_PREFIX:
        raise ValueError('/%d’den geniş aralık engellenemez (en geniş /%d).' % (MIN_PREFIX, MIN_PREFIX))
    return network


def default_gateways(route_path='/proc/net/route'):
    gateways = []
    try:
        with open(route_path) as stream:
            next(stream, None)
            for line in stream:
                fields = line.split()
                if len(fields) > 3 and fields[1] == '00000000' and int(fields[3], 16) & 2:
                    gateways.append(str(ipaddress.IPv4Address(bytes.fromhex(fields[2])[::-1])))
    except (OSError, ValueError):
        pass
    return gateways


def own_addresses(runner=subprocess.run):
    try:
        result = runner(['/usr/sbin/ip', '-j', '-4', 'addr', 'show'], capture_output=True, text=True, timeout=10)
        data = json.loads(result.stdout or '[]')
    except (OSError, ValueError, subprocess.TimeoutExpired):
        return []
    return [info['local'] for link in data for info in link.get('addr_info', []) if info.get('local')]


def conflicts(network, gateways=(), addresses=()):
    """Why blocking ``network`` would cut this machine off; empty when it is safe."""
    reasons = []
    for text, name in PROTECTED:
        if network.overlaps(ipaddress.ip_network(text)):
            reasons.append('%s (%s) bu aralıkta' % (name, text))
    for gateway in gateways:
        if ipaddress.ip_address(gateway) in network:
            reasons.append('modeminiz / ağ geçidiniz (%s) bu aralıkta; engellenirse internet kesilir' % gateway)
    for address in addresses:
        if ipaddress.ip_address(address) in network and not ipaddress.ip_address(address).is_loopback:
            reasons.append('bu bilgisayarın kendi adresi (%s) bu aralıkta' % address)
    return reasons


def render(networks):
    elements = ', '.join(str(n) for n in networks)
    lines = [f'table inet {TABLE} {{', f' comment "{OWNER}"',
             ' set nets { type ipv4_addr; flags interval; ' + (f'elements = {{ {elements} }}; ' if elements else '') + '}']
    for chain in ('input', 'output', 'forward'):
        lines.append(f' chain {chain} {{ type filter hook {chain} priority {PRIORITY}; policy accept;')
        if chain in ('input', 'forward'):
            lines.append('  ip saddr @nets counter drop')
        if chain in ('output', 'forward'):
            lines.append('  ip daddr @nets counter drop')
        lines.append(' }')
    return '\n'.join(lines + ['}', ''])


def _element(value):
    if isinstance(value, str):
        return ipaddress.ip_network(value)
    if isinstance(value, dict) and 'prefix' in value:
        return ipaddress.ip_network('%s/%s' % (value['prefix']['addr'], value['prefix']['len']))
    if isinstance(value, dict) and 'range' in value:
        first, last = value['range']
        return list(ipaddress.summarize_address_range(ipaddress.ip_address(first), ipaddress.ip_address(last)))
    raise ValueError('Unsupported set element')


def readback(data):
    """(owned, networks, rules_ok) from ``nft -j list table inet satsuma_netblock``."""
    entries = data.get('nftables', []) if isinstance(data, dict) else []
    tables = [e['table'] for e in entries if 'table' in e]
    owned = len(tables) == 1 and tables[0].get('name') == TABLE and tables[0].get('comment') == OWNER
    networks = set()
    for entry in entries:
        if entry.get('set', {}).get('name') == 'nets':
            for value in entry['set'].get('elem', []) or []:
                parsed = _element(value.get('elem', {}).get('val') if isinstance(value, dict) and 'elem' in value else value)
                networks.update(parsed if isinstance(parsed, list) else [parsed])
    chains = {e['chain']['name']: e['chain'] for e in entries if 'chain' in e}
    rules = {}
    for entry in entries:
        if 'rule' in entry:
            rule = entry['rule']
            rules.setdefault(rule['chain'], []).append(
                [(x['match']['left']['payload']['field'], x['match']['right'])
                 for x in rule.get('expr', []) if 'match' in x] + [k for x in rule.get('expr', []) for k in x if k in ('drop', 'accept')])
    wanted = {'input': [[('saddr', '@nets'), 'drop']], 'output': [[('daddr', '@nets'), 'drop']],
              'forward': [[('saddr', '@nets'), 'drop'], [('daddr', '@nets'), 'drop']]}
    rules_ok = set(chains) == set(wanted) and all(
        chains[name].get('policy') == 'accept' and chains[name].get('prio') == PRIORITY and rules.get(name) == wanted[name]
        for name in wanted)
    return owned, networks, rules_ok


def apply(networks, runner=subprocess.run):
    """Make the kernel table hold exactly ``networks``; verified by readback."""
    def call(args, **kwargs):
        return runner(['nft', *args], capture_output=True, text=True, timeout=15, **kwargs)
    listed = call(['-j', 'list', 'tables'])
    if listed.returncode:
        raise RuntimeError('Cannot inspect nftables: ' + (listed.stderr or '')[:300])
    present = any(e.get('table', {}).get('family') == 'inet' and e['table'].get('name') == TABLE
                  for e in json.loads(listed.stdout or '{}').get('nftables', []))
    script = (f'delete table inet {TABLE}\n' if present else '') + render(networks)
    checked = call(['--check', '-f', '-'], input=script)
    if checked.returncode:
        raise RuntimeError('nftables validation failed: ' + (checked.stderr or '')[:300])
    applied = call(['-f', '-'], input=script)
    if applied.returncode:
        raise RuntimeError('nftables transaction failed: ' + (applied.stderr or '')[:300])
    back = call(['-j', 'list', 'table', 'inet', TABLE])
    owned, live, rules_ok = readback(json.loads(back.stdout or '{}')) if not back.returncode else (False, set(), False)
    if not (owned and rules_ok and live == set(networks)):
        raise RuntimeError('Network block readback did not match')
    return {'status': 'ready', 'networks': [str(n) for n in networks]}


def stored(store):
    rows = store.get(STATE, []) or []
    return [row for row in rows if isinstance(row, dict) and row.get('network')]


def _networks(rows):
    return sorted({ipaddress.ip_network(row['network']) for row in rows}, key=lambda n: (int(n.network_address), n.prefixlen))


def add(store, text, reason='', uid=None, runner=subprocess.run, gateways=None, addresses=None):
    from .net_allow import overlapping
    clash = overlapping(store, parse(text))
    if clash:
        raise ValueError('Bu aralık izin verilen aralıkla çakışıyor: ' + ', '.join(clash) + '. Önce izni kaldırın.')
    network = parse(text)
    rows = stored(store)
    if any(ipaddress.ip_network(row['network']) == network for row in rows):
        return {'ok': True, 'status': 'already_blocked', 'network': str(network), 'networks': [r['network'] for r in rows]}
    if len(rows) >= LIMIT:
        raise ValueError('En fazla %d aralık engellenebilir.' % LIMIT)
    problems = conflicts(network, default_gateways() if gateways is None else gateways,
                         own_addresses(runner) if addresses is None else addresses)
    if problems:
        raise ValueError('Bu aralık engellenemez: ' + '; '.join(problems) + '. Daha dar bir aralık yazın.')
    updated = rows + [{'network': str(network), 'reason': str(reason or 'Yönetici ekledi')[:300],
                       'added_at': time.time(), 'uid': uid}]
    apply(_networks(updated), runner)
    store.set(STATE, updated)
    store.add('actions', {'action': 'network_range_block', 'network': str(network), 'manual': True,
                          'status': 'set_membership_confirmed', 'timestamp': time.time(), 'reason': updated[-1]['reason']})
    return {'ok': True, 'status': 'blocked', 'network': str(network), 'networks': [r['network'] for r in updated]}


def remove(store, text, runner=subprocess.run):
    network = parse(text)
    rows = stored(store)
    kept = [row for row in rows if ipaddress.ip_network(row['network']) != network]
    if len(kept) == len(rows):
        return {'ok': True, 'status': 'not_blocked', 'network': str(network), 'networks': [r['network'] for r in rows]}
    apply(_networks(kept), runner)
    store.set(STATE, kept)
    store.add('actions', {'action': 'network_range_unblock', 'network': str(network), 'manual': True,
                          'status': 'set_absence_confirmed', 'timestamp': time.time()})
    return {'ok': True, 'status': 'unblocked', 'network': str(network), 'networks': [r['network'] for r in kept]}


def restore(store, runner=subprocess.run):
    """At boot: the stored ranges go back into the kernel (an empty table when there are none)."""
    return apply(_networks(stored(store)), runner)
