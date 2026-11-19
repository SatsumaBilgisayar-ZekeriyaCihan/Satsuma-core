"""Address ranges the owner always allows, e.g. a VPN provider's servers (2.2.50).

Owner, 2026-11-19: "Opera VPN is blocked as soon as I open it; let me allow a
range so it is not blocked." VPN servers have no PTR record and open many
connections, so the guard's fixed rule (a no-PTR peer making a 6th connection
in one visit) blocked them at once. An allowed range is never blocked
automatically — not by that rule, OTX, Suricata alerts, the subnet limit or
automatic network response — and addresses already blocked inside it are
unblocked when the range is added. A block the owner sets by hand inside an
allowed range is refused with the reason, so the two never contradict.

Sahibi, 2026-11-19: Opera VPN açılır açılmaz engelleniyor; aralığa izin
vereyim. İzin verilen aralık hiçbir otomatik yolla engellenmez; içinde
önceden engellenmiş adreslerin engeli eklenince kalkar.
"""
import ipaddress
import time

STATE = 'operator_allow_networks'
SINGLE = 'operator_allow_ips'
LIMIT = 256
MIN_PREFIX = {4: 8, 6: 16}


def parse(text):
    """IPv4 or IPv6 network; a single address is /32 (/128). Too wide a range is refused."""
    value = str(text or '').strip()
    if not value:
        raise ValueError('Bir adres ya da aralık yazın, ör. 77.111.244.0/22')
    try:
        network = ipaddress.ip_network(value, strict=False)
    except ValueError:
        raise ValueError('Geçerli bir adres ya da CIDR aralığı değil: ' + value[:60]) from None
    if network.prefixlen < MIN_PREFIX[network.version]:
        raise ValueError('Aralık çok geniş: en fazla /%d izin verilebilir' % MIN_PREFIX[network.version])
    if network.is_unspecified or network.is_multicast:
        raise ValueError('Bu aralığa izin verilemez')
    return network


def stored(store):
    rows = store.get(STATE, []) if store is not None else []
    return [row for row in rows or [] if isinstance(row, dict) and row.get('network')]


def _networks(store):
    result = []
    for row in stored(store):
        try:
            result.append(ipaddress.ip_network(row['network']))
        except ValueError:
            continue
    return result


def allowed(store, ip):
    """The allow entry covering ``ip`` (the address itself or a range), or None."""
    if store is None:
        return None
    try:
        address = ipaddress.ip_address(str(ip))
    except ValueError:
        return None
    if str(address) in (store.get(SINGLE, []) or []):
        return str(address)
    for network in _networks(store):
        if address.version == network.version and address in network:
            return str(network)
    return None


def overlapping(store, network):
    """Allowed ranges that overlap ``network`` (used to refuse a contradicting manual block)."""
    return [str(n) for n in _networks(store) if n.version == network.version and n.overlaps(network)]


def add(store, text, reason='', uid=None):
    network = parse(text)
    rows = stored(store)
    if any(row['network'] == str(network) for row in rows):
        return {'status': 'already_allowed', 'network': str(network)}
    if len(rows) >= LIMIT:
        raise ValueError('En fazla %d izinli aralık tutulur' % LIMIT)
    rows.append({'network': str(network), 'reason': str(reason or '')[:200], 'added_at': time.time(), 'uid': uid})
    store.set(STATE, rows)
    store.add('actions', {'action': 'network_range_allow', 'network': str(network), 'reason': str(reason or '')[:200],
                          'status': 'allowed', 'operator_uid': uid, 'timestamp': time.time()})
    return {'status': 'allowed', 'network': str(network)}


def remove(store, text, uid=None):
    network = parse(text)
    rows = stored(store)
    kept = [row for row in rows if row['network'] != str(network)]
    if len(kept) == len(rows):
        return {'status': 'not_allowed', 'network': str(network)}
    store.set(STATE, kept)
    store.add('actions', {'action': 'network_range_unallow', 'network': str(network), 'status': 'removed',
                          'operator_uid': uid, 'timestamp': time.time()})
    return {'status': 'removed', 'network': str(network)}


def blocked_inside(blocked_ips, network):
    """Addresses from the automatic block list that fall inside ``network``."""
    inside = []
    for entry in blocked_ips or []:
        ip = entry.get('ip') if isinstance(entry, dict) else entry
        try:
            if ipaddress.ip_address(str(ip)) in network:
                inside.append(str(ip))
        except ValueError:
            continue
    return inside
