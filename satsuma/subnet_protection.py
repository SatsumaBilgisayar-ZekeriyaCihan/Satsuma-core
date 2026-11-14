"""Subnet aggregate: ten distinct connected peer IPs trigger blocking.

Connected peers are counted from /proc/net (never ss), like every other
connection check (operator rule, 2026-11-03).

Subnet toplamı: birbirinden farklı on bağlı uç IP'si engellemeyi tetikler.

Bağlı uçlar, diğer tüm bağlantı denetimleri gibi ss'ten değil /proc/net'ten
sayılır (operatör kuralı, 2026-11-03).
"""
from collections import Counter
import ipaddress
import os
import time
from .procnet import TABLES, parse
from .store import Store
from .config import load_with_policy
from .response import ResponseWorker


def connection_counts(proc='/proc'):
    """Established TCP and connected UDP sockets per remote address, from /proc/net."""
    counts = Counter()
    for proto, version, path in TABLES:
        try:
            with open(os.path.join(proc, 'net', os.path.basename(path))) as stream:
                sockets = parse(stream.read(), proto, version)
        except OSError:
            continue  # e.g. IPv6 disabled
        for sock in sockets:
            if sock['state'] != '01' or not sock['remote'][1]:
                continue
            address = sock['remote'][0]
            address = getattr(address, 'ipv4_mapped', None) or address
            if not (address.is_loopback or address.is_multicast or address.is_unspecified):
                counts[str(address)] += 1
    return counts


def evaluate(store, counts, config, response=None, now=None, boot_provider=None):
    now = time.time() if now is None else now
    policy = store.get('subnet_protection_policy', None)
    policy = {'enabled': config.get('subnet_protection_enabled',True), 'threshold': 10} if policy is None else policy
    if policy.get('enabled') is not True:
        return []
    from .early_guard import read_verdict
    if not (boot_provider or read_verdict)().get('response_unlocked'):
        store.set('subnet_health', {'status': 'boot_integrity_locked', 'updated_at': now})
        return []
    # Count sequential distinct peers as well as simultaneous connections.
    # Expired observations cannot contribute to a new block decision.
    recent = store.get('subnet_recent_peers', {}) or {}
    recent = {ip: row for ip, row in recent.items()
              if isinstance(row, dict) and isinstance(row.get('last_seen'), (int, float))
              and 0 <= now - row['last_seen'] < 300}
    groups = {}
    for text, count in counts.items():
        try:
            address = ipaddress.ip_address(text)
            address = getattr(address, 'ipv4_mapped', None) or address
        except ValueError:
            continue
        if (address.is_loopback or address.is_multicast or address.is_unspecified
                or type(count) is not int or count < 1):
            continue
        recent[str(address)] = {'last_seen': now, 'connections': count}
    store.set('subnet_recent_peers', recent)
    for text, row in recent.items():
        address = ipaddress.ip_address(text)
        count = row['connections']
        network = str(ipaddress.ip_network(f'{address}/{24 if address.version == 4 else 64}', strict=False))
        group = groups.setdefault(network, {'connections':0, 'ips':[]})
        group['connections'] += count
        group['ips'].append(str(address))
    threshold = int(policy.get('threshold', 10))
    if threshold < 10:
        raise ValueError('Subnet threshold cannot be below 10')
    response = response or ResponseWorker(store, {**config, 'response_enabled': True, 'subnet_limit_authorized': True})
    cooldown = store.get('subnet_block_attempts', {}) or {}
    cooldown = {ip: stamp for ip, stamp in cooldown.items() if now - stamp < 300}
    attempts = [stamp for stamp in (store.get('subnet_attempt_times', []) or []) if now - stamp < 60]
    results = []
    for network, group in sorted(groups.items()):
        if len(group['ips']) < threshold:
            continue
        for ip in sorted(group['ips']):
            if ip in cooldown:
                continue
            attempts.append(now)
            result = response.block_ip(ip, f'Subnet distinct-IP limit: {network}, {len(group["ips"])} different connected IPs >= {threshold}')
            if result.get('status') == 'set_membership_confirmed':
                cooldown[ip] = now
            record = {'timestamp': now, 'subnet': network, 'connections': group['connections'],
                      'threshold': threshold, 'ip_count':len(group['ips']), 'ip': ip, 'classification': 'indicator',
                      'reason': 'subnet_connection_limit', **result}
            store.add('subnet_decisions', record)
            results.append(record)
    store.set('subnet_block_attempts', cooldown)
    store.set('subnet_attempt_times', attempts)
    store.set('subnet_health', {'status': 'degraded' if any(item.get('status') != 'set_membership_confirmed' for item in results) else 'running', 'updated_at': now, 'threshold': threshold,
                               'count_mode': 'subnet_distinct_peer_ips', 'window_seconds': 300,
                               'groups': groups, 'dns_exempt': False})
    return results


def run():
    import signal
    running = True
    def stop(*_):
        nonlocal running
        running = False
    signal.signal(signal.SIGTERM, stop)
    signal.signal(signal.SIGINT, stop)
    store = Store()
    try:
        while running:
            try:
                config, _, _ = load_with_policy()
                evaluate(store, connection_counts(), config)
            except Exception as exc:
                store.set('subnet_health', {'status': 'error', 'updated_at': time.time(), 'error': str(exc)[:300]})
            for _ in range(10):
                if not running:
                    break
                time.sleep(.5)
    finally:
        store.close()
