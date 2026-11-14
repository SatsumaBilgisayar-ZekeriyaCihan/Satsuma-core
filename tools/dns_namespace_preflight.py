#!/usr/bin/env python3
"""Read-only source audit before a proposed Satsuma DNS network-namespace migration.

This is NOT an activation check: it never invokes nft, systemctl, or changes files.
"""
import argparse
import json
from pathlib import Path


def assess(root: Path):
    checks = {
        'dns_service': ('systemd/satsuma-core-dns.service',),
        'dns_daemon': ('satsuma/dnsmasq_control.py',),
        'dns_nat': ('satsuma/network_modes.py',),
        'network_filter': ('satsuma/network_control.py',),
        'network_rules': ('packaging/root/etc/satsuma-core/nftables.nft',),
    }
    texts = {}
    problems = []
    for name, (relative,) in checks.items():
        target = root / relative
        if not target.is_file() or target.is_symlink():
            problems.append(f'Missing or nonregular source: {relative}')
            texts[name] = ''
        else:
            texts[name] = target.read_text(encoding='utf-8')
    service = texts['dns_service']
    daemon = texts['dns_daemon']
    nat = texts['dns_nat']
    network = texts['network_filter']
    if 'NetworkNamespacePath=' not in service:
        problems.append('DNS service has no NetworkNamespacePath')
    if 'CapabilityBoundingSet=' in service and ('AmbientCapabilities=CAP_NET_BIND_SERVICE' not in service):
        problems.append('DNS daemon has no verified privileged-port capability for port 53')
    if 'port=53053' in daemon or 'listen-address=127.0.0.1' in daemon:
        problems.append('DNS daemon still configured for loopback:53053')
    if 'dnat ip to {address}' in nat or 'dnat ip to 208.67.' in nat:
        problems.append('DNS NAT redirects directly to a public resolver, not a namespace')
    if 'policy drop' in network and 'forward' in network:
        problems.append('Forward policy defaults to drop; namespace egress/replies must be reviewed with NFQUEUE 100')
    return {'status': 'BLOCKED' if problems else 'SOURCE_CHECKS_PASSED_NOT_HOST_VERIFIED',
            'checks': sorted(checks), 'blockers': problems,
            'note': 'Read-only source audit only; runtime nftables, routes, SELinux, DNS, Suricata and Fedora tests are NOT covered.'}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--root', type=Path, default=Path(__file__).resolve().parents[1])
    args = parser.parse_args()
    result = assess(args.root)
    print(json.dumps(result, indent=2, ensure_ascii=False))
    return 2 if result['blockers'] else 0


if __name__ == '__main__':
    raise SystemExit(main())
