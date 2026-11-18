"""Operator-owned LAN/DNS firewall tables; DNS stays reachable in LAN-off mode.

The DNS lock (satsuma_dns): every DNS query this machine sends, to whatever
server a program asked for, goes to Satsuma's dnsmasq filter on 169.254.53.2:53,
which lives in its own network namespace (satsuma.dns_netns) and asks only the
pinned resolver (OpenDNS). Loopback destinations are left to the local stub;
the stub's own queries to its upstream are then caught by the same rule.
History: until 2.2.37 the filter listened on 127.0.0.1:53053; 2.2.38-2.2.43
sent queries straight to the resolver with no filter (owner, 2026-11-13:
Satsuma's only relation to loopback is blocking it). 2.2.44 brings the filter
back outside loopback.

DNS kilidi (satsuma_dns): bu makinenin her DNS sorgusu, program hangi sunucuyu
sorarsa sorsun, kendi ağ ad alanındaki Satsuma dnsmasq filtresine
(169.254.53.2:53) gider; filtre yalnızca sabit çözümleyiciye (OpenDNS) sorar.
Loopback hedefleri yerel çözücüye bırakılır; onun üst sunucuya giden sorguları
yine aynı kuralla yakalanır.
"""
import ipaddress
import json
import subprocess
import time

LAN_TABLE = 'satsuma_lan'
DNS_TABLE = 'satsuma_dns'
OWNER = 'Satsuma Core managed'
DNS_MARK = 0x5341
# The pinned resolver (user decision 2026-10-26: OpenDNS). Sabit çözümleyici.
OPENDNS = ('208.67.222.222', '208.67.220.220')
LOCAL_NETWORKS = ('10.0.0.0/8', '172.16.0.0/12', '192.168.0.0/16', '169.254.0.0/16', 'fc00::/7', 'fe80::/10')


def dns_exceptions():
    """Plain DNS (53) stays reachable in LAN-off mode; 853 never.

    Field 2026-11-04: port 853 (DNS over TLS) was accepted here although
    Satsuma never uses it; encrypted DNS bypasses the pinned resolver and
    has carried C2 traffic on this host. The main table's default drop
    still blocked it, but no Satsuma table may name 853 as allowed.
    Düz DNS (53) yerel ağ kapalıyken de açık kalır; 853 asla. 853 (TLS
    üzerinden DNS) burada kabul ediliyordu; şifreli DNS sabit çözümleyiciyi
    atlatır ve bu makinede C2 trafiği taşıdı. Ana tablonun varsayılan
    düşürmesi onu yine engelliyordu, ama hiçbir Satsuma tablosu 853'e izin
    veremez.
    """
    return 'udp sport 53 accept\nudp dport 53 accept\ntcp sport 53 accept\ntcp dport 53 accept'


def lan_script():
    chains = []
    for chain, field in [('input', 'saddr'), ('output', 'daddr')]:
        rules = [dns_exceptions(), 'iifname "lo" accept' if chain == 'input' else 'oifname "lo" accept',
                 'udp sport { 67, 68, 546, 547 } udp dport { 67, 68, 546, 547 } accept',
                 'meta l4proto ipv6-icmp icmpv6 type { nd-router-advert, nd-router-solicit, nd-neighbor-solicit, nd-neighbor-advert } accept']
        for network in LOCAL_NETWORKS:
            rules.append(f'{"ip6" if ":" in network else "ip"} {field} {network} counter drop')
        chains.append(f'chain {chain} {{ type filter hook {chain} priority -220; policy accept;\n'+ '\n'.join(rules)+'\n}')
    return f'table inet {LAN_TABLE} {{\ncomment "{OWNER}"\n'+'\n'.join(chains)+'\n}\n'


def dns_script(resolver=OPENDNS[0]):
    """Redirect every non-loopback DNS query to the filter in its own namespace.

    ``resolver`` is still checked (it is what the filter asks), but queries no
    longer go to it directly. Sorgular artık doğrudan çözümleyiciye gitmez.
    """
    import ipaddress
    from .dns_netns import DNS_ADDR
    address = ipaddress.ip_address(resolver)
    if address.version != 4 or address.is_loopback or address.is_private or address.is_unspecified or address.is_multicast:
        raise ValueError('The DNS lock needs a public IPv4 resolver')
    return f'''table inet {DNS_TABLE} {{
 comment "{OWNER}"
 chain output {{ type nat hook output priority dstnat; policy accept;
 ip daddr 127.0.0.0/8 return
 udp dport 53 dnat ip to {DNS_ADDR}
 tcp dport 53 dnat ip to {DNS_ADDR}
 }}
}}
'''


class NetworkModes:
    def __init__(self, store, runner=subprocess.run):
        self.store, self.runner = store, runner

    def apply(self, table, enabled):
        if table not in (LAN_TABLE, DNS_TABLE) or type(enabled) is not bool:
            raise ValueError('Invalid managed network mode')
        probe = self.runner(['nft', '-j', 'list', 'tables'], capture_output=True, text=True, timeout=10)
        if probe.returncode:
            raise RuntimeError('Firewall tables could not be read')
        listed = json.loads(probe.stdout).get('nftables', [])
        present = any(e.get('table', {}).get('family') == 'inet' and e.get('table', {}).get('name') == table for e in listed)
        if present:
            existing = self.runner(['nft', '-j', 'list', 'table', 'inet', table], capture_output=True, text=True, timeout=10)
            data = json.loads(existing.stdout) if existing.returncode == 0 else {}
            if not any(e.get('table', {}).get('name') == table and e['table'].get('comment') == OWNER for e in data.get('nftables', [])):
                raise RuntimeError('Refusing to replace a table without Satsuma ownership')
        script = (f'delete table inet {table}\n' if present else '')
        if enabled:
            upstream = (self.store.get('dns_policy', {}) or {}).get('upstream') or OPENDNS[0]
            script += lan_script() if table == LAN_TABLE else dns_script(upstream)
        if script:
            result = self.runner(['nft', '-f', '-'], input=script, capture_output=True, text=True, timeout=10)
            if result.returncode:
                raise RuntimeError('Firewall transaction failed: ' + result.stderr[:250])
        check = self.runner(['nft', '-j', 'list', 'tables'], capture_output=True, text=True, timeout=10)
        if check.returncode:
            raise RuntimeError('Firewall readback failed')
        now_present = any(e.get('table', {}).get('family') == 'inet' and e.get('table', {}).get('name') == table for e in json.loads(check.stdout).get('nftables', []))
        if now_present != enabled:
            raise RuntimeError('Firewall mode readback mismatch')
        state = {'enabled': enabled, 'updated_at': time.time(), 'readback': True, 'traffic_verified': False}
        self.store.set(table + '_state', state)
        return {'ok': True, **state}
