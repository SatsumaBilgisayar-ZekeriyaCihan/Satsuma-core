"""Satsuma's DNS filter lives in its own network namespace (owner's decision 2026-11-13).

dnsmasq listens only on 169.254.53.2:53 inside the ``satsuma-dns`` namespace,
reached over a veth pair (host ``satsuma-dns0`` 169.254.53.1/30, namespace
``satsuma-dns1`` 169.254.53.2/30). Loopback (lo, 127.0.0.0/8, 53053) is never
used. Every DNS query this machine sends is redirected there by the DNS lock
(satsuma.network_modes); dnsmasq's own queries can only reach the pinned
resolver, and they cross the host's forward chain only through the Suricata
queue (satsuma.network_control). This module builds and removes the plumbing;
it runs as root from satsuma-dns-netns.service before dnsmasq starts.

Satsuma'nın DNS filtresi kendi ağ ad alanında çalışır. dnsmasq yalnızca
``satsuma-dns`` ad alanındaki 169.254.53.2:53'te dinler; veth çiftiyle ulaşılır.
Loopback hiç kullanılmaz. Bu modül altyapıyı kurar ve kaldırır.
"""
import json
import subprocess
import sys

NETNS = 'satsuma-dns'
NETNS_PATH = '/run/netns/' + NETNS
HOST_IF = 'satsuma-dns0'
NS_IF = 'satsuma-dns1'
HOST_ADDR = '169.254.53.1'
DNS_ADDR = '169.254.53.2'
PREFIX = 30
NAT_TABLE = 'satsuma_dns_ns'
# Pinned resolver (owner's decision 2026-10-26/2026-11-13). Sabit çözümleyici.
OPENDNS = ('208.67.222.222', '208.67.220.220')
FORWARD_SAVE = '/run/satsuma-dns-netns.ip_forward'
OWNER = 'Satsuma DNS namespace'
IP = '/usr/sbin/ip'
NFT = '/usr/sbin/nft'
SYSCTL = '/usr/sbin/sysctl'


def nat_script():
    """dnsmasq's queries leave with the host's address; forwarding is limited to them.

    The forward chain here (policy drop) is a second wall beside satsuma_core's:
    ip_forward is switched on for the namespace, and even if satsuma_core were
    missing the host would forward nothing but dnsmasq's DNS to the pinned
    resolver and its replies. A drop in any base chain is final.
    Buradaki forward zinciri (varsayılan düşür) satsuma_core yanında ikinci
    duvardır: satsuma_core olmasa bile ana makine yalnızca dnsmasq'ın sabit
    çözümleyiciye giden DNS'ini ve yanıtlarını iletir.
    """
    servers = ', '.join(OPENDNS)
    return (f'table inet {NAT_TABLE} {{\n comment "{OWNER}"\n'
            f' chain postrouting {{ type nat hook postrouting priority srcnat; policy accept;\n'
            f'  ip saddr {DNS_ADDR} oifname != "{HOST_IF}" masquerade\n }}\n'
            f' chain forward {{ type filter hook forward priority 10; policy drop;\n'
            f'  iifname "{HOST_IF}" ip saddr {DNS_ADDR} ip daddr {{ {servers} }} meta l4proto {{ tcp, udp }} th dport 53 accept\n'
            f'  oifname "{HOST_IF}" ip daddr {DNS_ADDR} ct state established,related accept\n'
            f'  counter drop\n }}\n}}\n')


def _run(runner, args, check=True, **kwargs):
    result = runner(args, capture_output=True, text=True, timeout=30, **kwargs)
    if check and result.returncode:
        raise RuntimeError(' '.join(args[:4]) + ' failed: ' + (result.stderr or '')[:300])
    return result


def _ns(*args):
    return [IP, 'netns', 'exec', NETNS, *args]


def present(runner=subprocess.run):
    listed = _run(runner, [IP, '-j', 'netns', 'list'], check=False)
    try:
        names = {entry.get('name') for entry in json.loads(listed.stdout or '[]')}
    except ValueError:
        names = set(listed.stdout.split())
    return NETNS in names


FIREWALL_CMD = '/usr/bin/firewall-cmd'


def _firewalld_trust(runner):
    """When firewalld runs, its zone for the veth must let the namespace's DNS out.

    Runtime only; satsuma_core and the forward chain in NAT_TABLE still limit
    the traffic to DNS for the pinned resolver. Firewalld çalışıyorsa veth
    yalnızca çalışma zamanında güvenilen bölgeye alınır; sınırı Satsuma koyar.
    """
    import os
    if not os.path.exists(FIREWALL_CMD):
        return False
    if _run(runner, [FIREWALL_CMD, '--state'], check=False).returncode:
        return False
    return _run(runner, [FIREWALL_CMD, '--zone=trusted', '--change-interface=' + HOST_IF], check=False).returncode == 0


def setup(runner=subprocess.run):
    """Create (or complete) the namespace, the veth pair, addresses, route and NAT; idempotent."""
    steps = []
    if not present(runner):
        _run(runner, [IP, 'netns', 'add', NETNS]); steps.append('netns')
    if _run(runner, [IP, 'link', 'show', HOST_IF], check=False).returncode:
        _run(runner, [IP, 'link', 'add', HOST_IF, 'type', 'veth', 'peer', 'name', NS_IF])
        _run(runner, [IP, 'link', 'set', NS_IF, 'netns', NETNS]); steps.append('veth')
    _run(runner, [IP, 'addr', 'replace', f'{HOST_ADDR}/{PREFIX}', 'dev', HOST_IF])
    _run(runner, [IP, 'link', 'set', HOST_IF, 'up'])
    _run(runner, _ns(IP, 'addr', 'replace', f'{DNS_ADDR}/{PREFIX}', 'dev', NS_IF))
    _run(runner, _ns(IP, 'link', 'set', NS_IF, 'up'))
    _run(runner, _ns(IP, 'link', 'set', 'lo', 'up'))
    _run(runner, _ns(IP, 'route', 'replace', 'default', 'via', HOST_ADDR, 'dev', NS_IF))
    # Replies to dnsmasq are forwarded back over the veth pair; the forward chain
    # (policy drop) admits only DNS to and from 169.254.53.2, through Suricata.
    import os
    if not os.path.exists(FORWARD_SAVE):
        before = _run(runner, [SYSCTL, '-n', 'net.ipv4.ip_forward'], check=False).stdout.strip()
        if before in ('0', '1'):
            with open(FORWARD_SAVE, 'w') as stream:
                stream.write(before)
    _run(runner, [SYSCTL, '-q', '-w', 'net.ipv4.ip_forward=1'])
    _run(runner, [SYSCTL, '-q', '-w', f'net.ipv4.conf.{HOST_IF}.rp_filter=1'])
    _firewalld_trust(runner)
    listed = _run(runner, [NFT, '-j', 'list', 'tables'], check=False)
    script = (f'delete table inet {NAT_TABLE}\n' if f'"name": "{NAT_TABLE}"' in (listed.stdout or '') else '') + nat_script()
    _run(runner, [NFT, '-f', '-'], input=script)
    return {'status': 'READY', 'created': steps, 'netns': NETNS, 'listen': DNS_ADDR + ':53'}


def teardown(runner=subprocess.run):
    """Remove the NAT table, the veth pair and the namespace; missing parts are fine."""
    _run(runner, [NFT, 'delete', 'table', 'inet', NAT_TABLE], check=False)
    _run(runner, [IP, 'link', 'delete', HOST_IF], check=False)
    if present(runner):
        _run(runner, [IP, 'netns', 'delete', NETNS], check=False)
    import os
    try:
        with open(FORWARD_SAVE) as stream:
            before = stream.read().strip()
    except OSError:
        before = None
    if before in ('0', '1'):
        # Forwarding goes back to what it was before Satsuma switched it on.
        _run(runner, [SYSCTL, '-q', '-w', 'net.ipv4.ip_forward=' + before], check=False)
        os.unlink(FORWARD_SAVE)
    return {'status': 'REMOVED', 'ip_forward_restored': before}


def main(argv=None):
    argv = list(sys.argv[1:] if argv is None else argv)
    if argv == ['setup']:
        print(json.dumps(setup()))
    elif argv == ['teardown']:
        print(json.dumps(teardown()))
    else:
        print('usage: dns_netns setup|teardown', file=sys.stderr)
        return 64
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
