"""Owned default-drop firewall: profile ports (DNS, HTTPS, add-ons) via Suricata NFQUEUE 100.

Outbound destination ports come from the egress profile
(satsuma.egress_profiles); with no stored profile they are DNS and TCP HTTPS.
Incoming traffic is only ever accepted as established replies. Loopback is
closed (2.2.13): on lo only replies and the DNS resolver, Satsuma's DNS
filter and TeamViewer's local daemon pass (LO_TCP, LO_UDP).
From 2.2.16 to 2.2.40 DHCP, NTP, TeamViewer and AnyDesk were accepted
directly, outside the queue. Since 2.2.41 (owner, 2026-11-18: "no channel may
bypass Suricata") they go through the Suricata queue like every other port
(ALWAYS_QUEUED): if Suricata stops, DHCP renewal, NTP and remote support stop
with it. Loopback never leaves the machine and is not queued. Blocked IPs are
still dropped first and nothing new is accepted inbound.
Since 2.2.12 a hand-edited /etc/satsuma-core/nftables.nft no longer stops the
firewall at boot (which left the emergency DROP and cut the network): the
edited file is kept as a dated copy and the managed file is written again
from this code.

Sahip olunan varsayılan-düşür güvenlik duvarı: profil portları (DNS, HTTPS,
eklentiler) Suricata NFQUEUE 100 üzerinden.

Çıkış hedef portları çıkış profilinden (satsuma.egress_profiles) gelir;
saklı profil yoksa DNS ve TCP HTTPS'tir. Gelen trafik yalnızca kurulmuş
bağlantıların yanıtı olarak kabul edilir. Loopback kapalıdır (2.2.13):
lo üzerinde yalnızca yanıtlar ile DNS çözücüsü, Satsuma DNS filtresi ve
TeamViewer'ın yerel servisi geçer (LO_TCP, LO_UDP). 2.2.41'den beri
(sahibinin kararı: Suricata'dan geçmeyen kanal kalmayacak) DHCP, NTP,
TeamViewer ve AnyDesk de Suricata kuyruğundan geçer; Suricata durursa onlar da
durur. Engellenen IP'ler yine önce düşürülür, gelen yeni
bağlantı kabul edilmez. 2.2.12'den beri elle
değiştirilmiş /etc/satsuma-core/nftables.nft güvenlik duvarını açılışta
durdurmuyor (bu, acil durum kilidini bırakıp ağı kesiyordu): değiştirilmiş
dosya tarihli bir kopya olarak saklanır ve yönetilen dosya bu koddan yeniden
yazılır.
"""
import ipaddress
import json
import os
from pathlib import Path
import subprocess
import time

TABLE = 'satsuma_core'
OWNER = 'Satsuma Core managed'
QUEUE = 100
RULESET = Path('/etc/satsuma-core/nftables.nft')
# Loopback is closed (user decision 2026-10-26): on lo only replies and these
# local services pass. 53: systemd-resolved stub; 5939: TeamViewer's local
# daemon, which its window talks to. 2.2.38 (owner, 2026-11-13): Satsuma's only
# relation to loopback is blocking it; its dnsmasq port 53053 is closed for good
# (2.2.44: the filter listens on 169.254.53.2 in its own namespace).
# Loopback kapalı; 2.2.38'den beri Satsuma'nın dnsmasq portu 53053 kalıcı olarak kapalı.
LO_TCP = (53, 5939)
LO_UDP = (53,)
# Always open, always through the Suricata queue (2.2.41; accepted directly
# outside the queue from 2.2.16 to 2.2.40): 67 DHCP, 123 NTP, 5938 TeamViewer,
# 6568 AnyDesk. Outbound only; inbound only as established replies.
# Her zaman açık, her zaman Suricata kuyruğundan geçer.
ALWAYS_QUEUED = {'tcp': (5938, 6568), 'udp': (67, 123, 5938)}
# 2.2.44: the only forwarded traffic is the DNS filter's (satsuma.dns_netns):
# from 169.254.53.2 over satsuma-dns0 to the pinned resolver on port 53, and
# its replies, both through the Suricata queue.
# Tek iletilen trafik DNS filtresininkidir; o da Suricata kuyruğundan geçer.
DNS_NS_IF = 'satsuma-dns0'
DNS_NS_ADDR = '169.254.53.2'
DNS_NS_UPSTREAMS = ('208.67.220.220', '208.67.222.222')


def run(args):
    return subprocess.run(['nft', *args], capture_output=True, text=True, timeout=10)


def match(left, right):
    op = 'in' if left == {'ct': {'key': 'state'}} else '=='
    return {'match': {'op': op, 'left': left, 'right': right}}


def _port_match(ports):
    ports = sorted(ports)
    return ports[0] if len(ports) == 1 else {'set': ports}


def _port_text(ports):
    ports = sorted(ports)
    return str(ports[0]) if len(ports) == 1 else '{ '+', '.join(map(str, ports))+' }'


def _profile_ports(ports):
    if ports is None:
        from .egress_profiles import current_ports
        ports = current_ports()
    # 2.2.41: the always-open ports join the queued set; nothing is accepted
    # around Suricata. Her zaman açık portlar kuyruğa girer.
    return {proto: tuple(sorted(set(ports.get(proto) or ()) | set(ALWAYS_QUEUED[proto]))) for proto in ('tcp', 'udp')}


def expected_rules(chain, previous=False, ports=None):
    ports = _profile_ports(ports)
    # 2.2.9: IPv6 is off; every IPv6 packet is dropped first (satsuma.ipv6_off).
    rules = [[match({'meta': {'key': 'nfproto'}}, 'ipv6'), {'counter': {}}, {'drop': None}]]
    if chain != 'forward':
        key = 'iifname' if chain == 'input' else 'oifname'
        lo = match({'meta': {'key': key}}, 'lo')
        rules.append([lo, match({'ct': {'key': 'state'}}, ['established', 'related']), {'accept': None}])
        # A single port is read back by nft as a plain value, not a set (2.2.38: udp is 53 only).
        rules.append([lo, match({'payload': {'protocol': 'tcp', 'field': 'dport'}}, _port_match(LO_TCP)), {'accept': None}])
        rules.append([lo, match({'payload': {'protocol': 'udp', 'field': 'dport'}}, _port_match(LO_UDP)), {'accept': None}])
        rules.append([lo, {'counter': {}}, {'drop': None}])
    rules.append([match({'ct': {'key': 'state'}}, 'invalid'), {'drop': None}])
    directions = ('saddr', 'daddr') if chain == 'forward' else ('saddr',) if chain == 'input' else ('daddr',)
    for direction in directions:
        for proto, name in (('ip', 'blocked_ips'), ('ip6', 'blocked_ips_v6')):
            rules.append([match({'payload': {'protocol': proto, 'field': direction}}, '@'+name),
                          {'counter': {}}, {'drop': None}])
    for proto, wanted in (('tcp', ports['tcp']), ('udp', ports['udp'])):
        if not wanted:
            continue
        ports_expr = _port_match(wanted)
        if chain == 'output' or previous:
            rules.append([match({'payload': {'protocol': proto, 'field': 'dport'}}, ports_expr),
                          {'counter': {}}, {'queue': {'num': QUEUE}}])
        if chain == 'input' or previous:
            rules.append([match({'ct': {'key': 'state'}}, 'established'),
                          match({'ct': {'key': 'direction'}}, 'reply'),
                          match({'payload': {'protocol': proto, 'field': 'sport'}}, ports_expr),
                          {'counter': {}}, {'queue': {'num': QUEUE}}])
    if chain == 'forward' and not previous:
        upstreams = {'set': list(DNS_NS_UPSTREAMS)}
        for proto in ('tcp', 'udp'):
            rules.append([match({'meta': {'key': 'iifname'}}, DNS_NS_IF),
                          match({'payload': {'protocol': 'ip', 'field': 'saddr'}}, DNS_NS_ADDR),
                          match({'payload': {'protocol': 'ip', 'field': 'daddr'}}, upstreams),
                          match({'payload': {'protocol': proto, 'field': 'dport'}}, 53),
                          {'counter': {}}, {'queue': {'num': QUEUE}}])
        for proto in ('tcp', 'udp'):
            rules.append([match({'meta': {'key': 'oifname'}}, DNS_NS_IF),
                          match({'payload': {'protocol': 'ip', 'field': 'daddr'}}, DNS_NS_ADDR),
                          match({'ct': {'key': 'state'}}, 'established'),
                          match({'ct': {'key': 'direction'}}, 'reply'),
                          match({'payload': {'protocol': 'ip', 'field': 'saddr'}}, upstreams),
                          match({'payload': {'protocol': proto, 'field': 'sport'}}, 53),
                          {'counter': {}}, {'queue': {'num': QUEUE}}])
    return rules


def _dns_forward_lines():
    upstreams = '{ ' + ', '.join(DNS_NS_UPSTREAMS) + ' }'
    lines = [f'  iifname "{DNS_NS_IF}" ip saddr {DNS_NS_ADDR} ip daddr {upstreams} {proto} dport 53 counter queue num {QUEUE}'
             for proto in ('tcp', 'udp')]
    lines += [f'  oifname "{DNS_NS_IF}" ip daddr {DNS_NS_ADDR} ct state established ct direction reply '
              f'ip saddr {upstreams} {proto} sport 53 counter queue num {QUEUE}' for proto in ('tcp', 'udp')]
    return lines


def render_ruleset(include_sets=True, ports=None):
    ports = _profile_ports(ports)
    lines = ['table inet satsuma_core {', ' comment "'+OWNER+'"']
    if include_sets:
        lines += [' set blocked_ips { type ipv4_addr; }', ' set blocked_ips_v6 { type ipv6_addr; }']
    for chain in ('input', 'output', 'forward'):
        lines.append(f' chain {chain} {{ type filter hook {chain} priority 0; policy drop;')
        lines.append('  meta nfproto ipv6 counter drop')
        if chain != 'forward':
            interface = 'iifname' if chain == 'input' else 'oifname'
            lines += [f'  {interface} "lo" ct state established,related accept',
                      f'  {interface} "lo" tcp dport {_port_text(LO_TCP)} accept',
                      f'  {interface} "lo" udp dport {_port_text(LO_UDP)} accept',
                      f'  {interface} "lo" counter drop']
        lines.append('  ct state invalid drop')
        directions = ('saddr', 'daddr') if chain == 'forward' else ('saddr',) if chain == 'input' else ('daddr',)
        for direction in directions:
            lines += [f'  ip {direction} @blocked_ips counter drop', f'  ip6 {direction} @blocked_ips_v6 counter drop']
        if chain == 'output':
            lines += [f'  {proto} dport {_port_text(ports[proto])} counter queue num 100' for proto in ('tcp', 'udp') if ports[proto]]
        elif chain == 'input':
            lines += [f'  ct state established ct direction reply {proto} sport {_port_text(ports[proto])} counter queue num 100'
                      for proto in ('tcp', 'udp') if ports[proto]]
        else:
            lines += _dns_forward_lines()
        lines.append(' }')
    return '\n'.join(lines+['}', ''])


def _canonical(expr):
    if 'counter' in expr:
        return {'counter': {}}
    right = expr.get('match', {}).get('right')
    if isinstance(right, dict) and isinstance(right.get('set'), list):
        return {'match': {**expr['match'], 'right': {'set': sorted(right['set'], key=lambda v: (type(v).__name__, v))}}}
    return expr


def _expressions(rule):
    return [_canonical(expr) for expr in rule.get('expr', [])]


def _owned(data):
    tables = [e['table'] for e in data.get('nftables', []) if 'table' in e]
    return len(tables) == 1 and tables[0].get('family') == 'inet' and tables[0].get('name') == TABLE and tables[0].get('comment') == OWNER


def validate_layout(data, previous=False, ports=None):
    if not isinstance(data, dict) or not _owned(data):
        return False
    entries = data.get('nftables', [])
    sets = {e['set']['name']: e['set'].get('type') for e in entries if 'set' in e}
    chains = {e['chain']['name']: e['chain'] for e in entries if 'chain' in e}
    if sets != {'blocked_ips': 'ipv4_addr', 'blocked_ips_v6': 'ipv6_addr'} or set(chains) != {'input', 'output', 'forward'}:
        return False
    for name in chains:
        chain = chains[name]
        if chain.get('type') != 'filter' or chain.get('hook') != name or chain.get('prio') != 0 or chain.get('policy') != 'drop':
            return False
        actual = [_expressions(e['rule']) for e in entries if 'rule' in e and e['rule'].get('chain') == name]
        if actual != expected_rules(name, previous, ports):
            return False
    return True


def validate_legacy_layout(data):
    """Recognize only the previous owned DNS-exempt block table for migration."""
    if not _owned(data):
        return False
    entries = data.get('nftables', [])
    sets = {e['set']['name']: e['set'].get('type') for e in entries if 'set' in e}
    chains = {e['chain']['name']: e['chain'] for e in entries if 'chain' in e}
    if sets != {'blocked_ips': 'ipv4_addr', 'blocked_ips_v6': 'ipv6_addr'} or set(chains) != {'input', 'output'}:
        return False
    for name, direction in (('input', 'saddr'), ('output', 'daddr')):
        chain = chains[name]
        if chain.get('hook') != name or chain.get('prio') != -210 or chain.get('policy') != 'accept':
            return False
        allowed = []
        required = []
        for proto, setname in (('ip', 'blocked_ips'), ('ip6', 'blocked_ips_v6')):
            required.append([match({'payload': {'protocol': proto, 'field': direction}}, '@'+setname), {'counter': {}}, {'drop': None}])
        allowed.extend(required)
        for proto, ports in (('udp', 53), ('udp', 853), ('tcp', {'set': [53, 853]})):
            for field in ('sport', 'dport'):
                allowed.append([match({'payload': {'protocol': proto, 'field': field}}, ports), {'accept': None}])
        actual = [_expressions(e['rule']) for e in entries if 'rule' in e and e['rule'].get('chain') == name]
        if any(expr not in allowed for expr in actual) or any(expr not in actual for expr in required):
            return False
    return True


def setup(runner=subprocess.run, ruleset_path=RULESET):
    def call(args, **kwargs):
        return runner(['nft', *args], capture_output=True, text=True, timeout=15, **kwargs)
    # A hand-edited managed file is kept aside and rewritten from this code;
    # its content is never loaded into the kernel.
    configured = Path(ruleset_path).read_text()
    if configured != render_ruleset():
        path = Path(ruleset_path)
        os.replace(path, path.with_name(path.name + '.elle-degistirilmis-' + time.strftime('%Y%m%d-%H%M%S')))
        tmp = path.with_name(path.name + '.tmp')
        tmp.write_text(render_ruleset())
        os.chmod(tmp, 0o644)
        os.replace(tmp, path)
        configured = render_ruleset()
    listed = call(['-j', 'list', 'tables'])
    if listed.returncode:
        raise RuntimeError('Cannot inspect nftables: '+listed.stderr[:300])
    present = any(e.get('table', {}).get('family') == 'inet' and e['table'].get('name') == TABLE
                  for e in json.loads(listed.stdout).get('nftables', []))
    if present:
        old = call(['-j', 'list', 'table', 'inet', TABLE])
        if old.returncode:
            raise RuntimeError('Cannot read managed nftables table')
        data = json.loads(old.stdout)
        if validate_layout(data):
            return {'status': 'ready', 'queue': QUEUE}
        # Any earlier layout of Satsuma's own table (owner comment and both
        # block sets) is replaced chain by chain; refusing it left the
        # emergency DROP after an upgrade that changed the rules.
        sets = {e['set']['name']: e['set'].get('type') for e in data.get('nftables', []) if 'set' in e}
        if not (_owned(data) and sets == {'blocked_ips': 'ipv4_addr', 'blocked_ips_v6': 'ipv6_addr'}):
            raise RuntimeError('Unknown or foreign firewall layout; refusing migration')
        # Atomic chain replacement keeps both live block sets and their elements.
        commands = []
        old_chains = [e['chain']['name'] for e in data['nftables'] if 'chain' in e]
        for chain in old_chains:
            commands += [f'flush chain inet {TABLE} {chain}', f'delete chain inet {TABLE} {chain}']
        script = '\n'.join(commands)+'\n'+render_ruleset(include_sets=False)
    else:
        script = configured
    checked = call(['--check', '-f', '-'], input=script)
    if checked.returncode:
        raise RuntimeError('nftables validation failed: '+checked.stderr[:300])
    applied = call(['-f', '-'], input=script)
    if applied.returncode:
        raise RuntimeError('nftables transaction failed: '+applied.stderr[:300])
    readback = call(['-j', 'list', 'table', 'inet', TABLE])
    if readback.returncode or not validate_layout(json.loads(readback.stdout)):
        raise RuntimeError('Strict firewall readback verification failed')
    return {'status': 'ready', 'queue': QUEUE}


def apply_profile(selection, runner=subprocess.run, ruleset_path=None, profile_path=None):
    """Switch the live table to a new egress profile in one nft transaction.

    The live table must match the stored profile exactly. The block sets and
    their elements are kept; only the chains are replaced. The kernel changes
    first and the files follow; if the readback or the file write fails, the
    previous chains are put back.
    """
    from . import egress_profiles as profiles
    profile_path = profiles.PROFILE_FILE if profile_path is None else profile_path
    ruleset_path = RULESET if ruleset_path is None else ruleset_path
    old_selection = profiles.load(profile_path)
    old_ports, new_ports = profiles.ports_for(old_selection), profiles.ports_for(selection)

    def call(args, **kwargs):
        return runner(['nft', *args], capture_output=True, text=True, timeout=15, **kwargs)

    def live_ok(ports):
        listed = call(['-j', 'list', 'table', 'inet', TABLE])
        return listed.returncode == 0 and validate_layout(json.loads(listed.stdout), ports=ports)

    def chains_script(ports):
        commands = [f'{verb} chain inet {TABLE} {chain}' for chain in ('input', 'output', 'forward') for verb in ('flush', 'delete')]
        return '\n'.join(commands)+'\n'+render_ruleset(include_sets=False, ports=ports)

    if not live_ok(old_ports):
        raise RuntimeError('Live firewall does not match the stored egress profile; refusing to change it')
    script = chains_script(new_ports)
    checked = call(['--check', '-f', '-'], input=script)
    if checked.returncode:
        raise RuntimeError('nftables validation failed: '+checked.stderr[:300])
    applied = call(['-f', '-'], input=script)
    if applied.returncode:
        raise RuntimeError('nftables transaction failed: '+applied.stderr[:300])
    try:
        if not live_ok(new_ports):
            raise RuntimeError('Strict firewall readback verification failed')
        profiles.save(selection, profile_path)
        tmp = Path(ruleset_path).with_name('.'+Path(ruleset_path).name+'.tmp')
        tmp.write_text(render_ruleset(ports=new_ports))
        os.replace(tmp, ruleset_path)
    except Exception:
        call(['-f', '-'], input=chains_script(old_ports))
        profiles.save(old_selection, profile_path)
        Path(ruleset_path).write_text(render_ruleset(ports=old_ports))
        raise
    return {'status': 'ready', 'queue': QUEUE, 'ports': {p: list(v) for p, v in new_ports.items()}}


def block(worker,ip,reason,raw_id=None,manual=False,duration=0):
    addr=ipaddress.ip_address(ip);ip=str(addr)
    denied=worker._guard('block_ip',ip)
    if denied:return denied
    protected=worker._protected_ip(addr,manual)
    if protected == 'target_review_required' and worker.config.get('subnet_limit_authorized') is True:
        protected = None  # This explicitly enabled per-IP limit also covers local-network peers.
    if protected:return {'status':protected,'ip':ip}
    if worker.store.get('operator_allow_ips',[]) and ip in worker.store.get('operator_allow_ips',[]):return {'status':'operator_allowlisted','ip':ip}
    # Explicit operator IP-limit policies cover the remote peer in both
    # directions. Generic automatic callers retain ORIGINAL-incoming scope.
    bidirectional = (worker.config.get('subnet_limit_authorized') is True
                     or worker.config.get('otx_limit_authorized') is True
                     or (worker.config.get('auto_action_network_enabled') is True
                         and worker.config.get('destructive_response_enabled') is True
                         and 'network_isolate' in worker.config.get('destructive_allowed_actions', [])))
    if not manual and not bidirectional:
        from .incoming_response import block as block_incoming
        return block_incoming(worker,ip,reason,raw_id)
    if worker.nft_table!=TABLE or worker.nft_family!='inet':return {'status':'failed','error':'dedicated satsuma_core table required'}
    setname='blocked_ips' if addr.version==4 else 'blocked_ips_v6'
    def call(args):
        if worker.runner:
            r=worker.runner(['nft',*args]);return r if isinstance(r,dict) else vars(r)
        r=run(args);return {'returncode':r.returncode,'stdout':r.stdout,'stderr':r.stderr}
    table=call(['-j','list','table','inet',TABLE])
    try:layout_ok=table['returncode']==0 and validate_layout(json.loads(table.get('stdout','')))
    except (ValueError,KeyError,TypeError):layout_ok=False
    if not layout_ok:return {'status':'failed','error':'DROP linkage validation failed'}
    args=['inet',TABLE,setname,'{',ip,'}']
    r=call(['add','element',*args]);check=call(['get','element',*args])
    if check.get('returncode')!=0:return {'status':'failed','error':r.get('stderr') or check.get('stderr')}
    persisted=worker._persist_block(ip,setname,reason,raw_id,manual,duration)
    # The kernel block may be active even if SQLite persistence failed; do not
    # report a durable block or quietly discard the incomplete state.
    result={'status':'set_membership_confirmed' if persisted else 'set_membership_confirmed_state_unpersisted',
            'ip':ip,'set':setname,'drop_rule_linked':True,
            'traffic_drop_verified':False,'persisted':persisted,
            'scope':'bidirectional_peer'}
    try:
        worker.store.add('actions',{**result,'timestamp':time.time(),'reason':reason,'raw_id':raw_id})
    except Exception:
        result['audit_write_failed'] = True
    return result


def unblock(worker, ip, reason, manual=False):
    """Remove only the named address after exact table and kernel readback checks."""
    addr=ipaddress.ip_address(ip);ip=str(addr)
    denied=worker._guard('unblock_ip',ip)
    if denied:return {'ok':False,**denied}
    if worker.nft_table!=TABLE or worker.nft_family!='inet':
        return {'ok':False,'status':'failed','error':'dedicated satsuma_core table required'}
    setname='blocked_ips' if addr.version==4 else 'blocked_ips_v6'
    def call(args):
        if worker.runner:
            result=worker.runner(['nft',*args]);return result if isinstance(result,dict) else vars(result)
        result=run(args);return vars(result)
    def members():
        result=call(['-j','list','table','inet',TABLE])
        if result.get('returncode')!=0:raise RuntimeError('Cannot verify firewall table')
        data=json.loads(result.get('stdout',''))
        if not validate_layout(data):raise RuntimeError('Strict firewall layout is not verified')
        definition=next(e['set'] for e in data['nftables'] if e.get('set',{}).get('name')==setname)
        values=definition.get('elem',[])
        if not isinstance(values,list) or any(not isinstance(x,str) for x in values):
            raise RuntimeError('Unsupported set element representation')
        return {str(ipaddress.ip_address(x)) for x in values}
    from .incoming_response import unblock_existing
    unblock_existing(worker,ip)
    if ip in members():
        call(['delete','element','inet',TABLE,setname,'{',ip,'}'])
    if ip in members():
        return {'ok':False,'status':'failed','error':'Address remains in firewall set','ip':ip}
    try:
        if getattr(worker.store,'db',None) is not None:
            worker.store.db.execute('BEGIN IMMEDIATE')
        blocks=worker._persistent_blocks();blocks.pop(ip,None)
        worker.store.set('persistent_blocks',blocks)
    except Exception:
        if getattr(worker.store,'db',None) is not None:worker.store.db.rollback()
        raise
    worker.blocked.discard(ip)
    result={'ok':True,'status':'set_absence_confirmed','ip':ip,'set':setname,'persisted':True}
    worker.store.add('actions',{'action':'unblock_ip','timestamp':time.time(),'reason':reason,'manual':manual,**result})
    return result


def lockdown(runner=subprocess.run):
    """On an unrecognized/failed policy, close external traffic in a reserved table.

    DHCP, NTP and TeamViewer/AnyDesk stay open outbound so the operator can
    still reach the machine, through the Suricata queue (2.2.41): with Suricata
    down they are closed too. Tanınmayan ya da başarısız ilkede dış trafik ayrı
    bir tabloda kapatılır; DHCP, NTP ve TeamViewer/AnyDesk yalnızca Suricata
    kuyruğundan geçerek açık kalır (2.2.41).
    """
    listed = runner(['nft','-j','list','tables'],capture_output=True,text=True,timeout=10,check=True)
    present = any(e.get('table',{}).get('family')=='inet' and e['table'].get('name')=='satsuma_lockdown'
                  for e in json.loads(listed.stdout).get('nftables',[]))
    script = 'delete table inet satsuma_lockdown\n' if present else ''
    script += 'table inet satsuma_lockdown {\n'
    for chain in ('input','output','forward'):
        script += f' chain {chain} {{ type filter hook {chain} priority -300; policy drop;\n'
        if chain != 'forward':
            script += ('  iifname' if chain=='input' else '  oifname')+' "lo" accept\n'
        # Address, clock and remote support survive the lockdown only through
        # Suricata (2.2.41; accepted directly from 2.2.16 to 2.2.40). No bypass flag:
        # with no queue consumer these packets are dropped.
        for proto in ('tcp', 'udp'):
            if chain == 'output':
                script += f'  {proto} dport {_port_text(ALWAYS_QUEUED[proto])} queue num {QUEUE}\n'
            elif chain == 'input':
                script += f'  ct state established ct direction reply {proto} sport {_port_text(ALWAYS_QUEUED[proto])} queue num {QUEUE}\n'
        script += ' }\n'
    script += '}\n'
    result=runner(['nft','-f','-'],input=script,capture_output=True,text=True,timeout=10,check=True)
    return {'status':'lockdown','reason':'strict_policy_could_not_be_verified'}


def remove_lockdown(runner=subprocess.run):
    listed=runner(['nft','-j','list','tables'],capture_output=True,text=True,timeout=10,check=True)
    if any(e.get('table',{}).get('family')=='inet' and e['table'].get('name')=='satsuma_lockdown'
           for e in json.loads(listed.stdout).get('nftables',[])):
        runner(['nft','delete','table','inet','satsuma_lockdown'],capture_output=True,text=True,timeout=10,check=True)
