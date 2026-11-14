#!/usr/bin/env python3
"""Independent OMNI-SENTINEL rescue: no Core database, GUI or package imports.

Only runs response lanes while at least two network protection units are down.
Existing firewall rules are never flushed. Original-direction input blocks only.
"""
import collections
import concurrent.futures
import ipaddress
import json
import os
from pathlib import Path
import re
import signal
import stat
import pwd
import subprocess
import tempfile
import time
import urllib.request

UNITS = ('satsuma-network.service', 'satsuma-suricata-ips.service',
         'satsuma-suricata-otx-guard.service', 'satsuma-core.service')
TABLE = 'satsuma_rescue'
STOP = False
MAX_BYTES = 4 * 1024 * 1024


def event(kind, **fields):
    print(json.dumps(dict(time=time.time(), source='omni_sentinel_rescue', event=kind, **fields)), flush=True)


def command(argv, **kwargs):
    # Temporary files prevent an unbounded pipe allocation or stderr deadlock.
    with tempfile.TemporaryFile(mode='w+b') as out, tempfile.TemporaryFile(mode='w+b') as err:
        result = subprocess.run(argv, stdout=out, stderr=err, text=True, timeout=5, **kwargs)
        out.seek(0); err.seek(0)
        output, error = out.read(MAX_BYTES+1), err.read(65537)
        if len(output)>MAX_BYTES or len(error)>65536:
            raise RuntimeError('Command output exceeds rescue capacity')
        return subprocess.CompletedProcess(argv,result.returncode,output.decode('utf-8','replace'),error.decode('utf-8','replace'))


def checked(argv):
    result=command(argv)
    if result.returncode:raise RuntimeError('Command failed: '+argv[0]+': '+result.stderr[:200])
    return result.stdout


def failed_units(states):
    # Unknown/activating/reloading are not fabricated as confirmed outages.
    return [unit for unit in UNITS if states.get(unit) in ('inactive','failed','deactivating')]


def service_states():
    states={}
    for unit in UNITS:
        result=command(['/usr/bin/systemctl','show',unit,'--property=LoadState,ActiveState'])
        if result.returncode:raise RuntimeError('systemd state query failed: '+unit)
        values=dict(line.split('=',1) for line in result.stdout.splitlines() if '=' in line)
        if values.get('LoadState')=='not-found':states[unit]='failed'
        elif values.get('ActiveState') in ('active','inactive','failed','activating','deactivating','reloading'):
            states[unit]=values['ActiveState']
        else:raise RuntimeError('Unknown systemd state: '+unit)
    return states


def trusted_file(path, private=False):
    fd=os.open(path,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK)
    try:
        info=os.fstat(fd)
        owners={0}
        if not private:
            try:
                account=pwd.getpwnam('suricata')
                if account.pw_uid<1000:owners.add(account.pw_uid)
            except KeyError:pass
        if not stat.S_ISREG(info.st_mode) or info.st_uid not in owners or info.st_mode & (0o077 if private else 0o022) or info.st_nlink!=1:
            raise PermissionError('Unsafe rescue input: '+str(path))
        return os.fdopen(fd,'rb')
    except BaseException:
        os.close(fd);raise


def public_peer(src,dst,own):
    try:
        address=ipaddress.ip_address(src)
        return address.is_global and not address.is_multicast and src not in own and dst in own
    except ValueError:return False


def flow_snapshot():
    addresses=json.loads(checked(['/usr/sbin/ip','-j','address','show']))
    own={str(ipaddress.ip_address(item['local'])) for device in addresses for item in device.get('addr_info',[]) if 'local' in item}
    if not own:raise RuntimeError('Local IP inventory unavailable')
    flows=set()
    for family in ('ipv4','ipv6'):
        text=checked(['/usr/sbin/conntrack','-L','-f',family])
        for line in text.splitlines():
            protocol=line.split(' ',1)[0]
            # Audit K2: only completed TCP connections. One forged UDP packet, or a
            # bare SYN, creates an ORIGINAL entry for any source address it claims.
            # Denetim K2: yalnızca tamamlanmış TCP bağlantıları; tek bir sahte UDP
            # paketi ya da yalın SYN, iddia ettiği her kaynak için kayıt oluşturur.
            if protocol!='tcp' or '[ASSURED]' not in line:continue
            found=re.search(r'\bsrc=(\S+)\s+dst=(\S+)\s+sport=(\d+)\s+dport=(\d+)',line)
            if not found:continue
            src,dst=str(ipaddress.ip_address(found[1])),str(ipaddress.ip_address(found[2]))
            if public_peer(src,dst,own):flows.add((protocol,src,dst,int(found[3]),int(found[4])))
    if len(flows)>10000:raise RuntimeError('Incoming flow inventory exceeds capacity')
    return flows


def resolvers():
    """Nameservers in resolv.conf; blocking one would cut this host off."""
    found=set()
    try:
        with open('/etc/resolv.conf',encoding='ascii',errors='replace') as stream:
            for line in stream.read(65536).splitlines():
                fields=line.split()
                if len(fields)>=2 and fields[0]=='nameserver':
                    try:found.add(str(ipaddress.ip_address(fields[1].split('%',1)[0])))
                    except ValueError:pass
    except OSError:pass
    return found


def endpoint(value):
    host,port=value.rsplit(':',1)
    port=int(port)
    if not 0<=port<=65535:raise ValueError('Port out of range')
    return str(ipaddress.ip_address(host.strip('[]'))),port


FAST=re.compile(r'\[Priority:\s*([123])\].*?\{(TCP|UDP)\}\s+(\S+)\s+->\s+(\S+)\s*$',re.I)


def fast_candidates(line,flows):
    match=FAST.search(line)
    if not match:return []
    try:
        src,sport=endpoint(match[3]);dst,dport=endpoint(match[4])
    except ValueError:return []
    if (match[2].lower(),src,dst,sport,dport) not in flows:return []
    return [(src,'suricata_priority_'+match[1])]


class FastLane:
    def __init__(self,path='/var/log/suricata/fast.log'):
        self.path=path;self.cursor=None
    def scan(self,flows):
        with trusted_file(self.path) as stream:
            info=os.fstat(stream.fileno());identity=(info.st_dev,info.st_ino)
            offset=self.cursor[2] if self.cursor and self.cursor[:2]==identity and self.cursor[2]<=info.st_size else 0
            if offset and len(self.cursor)>=6:
                anchor_start=max(0,offset-64)
                stream.seek(anchor_start)
                anchor=stream.read(offset-anchor_start).hex()
                if anchor!=self.cursor[3] or (info.st_size<=self.cursor[4] and info.st_ctime_ns!=self.cursor[5]):
                    offset=0
            stream.seek(offset);candidates=[]
            # First activation replays bounded batches, not just the last 2000 lines.
            for _ in range(512):
                start=stream.tell();line=stream.readline(65537)
                if not line:break
                if len(line)>65536:raise RuntimeError('Oversize fast.log line: cursor retained for inspection')
                if not line.endswith(b'\n'):stream.seek(start);break
                candidates.extend(fast_candidates(line.decode('utf-8','replace'),flows))
            position=stream.tell();anchor_start=max(0,position-64)
            stream.seek(anchor_start);anchor=stream.read(position-anchor_start).hex()
            return candidates,(*identity,position,anchor,info.st_size,info.st_ctime_ns)
    def commit(self,cursor):self.cursor=cursor


def burst_candidates(flows,threshold=10):
    groups=collections.defaultdict(set)
    for _,src,_,_,_ in flows:
        address=ipaddress.ip_address(src)
        if address.version==4:groups[str(ipaddress.ip_network(src+'/24',strict=False))].add(src)
    # A /24 is a counting group only: individual verified incoming peers are blocked.
    return [(ip,'distinct_incoming_peers_per_24') for members in groups.values() if len(members)>=threshold for ip in sorted(members)]


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self,*args,**kwargs):raise ValueError('OTX redirects rejected')


class OtxLane:
    def __init__(self,key_path='/etc/satsuma-core/otx-api.key'):
        self.key_path=key_path;self.cache={};self.requests=collections.deque();self.cursor=0
    def scan(self,flows):
        with trusted_file(self.key_path,private=True) as key_file:
            key=key_file.read(4097).strip()
        if not key or len(key)>4096:raise RuntimeError('OTX key missing or exceeds capacity')
        key=key.decode('ascii');now=time.monotonic()
        while self.requests and now-self.requests[0]>3600:self.requests.popleft()
        peers=sorted({flow[1] for flow in flows});candidates=[]
        if not peers:return candidates,None
        # Rotate bounded requests to avoid starving later peers.
        start=self.cursor % len(peers);peers=peers[start:]+peers[:start];self.cursor+=4
        checks=0
        for ip in peers:
            cached=self.cache.get(ip)
            if cached and now-cached[0]<3600:
                if cached[1]:candidates.append((ip,'otx_pulses_gt_35'))
                continue
            if checks>=4 or len(self.requests)>=120:continue
            checks+=1;self.requests.append(now)
            family='IPv4' if ipaddress.ip_address(ip).version==4 else 'IPv6'
            request=urllib.request.Request('https://otx.alienvault.com/api/v1/indicators/'+family+'/'+ip+'/general',headers={'X-OTX-API-KEY':key,'User-Agent':'Satsuma-Rescue/1'})
            opener=urllib.request.build_opener(NoRedirect())
            with opener.open(request,timeout=4) as response:
                raw=response.read(262145)
            if len(raw)>262144:raise RuntimeError('OTX response exceeds capacity')
            count=json.loads(raw).get('pulse_info',{}).get('count')
            if type(count) is not int or count<0:raise ValueError('Invalid OTX pulse count')
            verdict=count>35
            self.cache[ip]=(now,verdict)
            while len(self.cache)>500:self.cache.pop(next(iter(self.cache)))
            if verdict:candidates.append((ip,'otx_pulses_gt_35'))
        return candidates,None


class Nft:
    TABLE = 'satsuma_rescue'

    def verify_layout(self):
        try:
            entries = json.loads(self.run(['nft', '-j', 'list', 'table', 'inet', self.TABLE]))['nftables']
            chains = {e['chain']['name']: e['chain'] for e in entries if 'chain' in e}
            sets = {e['set']['name']: e['set'] for e in entries if 'set' in e}
            if set(chains) != {'input', 'forward'} or set(sets) != {'blocked_v4', 'blocked_v6'}:
                raise ValueError('Unexpected chains or sets')
            for name, family in [('blocked_v4', 'ipv4_addr'), ('blocked_v6', 'ipv6_addr')]:
                if sets[name].get('type') != family or sets[name].get('flags'):
                    raise ValueError('Unexpected address set type/flags')
            for name, chain in chains.items():
                if (chain.get('family'), chain.get('table'), chain.get('type'), chain.get('hook'),
                    chain.get('prio'), chain.get('policy')) != ('inet', self.TABLE, 'filter', name, -150, 'accept'):
                    raise ValueError('Unexpected chain hook/priority/policy')
                actual = []
                for entry in entries:
                    rule = entry.get('rule', {})
                    if rule.get('chain') == name:
                        if rule.get('family') != 'inet' or rule.get('table') != self.TABLE:
                            raise ValueError('Unexpected rule owner')
                        expr = []
                        for term in rule['expr']:
                            if 'counter' in term:
                                expr.append({'counter': None})
                            elif 'match' in term and term['match'].get('left') == {'ct': {'key': 'direction'}}:
                                match = dict(term['match'])
                                match['right'] = {'original': 0, 'reply': 1}.get(match['right'], match['right'])
                                expr.append({'match': match})
                            else:
                                expr.append(term)
                        actual.append(expr)
                expected = []
                if name == 'input':
                    expected.append([{'match': {'op': '==', 'left': {'meta': {'key': 'iifname'}}, 'right': 'lo'}}, {'accept': None}])
                for family, target in [('ip', 'blocked_v4'), ('ip6', 'blocked_v6')]:
                    expected.append([
                        {'match': {'op': '==', 'left': {'ct': {'key': 'direction'}}, 'right': 0}},
                        {'match': {'op': '==', 'left': {'payload': {'protocol': family, 'field': 'saddr'}}, 'right': '@'+target}},
                        {'counter': None}, {'drop': None}])
                if actual != expected:
                    raise ValueError('Incoming-only DROP linkage differs from policy')
        except (ValueError, KeyError, TypeError) as exc:
            raise RuntimeError('nft guard layout verification failed: '+str(exc)) from exc

    def run(self, cmd, input_text=None):
        try:
            result = command(cmd, input=input_text)
        except (OSError, subprocess.TimeoutExpired) as exc:
            raise RuntimeError('nft command failed: ' + str(exc)) from exc
        if result.returncode:
            raise RuntimeError('nft: ' + (result.stderr or result.stdout).strip()[:500])
        return result.stdout

    def setup(self):
        """Never flush other tables, chains or sets. We own only satsuma_otx_guard."""
        exists = command(['nft', 'list', 'table', 'inet', self.TABLE])
        if exists.returncode:
            script = f'''add table inet {self.TABLE}
add set inet {self.TABLE} blocked_v4 {{ type ipv4_addr; }}
add set inet {self.TABLE} blocked_v6 {{ type ipv6_addr; }}
add chain inet {self.TABLE} input {{ type filter hook input priority -150; policy accept; }}
add chain inet {self.TABLE} forward {{ type filter hook forward priority -150; policy accept; }}
add rule inet {self.TABLE} input iifname "lo" accept
add rule inet {self.TABLE} input ct direction original ip saddr @blocked_v4 counter drop
add rule inet {self.TABLE} input ct direction original ip6 saddr @blocked_v6 counter drop
add rule inet {self.TABLE} forward ct direction original ip saddr @blocked_v4 counter drop
add rule inet {self.TABLE} forward ct direction original ip6 saddr @blocked_v6 counter drop
'''
            self.run(['nft', '-f', '-'], input_text=script)
        else:
            for set_name in ('blocked_v4', 'blocked_v6'):
                self.run(['nft', 'list', 'set', 'inet', self.TABLE, set_name])
            for chain in ('input', 'forward'):
                self.run(['nft', 'list', 'chain', 'inet', self.TABLE, chain])
        self.verify_layout()

    def contains(self, ip):
        addr = ipaddress.ip_address(ip)
        target = 'blocked_v4' if addr.version == 4 else 'blocked_v6'
        try:
            data = json.loads(self.run(['nft', '-j', 'list', 'set', 'inet', self.TABLE, target]))
            sets = [entry['set'] for entry in data['nftables']
                    if isinstance(entry, dict) and 'set' in entry]
            matches = [s for s in sets if s.get('family') == 'inet'
                       and s.get('table') == self.TABLE and s.get('name') == target]
            if len(matches) != 1:
                raise ValueError('Expected owned nft set is missing or ambiguous')
            members = matches[0].get('elem', [])
            if not isinstance(members, list):
                raise ValueError('Invalid nft set elements')
            addresses = set()
            for member in members:
                if isinstance(member, dict):
                    member = member['elem']['val']
                parsed = ipaddress.ip_address(member)
                if parsed.version != addr.version:
                    raise ValueError('Unexpected nft address family')
                addresses.add(str(parsed))
            return str(addr) in addresses
        except (ValueError, KeyError, TypeError) as exc:
            raise RuntimeError('nft readback could not be verified: ' + str(exc)) from exc

    def block(self, ip):
        addr = ipaddress.ip_address(ip)
        target = 'blocked_v4' if addr.version == 4 else 'blocked_v6'
        if not self.contains(str(addr)):
            try:
                self.run(['nft', 'add', 'element', 'inet', self.TABLE, target, '{', str(addr), '}'])
            except RuntimeError:
                # Another writer may have inserted it; only kernel readback counts.
                if not self.contains(str(addr)):
                    raise
        if not self.contains(str(addr)):
            raise RuntimeError('nft block failed kernel readback')

    def unblock(self, ip):
        addr = ipaddress.ip_address(ip)
        target = 'blocked_v4' if addr.version == 4 else 'blocked_v6'
        self.run(['nft', 'delete', 'element', 'inet', self.TABLE, target, '{', str(addr), '}'])
        if self.contains(str(addr)):
            raise RuntimeError('nft unblock failed kernel readback')


def save_status(record,path='/run/satsuma-rescue/status.json'):
    target=Path(path)
    # RuntimeDirectory is root-owned 0700; replace never follows a target symlink.
    with tempfile.NamedTemporaryFile(mode='w',dir=target.parent,delete=False) as stream:
        temporary=stream.name
        json.dump(record,stream);stream.flush();os.fsync(stream.fileno())
    try:os.replace(temporary,target)
    finally:
        if os.path.exists(temporary):os.unlink(temporary)


def stopped(*_):
    global STOP
    STOP=True


def run():
    if os.geteuid()!=0:raise PermissionError('Rescue requires root')
    signal.signal(signal.SIGTERM,stopped);signal.signal(signal.SIGINT,stopped)
    fast=FastLane();otx=OtxLane();nft=Nft()
    lanes={'fast':fast.scan,'otx':otx.scan,'burst':lambda flows:(burst_candidates(flows),None)}
    health={name:'WAITING' for name in lanes};pending={}
    active=False;generation=0;recovered=0;last_repair=0
    with concurrent.futures.ThreadPoolExecutor(max_workers=3,thread_name_prefix='rescue') as pool:
        while not STOP:
            try:
                states=service_states();down=failed_units(states)
                uptime=float(Path('/proc/uptime').read_text().split()[0])
                trigger=len(down)>=2 and uptime>=90
                if trigger and not active:
                    active=True;generation+=1;recovered=0
                    health={name:"WAITING" for name in lanes}
                    event('automatic_takeover',down=down,confirmation_required=False)
                elif active and not trigger:
                    # Require known recovered states twice, without removing protection rules.
                    if all(value=='active' for value in states.values()):recovered+=1
                    else:recovered=0
                    if recovered>=2:
                        active=False;generation+=1
                        event('standby_restored',existing_blocks_retained=True)
                if active:
                    if time.monotonic()-last_repair>=60:
                        repair=command(['/usr/bin/systemctl','start','--no-block','satsuma-network.service','satsuma-suricata-ips.service'])
                        event('suricata_recovery_requested',accepted=repair.returncode==0)
                        last_repair=time.monotonic()
                    ready=False
                    try:
                        nft.setup();flows=flow_snapshot();ready=True
                    except Exception as exc:
                        event('response_unavailable',detail=str(exc)[:250])
                    if ready:
                        peers={flow[1] for flow in flows}
                        protected=resolvers()
                        for name,(future,epoch) in list(pending.items()):
                            if not future.done():continue
                            del pending[name]
                            if epoch!=generation:continue
                            try:
                                candidates,cursor=future.result()
                                for ip,reason in candidates:
                                    # A slow OTX answer must still have an incoming original flow now.
                                    if ip not in peers or ip in protected:continue
                                    nft.verify_layout();nft.block(ip)
                                    event('incoming_ip_block',ip=ip,reason=reason,kernel_membership_verified=True,traffic_prevention_tested=False)
                                if name=='fast':fast.commit(cursor)
                                health[name]='AVAILABLE'
                            except Exception as exc:
                                health[name]='DEGRADED'
                                event('lane_degraded',lane=name,detail=str(exc)[:250])
                        for name,work in lanes.items():
                            if name not in pending:pending[name]=(pool.submit(work,flows),generation)
                    status={'mode':'RESCUE_ACTIVE' if ready else 'RESCUE_DEGRADED',
                            'status':'RUNNING' if ready and all(value=='AVAILABLE' for value in health.values()) and states['satsuma-suricata-ips.service']=='active' else 'DEGRADED','down':down,
                            'states':states,'lanes':dict(health),'suricata_active':states['satsuma-suricata-ips.service']=='active',
                            'traffic_prevention_tested':False,'updated_at':time.time()}
                else:
                    for name,(future,_) in list(pending.items()):
                        if future.done():del pending[name]
                    status={'mode':'BOOT_GRACE' if uptime<90 else 'ARMED','status':'ARMED','down':down,'states':states,'updated_at':time.time()}
                save_status(status)
            except Exception as exc:
                # Never turn unknown systemd state into a fabricated healthy report.
                event('watchdog_degraded',detail=str(exc)[:250])
                save_status({'mode':'WATCHDOG_DEGRADED','takeover_latched':active,'updated_at':time.time()})
            for _ in range(10):
                if STOP:break
                time.sleep(.5)
    event('rescue_stopped',existing_blocks_retained=True)


if __name__=='__main__':run()
