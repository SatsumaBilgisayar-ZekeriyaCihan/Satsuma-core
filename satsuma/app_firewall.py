"""Satsuma-owned process firewall. Unknown/ambiguous identities never receive a grant.

Permission covers the executable and UID, including code it loads. This is not a
sandbox against hostile root, injected code, or interpreter scripts sharing a binary.

Only the first packet of a connection is queued (2.2.30). Field report
2026-11-04: every outgoing packet went through the queue, and each batch scanned
every socket on the machine, so App Control lagged and the internet stalled. A
connection's later packets now pass once it was allowed; a denied first packet
never creates an established connection. WireGuard's own encrypted packets
come from the kernel, not from a process, and carry Satsuma's WireGuard fwmark;
they pass, while traffic inside the tunnel is still decided per program.
While OpenSnitch runs (satsuma.opensnitch), App Control steps aside and
comes back on its own when OpenSnitch stops.

Satsuma'ya ait süreç güvenlik duvarı. Bilinmeyen ya da belirsiz kimlik izin almaz.
İzin, program dosyasını ve kullanıcıyı kapsar. Yalnızca bağlantının ilk paketi
kuyruğa girer (2.2.30): saha bildirimi 2026-11-04'te her giden paket kuyruktan
geçiyor ve her yığın bütün soketleri tarıyordu; App Control gecikiyor, internet
takılıyordu. İzin verilmiş bağlantının sonraki paketleri artık doğrudan geçer;
reddedilen ilk paket kurulmuş bağlantı oluşturmaz. WireGuard'ın şifreli paketleri
bir süreçten değil çekirdekten gelir ve Satsuma'nın WireGuard fwmark'ını taşır;
bunlar geçer, tünelin içindeki trafik yine programa göre değerlendirilir.
OpenSnitch çalışırken (satsuma.opensnitch) App Control kenara çekilir,
OpenSnitch durunca kendiliğinden geri gelir.
"""
import hashlib
import ipaddress
import json
import os
from pathlib import Path
import socket
import struct
import subprocess
import time

from .protected_storage import RootDataStore
TABLE='satsuma_app_control'
OWNER='Satsuma process firewall v1'
QUEUE=201
# satsuma.wireguard.FWMARK: the outer packets of Satsuma's WireGuard profiles.
WG_MARK=51847
_HASH_CACHE={}
_RPM_DIGESTS={}
TRUSTED_UNITS=frozenset(('satsuma-core.service','satsuma-teams.service','satsuma-core-otx.service',
    'satsuma-core-sentinel.service','satsuma-core-gateway.service','satsuma-core-subnet.service',
    'satsuma-core-dns.service','satsuma-core-dns-refresh.service','satsuma-suricata-ips.service',
    'satsuma-suricata-otx-guard.service','satsuma-rescue.service','satsuma-operator.service'))


def process_cgroup(pid):
    rows=Path(f'/proc/{pid}/cgroup').read_text().splitlines()
    groups=[row[3:] for row in rows if row.startswith('0::')]
    return groups[0] if len(groups)==1 else ''


def trusted_dependency(app,runner=subprocess.run):
    # Exact system service cgroup: desktop programs using the same Python binary
    # do not inherit Satsuma's dependency grant. Descendant/delegated groups are excluded.
    group=app.get('cgroup','')
    unit=group.removeprefix('/system.slice/')
    if group!='/system.slice/'+unit or unit not in TRUSTED_UNITS:return False
    import pwd
    uid=pwd.getpwnam('satsuma-dns').pw_uid if unit=='satsuma-core-dns.service' else 0
    if app['uid']!=uid:return False
    expected=('/usr/sbin/dnsmasq',) if unit=='satsuma-core-dns.service' else ('/usr/bin/python3','/usr/bin/suricata','/usr/sbin/suricata')
    if unit=='satsuma-core-sentinel.service':expected=(*expected,'/usr/bin/dig')
    if app['executable'] not in {str(Path(path).resolve()) for path in expected}:return False
    path=app['executable']
    if path not in _RPM_DIGESTS:
        result=runner(['/usr/bin/rpm','-qf','--qf','[%{FILENAMES}\t%{FILEDIGESTS}\n]',path],capture_output=True,text=True,timeout=10)
        if result.returncode:raise RuntimeError('Dependency is not RPM-owned')
        values={line.split('\t',1)[1] for line in result.stdout.splitlines() if line.split('\t',1)[0]==path and '\t' in line}
        if len(values)!=1:raise RuntimeError('Ambiguous dependency digest')
        _RPM_DIGESTS[path]=values.pop()
    return app['sha256']==_RPM_DIGESTS[path]

ROOT=Path('/var/lib/satsuma-core/app-control')


def read_record(name, default):
    from installer.integrity import safe_read
    try:
        raw,_=safe_read(ROOT/name,limit=4*1024*1024)
        result=json.loads(raw)
        if not isinstance(result,dict):raise ValueError('Invalid app-control record')
        return result
    except FileNotFoundError:return default


def policy():
    data=read_record('policy.json',{'schema':1,'enabled':True,'rules':{}})
    if (data.get('schema')!=1 or type(data.get('enabled')) is not bool
        or not isinstance(data.get('rules'),dict)):raise ValueError('Invalid App Control policy')
    data.setdefault('application_rules',{})
    if not isinstance(data['application_rules'],dict):raise ValueError('Invalid application rules')
    for collection in ('rules','application_rules'):
        for key,value in data[collection].items():
            if not isinstance(key,str) or len(key)!=64 or any(c not in '0123456789abcdef' for c in key) or value not in ('allow','deny','ask'):
                raise ValueError('Invalid App Control rule')
    return data


def identity(pid):
    import psutil
    proc=psutil.Process(pid)
    born=proc.create_time()
    uid=proc.uids().effective
    path=proc.exe()
    group=process_cgroup(pid)
    if not path.startswith('/') or path.endswith(' (deleted)'):raise ValueError('Unstable executable')
    fd=os.open(f'/proc/{pid}/exe',os.O_RDONLY|os.O_NONBLOCK)
    with os.fdopen(fd,'rb') as stream:
        before=os.fstat(stream.fileno())
        if before.st_size>512*1024*1024:raise ValueError('Executable exceeds hashing budget')
        cache_key=(before.st_dev,before.st_ino,before.st_size,before.st_mtime_ns,before.st_ctime_ns)
        digest=_HASH_CACHE.get(cache_key)
        if digest is None:
            digest=hashlib.file_digest(stream,'sha256').hexdigest()
            if len(_HASH_CACHE)>=256:_HASH_CACHE.clear()
            _HASH_CACHE[cache_key]=digest
        after=os.fstat(stream.fileno())
    if (before.st_ino,before.st_dev,before.st_size,before.st_mtime_ns,before.st_ctime_ns)!=(after.st_ino,after.st_dev,after.st_size,after.st_mtime_ns,after.st_ctime_ns):
        raise ValueError('Executable changed while hashing')
    if proc.create_time()!=born or proc.exe()!=path or proc.uids().effective!=uid or process_cgroup(pid)!=group:raise ValueError('Process changed')
    current=os.stat(f'/proc/{pid}/exe')
    if (current.st_dev,current.st_ino)!=(before.st_dev,before.st_ino):raise ValueError('Executable replaced')
    from .python_entry import resolve as resolve_python_entry, _python_executable
    entry = resolve_python_entry(proc, path)
    # An unverified Python entry must NOT inherit a blanket interpreter grant.
    # A verified script gets a distinct, content-bound application identity.
    # Unverifiable entry points are process-lifetime scoped (not remembered).
    if _python_executable(path):
        scope = ['python', entry['path'], entry['sha256']] if entry and entry['status']=='verified' else ['python_unverified', pid, born]
    else:
        scope = ['native']
    key=hashlib.sha256(json.dumps([uid,path,digest,group,scope],separators=(',',':')).encode()).hexdigest()
    application_key=hashlib.sha256(json.dumps([uid,path,digest,scope],separators=(',',':')).encode()).hexdigest()
    return {'key':key,'application_key':application_key,'pid':pid,'created_at':born,
            'uid':uid,'executable':path,'sha256':digest,'cgroup':group,
            'python_entry':entry, 'identity_verified':entry is None or entry.get('status')=='verified'}


def parse_packet(raw):
    if not raw:raise ValueError('Empty packet')
    version=raw[0]>>4
    if version==4:
        if len(raw)<20:raise ValueError('Short IPv4 packet')
        offset=(raw[0]&15)*4
        total=int.from_bytes(raw[2:4],'big')
        if offset<20 or total>len(raw) or int.from_bytes(raw[6:8],'big')&0x3fff:
            raise ValueError('Malformed or fragmented IPv4')
        proto=raw[9];src=str(ipaddress.ip_address(raw[12:16]));dst=str(ipaddress.ip_address(raw[16:20]))
    elif version==6:
        if len(raw)<40:raise ValueError('Short IPv6 packet')
        offset=40;total=40+int.from_bytes(raw[4:6],'big');proto=raw[6]
        if total>len(raw):raise ValueError('Truncated IPv6')
        src=str(ipaddress.ip_address(raw[8:24]));dst=str(ipaddress.ip_address(raw[24:40]))
        # Bounded extension-header walk; fragments/ESP are not attributable here.
        for _ in range(8):
            if proto not in (0,43,60):break
            if offset+2>total:raise ValueError('Short extension')
            nxt=raw[offset];length=(raw[offset+1]+1)*8
            offset+=length;proto=nxt
        if offset>total:raise ValueError('Invalid extension length')
    else:raise ValueError('Unsupported network protocol')
    if proto not in (6,17) or offset+4>total:raise ValueError('Unsupported transport')
    sport,dport=struct.unpack('!HH',raw[offset:offset+4])
    return (version,proto,src,sport,dst,dport)


class OwnerMissing(ValueError):
    """No socket in the snapshot belongs to the packet (a socket opened after the snapshot).

    Anlık görüntüde pakete ait soket yok (görüntüden sonra açılmış bir soket).
    """


class Attribution:
    """A per-batch socket snapshot that is taken again, a few times, when a socket is missing.

    The snapshot is taken when a batch of queued packets starts. The first packet of a
    connection can be queued a moment after that, so its socket is not in the snapshot,
    and the packet used to be dropped as "unattributed" until TCP retried a second later.
    A missing owner now triggers up to ``rescans`` new snapshots per batch. An ambiguous
    owner never does, and an exhausted budget still fails closed.

    Her yığın için soket anlık görüntüsü; soket bulunamazsa birkaç kez yeniden alınır.
    Görüntü, kuyruktaki paket yığını başlarken alınır. Bir bağlantının ilk paketi bundan
    biraz sonra kuyruğa girebilir; soketi görüntüde olmaz ve paket, TCP bir saniye sonra
    yeniden deneyene kadar "sahipsiz" diye düşürülürdü. Eksik sahip artık yığın başına en
    çok ``rescans`` yeni görüntü başlatır. Belirsiz sahip asla başlatmaz; bütçe tükenirse
    yine kapalı başarısız olur.
    """
    def __init__(self, scan, rescans=3):
        self.scan, self.rescans = scan, rescans
        self.owners, self.left, self.scans = None, 0, 0

    def begin(self):
        self.owners, self.left = None, self.rescans
        self.owners = self.scan()
        self.scans += 1
        return self.owners

    def end(self):
        self.owners = None

    def resolve(self, flow):
        if self.owners is None:
            raise ValueError('Socket snapshot unavailable')
        try:
            return self.owners.resolve(flow)
        except OwnerMissing:
            if self.left <= 0:
                raise
            self.left -= 1
            self.owners = self.scan()
            self.scans += 1
            return self.owners.resolve(flow)


class SocketOwners:
    """One bounded index per received batch; never stores permission verdicts."""
    def __init__(self, entries):
        self.exact,self.wild={},{}
        for count,item in enumerate(entries):
            if count>=200000:raise ValueError('Socket attribution capacity exceeded')
            if not item.pid or not item.laddr:continue
            if item.family not in (socket.AF_INET,socket.AF_INET6):continue
            if item.type not in (socket.SOCK_STREAM,socket.SOCK_DGRAM):continue
            version=4;local=item.laddr.ip
            remote=item.raddr.ip if item.raddr else None
            # Linux exposes dual-stack IPv4 sockets as AF_INET6 with
            # IPv4-mapped addresses. Match their actual wire address family,
            # including conflicts with native IPv4 owners of the same tuple.
            if item.family==socket.AF_INET6:
                local_address=ipaddress.IPv6Address(local)
                local_address=local_address.ipv4_mapped or local_address
                version=local_address.version;local=str(local_address)
                if remote is not None:
                    remote_address=ipaddress.IPv6Address(remote)
                    remote=str(remote_address.ipv4_mapped or remote_address)
            # psutil already gives canonical IPv4 strings from the kernel.
            # Only IPv6/mapped addresses need normalization here.
            prefix=(version,6 if item.type==socket.SOCK_STREAM else 17,local,item.laddr.port)
            if remote:self.exact.setdefault((*prefix,remote,item.raddr.port),set()).add(item.pid)
            elif item.type==socket.SOCK_DGRAM:self.wild.setdefault(prefix,set()).add(item.pid)

    def resolve(self,flow):
        version,proto,src,sport,dst,dport=flow
        candidates=set()
        for local in {src,'0.0.0.0' if version==4 else '::'}:
            prefix=(version,proto,local,sport)
            candidates.update(self.exact.get((*prefix,dst,dport),()))
            if proto==17:candidates.update(self.wild.get(prefix,()))
        # One message for both, as before; the class tells them apart (OwnerMissing).
        if not candidates:raise OwnerMissing('Socket owner is missing or ambiguous')
        if len(candidates)!=1:raise ValueError('Socket owner is missing or ambiguous')
        # Every packet still revalidates process lifetime, executable image,
        # UID and cgroup. Sharing a batch never shares an allow decision.
        return identity(candidates.pop())


def resolve(flow, connections=None):
    import psutil
    owners=connections if isinstance(connections,SocketOwners) else SocketOwners(
        connections if connections is not None else psutil.net_connections(kind='inet'))
    return owners.resolve(flow)


def nft_script(enabled, present=False):
    text=f'delete table inet {TABLE}\n' if present else ''
    if not enabled:return text
    return text+f'''table inet {TABLE} {{
 comment "{OWNER}"
 chain output {{ type filter hook output priority -110; policy accept;
  oifname "lo" accept
  ct direction reply accept
  ct state established,related accept
  meta mark {WG_MARK} accept
  udp sport 68 udp dport 67 accept
  udp sport 546 udp dport 547 accept
  # DNS is not an application permission: Satsuma's NAT redirect (priority dstnat,
  # after this chain) forces every query through the dnsmasq filter anyway.
  # Queuing it here held the readiness probe and every unapproved resolver
  # call until timeout (field log 2026-11-04, queue 201).
  meta l4proto {{ tcp, udp }} th dport 53 accept
  meta l4proto ipv6-icmp icmpv6 type {{ nd-router-solicit, nd-neighbor-solicit, nd-neighbor-advert }} accept
  meta l4proto {{ tcp, udp }} queue num {QUEUE}
  counter drop
 }}
}}
'''


def apply(enabled, runner=subprocess.run):
    args={'capture_output':True,'text':True,'timeout':15}
    result=runner(['/usr/sbin/nft','-j','list','tables'],**args)
    if result.returncode:raise RuntimeError('Cannot inspect application firewall')
    present=any(x.get('table',{}).get('name')==TABLE and x['table'].get('family')=='inet'
                for x in json.loads(result.stdout).get('nftables',[]))
    if present:
        check=runner(['/usr/sbin/nft','-j','list','table','inet',TABLE],**args)
        if check.returncode or not any(x.get('table',{}).get('comment')==OWNER for x in json.loads(check.stdout).get('nftables',[])):
            raise RuntimeError('App Control table ownership mismatch')
    script=nft_script(enabled,present)
    if not script:return
    for options in (['--check','-f','-'],['-f','-']):
        result=runner(['/usr/sbin/nft',*options],input=script,**args)
        if result.returncode:raise RuntimeError('App Control firewall transaction failed: '+result.stderr[:500])
    result=runner(['/usr/sbin/nft','-j','list','tables'],**args)
    actual=any(x.get('table',{}).get('name')==TABLE and x['table'].get('family')=='inet'
               for x in json.loads(result.stdout).get('nftables',[])) if result.returncode==0 else None
    if actual!=enabled:raise RuntimeError('App Control firewall readback failed')


class Decisions:
    def __init__(self,clock=time.monotonic):
        self.clock=clock;self.pending={};self.once={};self.rules={};self.application_rules={};self.enabled=False
        self.metrics={'socket_scans':0,'batches':0,'attribution_seconds':0,'packet_errors':{}}
        self.last_publish=0;self.counts={'allowed':0,'denied':0,'unattributed':0}

    def reload(self):
        data=policy()
        groups=data.get('application_rules',{})
        if data['rules']!=self.rules or groups!=self.application_rules:self.once.clear()
        self.rules=data['rules'];self.application_rules=groups
        return data['enabled'] and not self.handed_off()

    def handed_off(self):
        """True while OpenSnitch is the per-program firewall (checked every 5 s)."""
        now=time.monotonic()
        if now-getattr(self,'_handoff_checked',-10)>=5:
            from .opensnitch import running
            self._handoff_checked=now;self.handoff=running()
        return bool(getattr(self,'handoff',False))

    def decide(self,app,flow):
        now=self.clock();self.once={k:v for k,v in self.once.items() if v['expires']>now}
        key=app['key'];action=self.rules.get(key,'ask')
        group_action=self.application_rules.get(app.get('application_key'),'ask')
        flow_key=json.dumps([key,app['pid'],app['created_at'],list(flow)],separators=(',',':'))
        grant=self.once.get(flow_key)
        if action=='deny' or group_action=='deny' or grant and grant['action']=='deny':return False
        if action=='allow' or group_action=='allow' or grant and grant['action']=='allow':return True
        if trusted_dependency(app):return True
        request=hashlib.sha256(flow_key.encode()).hexdigest()
        if len(self.pending)<256 or request in self.pending:
            self.pending[request]={'id':request,'application':app,'flow':list(flow),'flow_key':flow_key,
                                   'expires':now+120,'destination':flow[4]+':'+str(flow[5])}
        return False

    def answer(self,request,action,duration):
        import psutil
        if action not in ('allow','deny','ask') or duration not in ('once','always','application'):
            raise ValueError('Invalid application decision')
        item=self.pending.get(request)
        if not item or item['expires']<self.clock():raise ValueError('Request expired; retry the connection')
        # The request refers to a specific process lifetime and executable.
        candidates=[item]
        if duration=='application':
            expected=item['application'].get('application_key')
            candidates.extend(v for v in self.pending.values() if v is not item
                and expected and v['application'].get('application_key')==expected
                and v['expires']>self.clock())
        live=None
        for candidate in candidates:
            try:current=identity(candidate['application']['pid'])
            except (OSError,ValueError,psutil.Error):continue
            # A short-lived browser child may exit before approval. Only an
            # independently verified live instance of the SAME application can
            # represent an explicitly application-scoped decision.
            if current==candidate['application']:
                live=current;break
        if live is None:raise ValueError('Request process changed')
        if duration in ('always','application'):
            data=policy()
            collection='application_rules' if duration=='application' else 'rules'
            if duration in ('application','always') and live.get('python_entry') and live['python_entry'].get('status')!='verified':
                raise ValueError('Unverified Python entry cannot receive a persistent application grant')
            grant_key=live['application_key'] if duration=='application' else live['key']
            data.setdefault(collection,{})[grant_key]=action
            RootDataStore('app-control/policy.json').replace(data)
            self.rules=data['rules'];self.application_rules=data.get('application_rules',{});self.once.clear()
            # All already covered child/flow prompts disappear after an
            # explicit persistent decision, not only the selected row.
            field='application_key' if duration=='application' else 'key'
            self.pending={k:v for k,v in self.pending.items() if v['application'].get(field)!=grant_key}
        else:
            self.once[item['flow_key']]={'action':action,'expires':self.clock()+300}
        self.pending.pop(request,None)

    def publish(self):
        now=self.clock();self.pending={k:v for k,v in self.pending.items() if v['expires']>now
            and self.rules.get(v['application']['key'],'ask')=='ask'
            and self.application_rules.get(v['application'].get('application_key'),'ask')=='ask'}
        grouped={}
        for item in self.pending.values():
            app=item['application'];key=app.get('application_key') or app['key']
            if key not in grouped:
                grouped[key]={k:v for k,v in item.items() if k!='flow_key'}
                grouped[key]['connection_count']=0
            grouped[key]['connection_count']+=1
        RootDataStore('app-control/status.json').replace({'status':'ACTIVE' if self.enabled else 'HANDED_TO_OPENSNITCH' if getattr(self,'handoff',False) else 'DISABLED',
            'handed_to':'opensnitch' if getattr(self,'handoff',False) else None,
            'updated_at':time.time(),'enabled':self.enabled,'queue':QUEUE,'counts':self.counts,
            'metrics':self.metrics,
            'pending':list(grouped.values()),
            'scope':'host outbound TCP/UDP; executable+UID; ambiguous owners denied'})


def status():
    data=read_record('status.json',{'status':'NOT_RUNNING'})
    if data.get('status') in ('ACTIVE','DISABLED','HANDED_TO_OPENSNITCH') and not 0<=time.time()-data.get('updated_at',0)<=10:
        data={**data,'status':'STALE'}
    current=policy()
    data['rules']=current['rules']
    data['application_rules']=current.get('application_rules',{})
    data['last_command']=read_record('command-result.json',{})
    return data


def control(action,params=None):
    """Called only by the authenticated, peer-bound operator channel."""
    params=params or {}
    if action=='status':return status()
    # The daemon consumes bounded durable commands. Operator never changes network rules.
    if action not in ('enable','disable','decision','rule'):raise ValueError('Unsupported App Control action')
    if action=='decision' and (params.get('decision') not in ('allow','deny','ask') or params.get('duration') not in ('once','always','application')):
        raise ValueError('Invalid decision')
    if action=='rule':
        if params.get('scope','session') not in ('session','application'):raise ValueError('Invalid rule scope')
        key=params.get('key','')
        if len(key)!=64 or any(c not in '0123456789abcdef' for c in key) or params.get('decision') not in ('allow','deny','ask'):
            raise ValueError('Invalid rule')
    import uuid
    command={'id':uuid.uuid4().hex,'action':action,'params':params,'created_at':time.time()}
    from .protected_storage import open_directory
    import fcntl
    directory=open_directory(ROOT)
    fd=None
    try:
        fd=os.open('.command.lock',os.O_CREAT|os.O_RDWR|os.O_NOFOLLOW,0o600,dir_fd=directory)
        import stat
        info=os.fstat(fd)
        if not stat.S_ISREG(info.st_mode) or info.st_uid!=0 or info.st_nlink!=1 or info.st_mode&0o077:
            raise PermissionError('Unsafe command lock')
        fcntl.flock(fd,fcntl.LOCK_EX)
        previous=read_record('command.json',{})
        completed=read_record('command-result.json',{})
        if (previous.get('id') and previous.get('id')!=completed.get('id')
            and 0<=time.time()-previous.get('created_at',0)<120):
            raise RuntimeError('An App Control command is still pending')
        RootDataStore('app-control/command.json').replace(command)
    finally:
        if fd is not None:os.close(fd)
        os.close(directory)
    return {'status':'REQUESTED','command_id':command['id']}


def notify_ready():
    address=os.environ.get('NOTIFY_SOCKET')
    if not address:return
    if address.startswith('@'):address='\0'+address[1:]
    with socket.socket(socket.AF_UNIX,socket.SOCK_DGRAM) as client:
        client.connect(address);client.sendall(b'READY=1\nSTATUS=App Control queue and policy verified')


def run():
    from .nfqueue import Queue
    from .self_guard import verify
    verify()
    engine=Decisions();last_command=read_record('command-result.json',{}).get('id');last_check=0
    def scan():
        import psutil
        started=time.monotonic()
        try:
            result=SocketOwners(psutil.net_connections(kind='inet'))
            engine.metrics.pop('attribution_error',None)
            return result
        except Exception as exc:
            engine.metrics['attribution_error']=str(exc)[:200]
            raise
        finally:
            engine.metrics['socket_scans']+=1
            engine.metrics['attribution_seconds']+=time.monotonic()-started
    attribution=Attribution(scan)
    def prepare():
        engine.metrics['batches']+=1
        try:attribution.begin()
        except Exception:attribution.owners=None
    def finish():
        attribution.end()
    def packet(raw):
        phase='parse'
        try:
            if attribution.owners is None:raise ValueError('Socket snapshot unavailable')
            flow=parse_packet(raw);phase='attribution'
            app=attribution.resolve(flow);phase='decision'
            allowed=engine.decide(app,flow)
        except Exception:
            errors=engine.metrics['packet_errors'];errors[phase]=errors.get(phase,0)+1
            engine.counts['unattributed']+=1;allowed=False
        engine.counts['allowed' if allowed else 'denied']+=1
        return allowed
    # Bind before installing any queue rule. No bypass on crash; bounded restart by systemd.
    with Queue(QUEUE,packet,prepare=prepare,finish=finish) as queue:
        while True:
            if time.monotonic()-last_check>=1:
                enabled=engine.reload()
                command=read_record('command.json',{})
                if command.get('id')!=last_command and command.get('id'):
                    last_command=command['id']
                    outcome={'id':last_command,'updated_at':time.time()}
                    try:
                        if not 0<=time.time()-command.get('created_at',0)<120:raise ValueError('Expired command')
                        action=command['action'];params=command.get('params',{})
                        if action in ('enable','disable'):
                            if action=='enable':verify()
                            data=policy();data['enabled']=action=='enable'
                            if data['enabled']!=engine.enabled:apply(data['enabled'])
                            RootDataStore('app-control/policy.json').replace(data);enabled=data['enabled'];engine.enabled=enabled
                        elif action=='decision':engine.answer(params.get('request_id'),params.get('decision'),params.get('duration'))
                        elif action=='rule':
                            data=policy();collection='application_rules' if params.get('scope')=='application' else 'rules'
                            data[collection][params['key']]=params['decision']
                            RootDataStore('app-control/policy.json').replace(data)
                            engine.rules=data['rules'];engine.application_rules=data['application_rules'];engine.once.clear()
                        else:raise ValueError('Unknown command')
                        outcome['status']='APPLIED'
                    except Exception as exc:outcome.update(status='FAILED',error=str(exc)[:500])
                    RootDataStore('app-control/command-result.json').replace(outcome)
                # On daemon restart, reconcile even if the initial desired state is disabled.
                if enabled!=engine.enabled or last_check==0:apply(enabled);engine.enabled=enabled
                engine.metrics['queue']=queue.metrics()
                engine.publish()
                if last_check==0:notify_ready()
                last_check=time.monotonic()
            queue.poll(.2)


def main():
    try:run()
    except Exception as exc:
        RootDataStore('app-control/status.json').replace({'status':'FAILED','updated_at':time.time(),'error':str(exc)[:1000]})
        raise


if __name__=='__main__':main()

