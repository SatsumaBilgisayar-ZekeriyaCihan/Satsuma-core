"""Read-only interface/gateway observations; no TOFU trust, pinning or lockdown.

Every two seconds the routes and the gateway's hardware address are
compared with the modem the user approved. A change is recorded as a
finding whose severity says what it most likely means: the same gateway
address answering from another MAC is the classic sign of ARP spoofing
(critical); a different or additional gateway is high; a routing change
alone is a warning. An approved route whose MAC is not visible at the moment
is its own warning (GATEWAY_MAC_UNOBSERVED), not a gateway change. Nothing is
blocked automatically.

Salt okunur arayüz/ağ geçidi gözlemleri; ilk görüşte güven, sabitleme ya da
kilitleme yok.

Rotalar ve ağ geçidinin donanım adresi iki saniyede bir kullanıcının
onayladığı modemle karşılaştırılır. Değişiklik, büyük olasılıkla ne
anlama geldiğini söyleyen bir önem derecesiyle bulgu olarak kaydedilir:
aynı ağ geçidi adresinin başka bir MAC'ten yanıt vermesi ARP sahteciliğinin
klasik işaretidir (kritik); farklı ya da ek bir ağ geçidi yüksek; yalnızca
rota değişikliği uyarıdır. Onaylı rota duruyor ama MAC'i o an görünmüyorsa
bu ağ geçidi değişikliği değil, ayrı bir uyarıdır (GATEWAY_MAC_UNOBSERVED).
Hiçbir şey otomatik engellenmez.
"""
import argparse
import fcntl
import os
import stat
import hashlib
import hmac
import ipaddress
import json
import re
import signal
import socket
import subprocess
import time
import tempfile
from pathlib import Path
from .protected_storage import RootDataStore
from .package_trust import secure_read

POLICY=Path('/var/lib/satsuma-core/network-identity/policy.json')
TABLE='satsuma_identity'
OWNER='Satsuma interface identity guard'
MAC=re.compile(r'(?:[0-9a-f]{2}:){5}[0-9a-f]{2}')

def command(args):
    with tempfile.TemporaryFile() as out,tempfile.TemporaryFile() as err:
        result=subprocess.run(args,stdout=out,stderr=err,timeout=10)
        out.seek(0);err.seek(0);raw=out.read(1048577);error=err.read(65537)
        if len(raw)>1048576 or len(error)>65536:raise RuntimeError('Network inventory exceeds capacity')
        if result.returncode:raise RuntimeError('Network inventory command failed: '+error.decode(errors='replace')[:250])
        return raw.decode()


def ip(*args):
    values=tuple(args)
    allowed=values in (('link','show'),('address','show','dev','lo'),
        ('-4','route','show','default'),('-6','route','show','default'),
        ('-4','route','show','table','all'),('-6','route','show','table','all'),
        ('-4','rule','show'),('-6','rule','show'))
    if len(values)==6 and values[:3]==('neigh','show','to') and values[4]=='dev':
        ipaddress.ip_address(values[3])
        allowed=bool(re.fullmatch(r'[A-Za-z0-9_.:-]{1,64}',values[5]))
    if not allowed:raise PermissionError('Only explicitly allowed read-only iproute inventory commands may run')
    return json.loads(command(['/usr/sbin/ip','-j',*values]))


def check_loopback(links,addresses):
    lo=next((x for x in links if x.get('ifname')=='lo'),None)
    if not lo or lo.get('link_type')!='loopback' or not {'UP','LOOPBACK'}<=set(lo.get('flags',[])):
        raise RuntimeError('lo is missing, down, or not a loopback interface')
    values=[x for row in addresses for x in row.get('addr_info',[]) if x.get('family') in ('inet','inet6')]
    if not values or any(not ipaddress.ip_address(x['local']).is_loopback for x in values):
        raise RuntimeError('lo carries a non-loopback address or no loopback address')
    return {'status':'checked','ifindex':lo.get('ifindex'),'addresses':[x['local'] for x in values]}

def observe():
    links=ip('link','show')
    loopback=check_loopback(links,ip('address','show','dev','lo'))
    routes=ip('-4','route','show','default')+ip('-6','route','show','default')
    gateways=[]
    for route in routes:
        if not route.get('gateway') or not route.get('dev'): continue
        dev=route['dev']; gateway=str(ipaddress.ip_address(route['gateway']))
        link=next((x for x in links if x.get('ifname')==dev),None)
        if not link or link.get('link_type')!='ether':
            raise RuntimeError('Default route interface is not verified Ethernet: '+dev)
        mac=link.get('address','').lower()
        if not MAC.fullmatch(mac) or int(mac.split(':')[0],16)&1:
            raise RuntimeError('Invalid Ethernet interface MAC: '+dev)
        neighbors=ip('neigh','show','to',gateway,'dev',dev)
        peer=next((x for x in neighbors if x.get('lladdr')),{})
        gateways.append({'interface':dev,'mac':mac,'gateway':gateway,
                         'gateway_mac':peer.get('lladdr','').lower(),
                         'neighbor_state':peer.get('state',[])})
    # Multipath duplicate entries must not silently create extra trusted gateways.
    unique={(x['interface'],x['gateway']):x for x in gateways}
    return {'loopback':loopback,'gateways':sorted(unique.values(),key=lambda x:(x['interface'],x['gateway']))}

def canonical(value):
    return json.dumps(value,sort_keys=True,separators=(',',':')).encode()

def load():
    from .modem_identity import load as approved
    return approved()


def save(observed):
    raise PermissionError('Automatic modem enrollment is disabled; explicit user selection required')

def differences(policy,observed):
    expected={(p['interface'],p['gateway']):p for p in policy['gateways']}
    actual={(p['interface'],p['gateway']):p for p in observed['gateways']}
    errors=[]
    if set(expected)!=set(actual): errors.append('Default route interfaces/gateways changed')
    for key in set(expected)&set(actual):
        for field in ('mac','gateway_mac'):
            if actual[key].get(field) and actual[key][field]!=expected[key][field]:
                errors.append(f'{key[0]} {field} changed: expected={expected[key][field]}, actual={actual[key][field]}')
    return errors

def pin_neighbors(policy):
    raise PermissionError('Automatic neighbor pinning is disabled; observations are not authenticated')


def restrict(enabled):
    if enabled:
        raise PermissionError('Network identity is read-only; automatic network lockdown is disabled')
    return {'status':'READ_ONLY_NO_NETWORK_MUTATION'}


def sync(relearn=False):
    from .protected_storage import open_directory, check
    directory=open_directory(POLICY.parent)
    try:
        fd=os.open('sync.lock',os.O_RDWR|os.O_CREAT|os.O_NOFOLLOW|os.O_NONBLOCK,0o600,dir_fd=directory)
        try:
            check(os.fstat(fd))
            fcntl.flock(fd,fcntl.LOCK_EX)
            return _sync(relearn)
        finally: os.close(fd)
    finally: os.close(directory)


def classify_change(result):
    """(kind, severity, title, advice) for a non-matching observation."""
    status=result.get('status')
    if status=='MODEM_APPROVAL_REQUIRED':
        return ('MODEM_APPROVAL_REQUIRED','warning','Modem henüz onaylanmadı; ağ geçidi değişiklikleri karşılaştırılamıyor',
                'Yönetim → Ağ koruması bölümünden kendi modeminizi seçip onaylayın.')
    reference=result.get('reference') or {}
    others=result.get('additional_gateway_candidates') or []
    same_address=[c for c in others if c.get('gateway')==reference.get('gateway')
                  and c.get('interface')==reference.get('interface') and c.get('gateway_mac')!=reference.get('gateway_mac')]
    if same_address:
        return ('GATEWAY_MAC_CHANGED','critical',
                'Modeminizin donanım adresi (MAC) değişti: '+str(reference.get('gateway_mac'))+' → '
                +', '.join(str(c.get('gateway_mac')) for c in same_address)+'. ARP sahteciliği (ortadaki adam) olabilir.',
                'Modeminizi değiştirmediyseniz ağ bağlantısını kesip modemin arkasındaki cihazları kontrol edin. '
                'Modemi siz değiştirdiyseniz yeni modemi Yönetim → Ağ koruması bölümünden onaylayın.')
    if others:
        return ('ADDITIONAL_GATEWAY','high','Onaylı modem dışında ağ geçidi görünüyor: '
                +', '.join(str(c.get('gateway'))+' ('+str(c.get('gateway_mac'))+')' for c in others),
                'Bu bağlantıyı tanımıyorsanız (ör. telefon paylaşımı, ikinci ağ kartı) kaynağını kontrol edin.')
    if result.get('reference_mac_unobserved'):
        return ('GATEWAY_MAC_UNOBSERVED','warning','Modemin donanım adresi (MAC) şu anda görünmüyor; değiştiğine dair kanıt yok',
                'Bağlantı koptuysa ya da modeme bir süredir trafik gitmediyse beklenir. Sürüyorsa ağ bağlantısını kontrol edin.')
    if status=='MODEM_REFERENCE_CHANGED' and result.get('routing_snapshot_matches') is not False:
        return ('GATEWAY_CHANGED','high','Onaylı modem şu anda ağ geçidi olarak görünmüyor',
                'Başka bir ağa bağlandıysanız bu beklenir; bağlanmadıysanız modem bağlantısını kontrol edin.')
    if status=='MODEM_REFERENCE_CHANGED':
        return ('ROUTES_CHANGED','warning','Yönlendirme tablosu onay anındakinden farklı',
                'VPN ya da yeni bir bağlantı açtıysanız beklenir; Teknik ayrıntılardaki rota farkını inceleyin.')
    return (str(status),'warning','Ağ gözlemi değişti; otomatik sabitleme/izolasyon yapılmadı','Teknik ayrıntıları inceleyin.')


def _sync(relearn=False):
    from .store import Store
    store=Store()
    try:
        from . import modem_identity
        loopback=check_loopback(ip('link','show'),ip('address','show','dev','lo'))
        data=modem_identity.inventory()
        policy=modem_identity.load()
        enrolled=None
        if policy is None:
            # 2.2.10: one visible modem is enrolled automatically.
            enrolled=modem_identity.approve_automatic(data=data)
            if enrolled['status']=='AUTOMATICALLY_ENROLLED':policy=modem_identity.load()
        result={**modem_identity.compare(policy,data),'automatic_enrollment':enrolled,
                'loopback':loopback,'tables':data['tables'],
                'gateways':data['candidates'],'route_fingerprint':data['route_fingerprint'],'updated_at':time.time(),
                'initial_authenticity_verified':False,'legacy_pins_require_review':True}
        if relearn:
            result['message']='Automatic trust enrollment disabled; select and approve your modem in the admin panel'
        errors=[] if result['status']=='MATCHED_USER_APPROVAL' else [result['status']]
        previous=store.get('network_identity',{}) or {}
        if errors:
            kind,severity,title,advice=classify_change(result)
            result.update(change_kind=kind,change_severity=severity)
        store.set('network_identity',result)
        if errors and (previous.get('status'),previous.get('route_fingerprint'),previous.get('change_kind'))!=(result['status'],result['route_fingerprint'],kind):
            store.add('findings',{**result,'source':'network_identity','classification':'indicator',
                'severity':severity,'title':title,'advice':advice,'automatic_action':'none'})
        return result
    except Exception as exc:
        result={'status':'OBSERVATION_ERROR','error':str(exc)[:500],
                'updated_at':time.time(),'initial_authenticity_verified':False,
                'network_mutations_enabled':False,'external_traffic':'not_changed_by_identity_monitor'}
        store.set('network_identity',result)
        store.add('errors',{'component':'network_identity',**result})
        return result
    finally:store.close()


def main():
    parser=argparse.ArgumentParser()
    parser.add_argument('--watch',action='store_true')
    parser.add_argument('--learn',action='store_true',help='Replace observation reference only; never authenticate or pin it')
    args=parser.parse_args()
    if not args.watch:
        result=sync(relearn=args.learn); print(json.dumps(result,indent=2)); return 1 if result['status']=='OBSERVATION_ERROR' else 0
    running=True
    def stop(*_):
        nonlocal running
        running=False
    signal.signal(signal.SIGTERM,stop); signal.signal(signal.SIGINT,stop)
    while running:
        sync()
        for _ in range(10):
            if not running: break
            time.sleep(.2)
    return 0

if __name__=='__main__': raise SystemExit(main())
