"""List routing tables and require an explicit user-selected modem reference.

Read-only netlink inventory. Approval stores evidence; it never changes routes,
neighbors, DNS or nftables. HMAC authenticates the stored approval, not a router.
Every default route that is not offered as a modem carries its reason in
``rejected``, so an empty list is never silent. The gateway's MAC comes from
the neighbour table, or from /proc/net/arp when the table has no address. An
IPv6 inventory failure (IPv6 off) does not stop the IPv4 list. When the
approved modem's route is present but its MAC is in neither table, the
comparison says ``reference_mac_unobserved`` instead of implying another modem.

Yönlendirme tablolarını listeler ve kullanıcının açıkça seçtiği modemi
referans olarak saklar. Salt okunur; rota, komşu, DNS ya da nftables
değiştirmez. Modem olarak sunulmayan her varsayılan rota ``rejected`` içinde
sebebiyle gösterilir; boş liste hiçbir zaman sessiz kalmaz. Ağ geçidinin MAC
adresi komşu tablosundan, orada yoksa /proc/net/arp'tan okunur. IPv6
okumasının başarısız olması (IPv6 kapalı) IPv4 listesini durdurmaz. Onaylı
modemin rotası duruyor ama MAC'i iki tabloda da yoksa karşılaştırma başka bir
modem varmış gibi değil ``reference_mac_unobserved`` olarak sonuç verir.
"""
import hashlib
import hmac
import ipaddress
import json
import os
import stat
from pathlib import Path
import re
import time
from .package_trust import secure_read
from .protected_storage import RootDataStore

REFERENCE=Path('/var/lib/satsuma-core/network-identity/approved-modem.json')
# A reference comes from the user's choice or, when the machine sees exactly
# one modem, from automatic enrollment (user decision 2026-10-26).
SOURCES=('explicit_user_selection','automatic_single_candidate')
MAC=re.compile(r'(?:[0-9a-f]{2}:){5}[0-9a-f]{2}')
INTERFACE=re.compile(r'[A-Za-z0-9_.:-]{1,64}')


def encoded(value):return json.dumps(value,sort_keys=True,separators=(',',':')).encode()


def table_id(value):
    aliases={'local':'255','main':'254','default':'253'}
    value=aliases.get(str(value),str(value))
    if not re.fullmatch(r'[A-Za-z0-9_.-]{1,64}',value):raise ValueError('Invalid routing table')
    return value


def defined_tables():
    result={'253':'default','254':'main','255':'local'}
    paths=[Path('/usr/lib/iproute2/rt_tables'),Path('/etc/iproute2/rt_tables')]
    for directory in (Path('/usr/lib/iproute2/rt_tables.d'),Path('/etc/iproute2/rt_tables.d')):
        try:info=directory.lstat()
        except FileNotFoundError:continue
        if not stat.S_ISDIR(info.st_mode) or info.st_uid!=0 or info.st_mode & 0o022:
            raise PermissionError('Untrusted routing table catalog directory')
        files=list(directory.iterdir())
        if len(files)>64:raise RuntimeError('Routing table catalog exceeds capacity')
        paths.extend(path for path in files if path.suffix=='.conf')
    for path in paths:
        try:fd=os.open(path,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK)
        except FileNotFoundError:continue
        with os.fdopen(fd,'rb') as stream:
            info=os.fstat(stream.fileno())
            if not stat.S_ISREG(info.st_mode) or info.st_uid!=0 or info.st_mode & 0o022 or info.st_nlink!=1:
                raise PermissionError('Untrusted routing table catalog')
            raw=stream.read(65537)
        if len(raw)>65536:raise RuntimeError('Routing table catalog exceeds capacity')
        for line in raw.decode().splitlines():
            parts=line.split('#',1)[0].split()
            if len(parts)==2 and parts[0].isdigit() and 0<=int(parts[0])<=4294967295:
                result[table_id(parts[0])]=table_id(parts[1])
    return result


def arp_mac(gateway,interface,path='/proc/net/arp'):
    """Gateway MAC from the kernel ARP table, or None."""
    try:lines=Path(path).read_text().splitlines()[1:]
    except OSError:return None
    for line in lines:
        parts=line.split()
        if len(parts)>=6 and parts[0]==gateway and parts[5]==interface:
            mac=parts[3].lower()
            if MAC.fullmatch(mac) and mac!='00:00:00:00:00:00':return mac
    return None


def inventory(reader=None):
    if reader is None:
        from .network_identity import ip
        reader=ip
    links=reader('link','show')
    linkmap={x['ifname']:x for x in links if x.get('link_type')=='ether' and INTERFACE.fullmatch(x.get('ifname',''))}
    routes=[];rules=[]
    for family in ('-4','-6'):
        try:
            routes+=reader(family,'route','show','table','all')
            rules+=reader(family,'rule','show')
        except (RuntimeError,OSError,ValueError):
            if family=='-4':raise
    if len(routes)>4096 or len(rules)>1024:raise RuntimeError('Route inventory exceeds capacity')
    labels=defined_tables()
    tables=set(labels)
    for row in routes+rules:
        value=row.get('table',row.get('lookup'))
        if value is not None:tables.add(table_id(value))
    candidates={}
    def stable(value):
        if isinstance(value,dict):return {key:stable(item) for key,item in value.items() if key not in ('expires','cache','age','used','lastuse')}
        if isinstance(value,list):return [stable(item) for item in value]
        return value
    snapshot={'routes':sorted([stable(row) for row in routes],key=encoded),
              'rules':sorted([stable(row) for row in rules],key=encoded),'tables':sorted(tables)}
    fingerprint=hashlib.sha256(encoded(snapshot)).hexdigest()
    rejected=[];manual=[]
    def reject(route,reason):
        rejected.append({'dev':route.get('dev'),'gateway':route.get('gateway'),
                         'table':table_id(route.get('table','main')),'reason':reason})
    for route in routes:
        if route.get('dst') not in (None,'default','0.0.0.0/0','::/0'):continue
        if not route.get('gateway'):
            reject(route,'Bu varsayılan rotada ağ geçidi yok (VPN ya da noktadan noktaya bağlantı olabilir).');continue
        interface=route.get('dev','');link=linkmap.get(interface)
        if not link:
            reject(route,'Arayüz bir Ethernet/Wi-Fi kartı değil (VPN, tünel ya da sanal arayüz olabilir).');continue
        gateway=str(ipaddress.ip_address(route['gateway']));local_mac=link.get('address','').lower()
        if not MAC.fullmatch(local_mac):
            reject(route,'Arayüzün kendi MAC adresi okunamadı.');continue
        try:neighbors=reader('neigh','show','to',gateway,'dev',interface)
        except (RuntimeError,OSError,ValueError):neighbors=[]
        peer=next((n for n in neighbors if n.get('dst')==gateway and MAC.fullmatch(n.get('lladdr','').lower())),None)
        mac=peer['lladdr'].lower() if peer else arp_mac(gateway,interface)
        # A wired/wireless default route the user may complete with a typed MAC.
        manual.append({'table':table_id(route.get('table','main')),'interface':interface,
                       'interface_mac':local_mac,'gateway':gateway})
        if mac is None:
            reject(route,'Modemin MAC adresi komşu tablosunda ve ARP tablosunda yok; modeme hiç trafik gitmemiş olabilir.')
            rejected[-1].update(gateway=gateway,code='mac_unobserved');continue
        if int(mac.split(':')[0],16)&1 or int(local_mac.split(':')[0],16)&1:
            reject(route,'Modemin MAC adresi çok noktaya yayın adresi; gerçek bir cihaz adresi değil.');continue
        candidate={'table':table_id(route.get('table','main')),'interface':interface,
                   'interface_mac':local_mac,'gateway':gateway,'gateway_mac':mac}
        candidate['id']=hashlib.sha256(encoded(candidate)).hexdigest()
        candidates[candidate['id']]=candidate
    return {'route_fingerprint':fingerprint,'table_names':labels,'tables':sorted(tables),'routes':routes,'rules':rules,
            'candidates':list(candidates.values()),'rejected':rejected,'manual_routes':manual,'suggested_id':next(iter(candidates)) if len(candidates)==1 else None,
            'automatic_configuration':'CANDIDATE_LIST_ONLY','approval_required':True,
            'network_mutations_enabled':False,'observed_at':time.time()}


def load():
    if not REFERENCE.exists():return None
    from installer.integrity import read_key
    envelope=json.loads(secure_read(REFERENCE))
    policy=envelope['policy']
    expected=hmac.new(read_key(),encoded(policy),hashlib.sha256).hexdigest()
    if not hmac.compare_digest(envelope.get('hmac',''),expected):raise PermissionError('Modem approval authentication failed')
    if policy.get('schema')!=1:raise ValueError('Unsupported modem reference')
    if policy.get('approved') is False:return None
    if policy.get('source') not in SOURCES or policy.get('approved') is not True or not isinstance(policy.get('modem'),dict):
        raise ValueError('No explicit modem approval')
    return policy


def approve(candidate_id,uid,confirmed,provider=inventory,writer=None,expected_fingerprint=None):
    if confirmed is not True:raise PermissionError('Explicit modem confirmation required')
    data=provider()
    # The candidate id pins table, interface, gateway and both MAC addresses;
    # an unrelated route change since the preview no longer blocks approval.
    choices=[c for c in data['candidates'] if c['id']==candidate_id]
    if len(choices)!=1:raise ValueError('Selected modem changed or is no longer present; refresh the list')
    from installer.integrity import read_key
    policy={'schema':1,'approved':True,'source':'explicit_user_selection',
            'approval_uid':uid,'approved_at':time.time(),'modem':choices[0],
            'route_fingerprint':data['route_fingerprint'],
            'independent_device_authentication':False}
    envelope={'policy':policy,'hmac':hmac.new(read_key(),encoded(policy),hashlib.sha256).hexdigest()}
    (writer or RootDataStore('network-identity/approved-modem.json').replace)(envelope)
    return {'status':'USER_REFERENCE_SAVED','modem':policy['modem'],'network_mutations_enabled':False}


def approve_automatic(provider=inventory,writer=None,data=None):
    """Enroll the modem by itself when exactly one candidate is visible."""
    data=data if data is not None else provider()
    if len(data['candidates'])!=1:
        return {'status':'NOT_ENROLLED','candidate_count':len(data['candidates']),'reasons':not_found(data)}
    from installer.integrity import read_key
    policy={'schema':1,'approved':True,'source':'automatic_single_candidate',
            'approval_uid':None,'approved_at':time.time(),'modem':data['candidates'][0],
            'route_fingerprint':data['route_fingerprint'],
            'independent_device_authentication':False}
    envelope={'policy':policy,'hmac':hmac.new(read_key(),encoded(policy),hashlib.sha256).hexdigest()}
    (writer or RootDataStore('network-identity/approved-modem.json').replace)(envelope)
    return {'status':'AUTOMATICALLY_ENROLLED','modem':policy['modem'],'network_mutations_enabled':False}


def approve_manual(mac,uid,confirmed,provider=inventory,writer=None):
    """Save a reference from the user's typed modem MAC and the default route."""
    if confirmed is not True:raise PermissionError('Explicit modem confirmation required')
    mac=str(mac or '').strip().lower().replace('-',':')
    if not MAC.fullmatch(mac) or mac=='00:00:00:00:00:00' or int(mac.split(':')[0],16)&1:
        raise ValueError('Geçerli bir MAC adresi yazın (ör. a8:9a:93:12:34:56).')
    data=provider()
    routes={(r['table'],r['interface'],r['interface_mac'],r['gateway']):r for r in data.get('manual_routes',[])}
    if len(routes)!=1:
        raise ValueError('Modeme giden tek bir kablolu/kablosuz varsayılan rota bulunamadı; bulunan: '+str(len(routes)))
    candidate={**next(iter(routes.values())),'gateway_mac':mac}
    candidate['id']=hashlib.sha256(encoded({k:candidate[k] for k in ('table','interface','interface_mac','gateway','gateway_mac')})).hexdigest()
    from installer.integrity import read_key
    policy={'schema':1,'approved':True,'source':'explicit_user_selection',
            'approval_uid':uid,'approved_at':time.time(),'modem':candidate,
            'route_fingerprint':data['route_fingerprint'],'mac_typed_by_user':True,
            'independent_device_authentication':False}
    envelope={'policy':policy,'hmac':hmac.new(read_key(),encoded(policy),hashlib.sha256).hexdigest()}
    (writer or RootDataStore('network-identity/approved-modem.json').replace)(envelope)
    observed=[c['gateway_mac'] for c in data['candidates'] if c['gateway']==candidate['gateway']]
    return {'status':'USER_REFERENCE_SAVED','modem':candidate,'network_mutations_enabled':False,
            'observed_mac':observed[0] if observed else None,
            'matches_observed':bool(observed) and observed[0]==mac}


def compare(policy,data):
    if policy is None:return {'status':'MODEM_APPROVAL_REQUIRED','approved':False,'network_mutations_enabled':False}
    reference=policy['modem']
    matched=any(candidate==reference for candidate in data['candidates'])
    routes_match=policy.get('route_fingerprint')==data.get('route_fingerprint')
    selected_table=reference['table']
    additional=[candidate for candidate in data['candidates'] if candidate!=reference]
    # The approved route is still there but its MAC is not visible right now:
    # no observation, which is not evidence of a different modem.
    unobserved=not matched and any(r.get('code')=='mac_unobserved' and r.get('dev')==reference.get('interface')
                                   and r.get('gateway')==reference.get('gateway') for r in data.get('rejected',[]))
    # Multiple active gateway candidates cannot be reported globally healthy.
    return {'status':'MATCHED_USER_APPROVAL' if matched and routes_match and not additional else 'MODEM_REFERENCE_CHANGED',
            'approved':True,'selected_table':selected_table,'reference':reference,
            'additional_gateway_candidates':additional,'routing_snapshot_matches':routes_match,
            'reference_mac_unobserved':unobserved,'network_mutations_enabled':False,
            'independent_device_authentication':False}


def preview(provider=inventory):
    data=provider();candidate=data['candidates'][0] if len(data['candidates'])==1 else None
    return {'ready_for_automatic':candidate is not None,'candidate':candidate,
            'route_fingerprint':data['route_fingerprint'],'inventory':data,
            'confirmation_required':True,
            'summary':(['Bulunan modem adayı: '+candidate['gateway']+' · bağlantı: '+candidate['interface'],
                        'Cihazın donanım adresi: '+candidate['gateway_mac'],
                        'Bu cihaz tek modem referansınız olarak kaydedilecek.',
                        'Modem veya ağ yönlendirmesi değiştiğinde uyarı gösterilecek.',
                        'Mevcut internet, DNS ve ağ geçidi ayarlarınız bu adımda değiştirilmeyecek.']
                       if candidate else not_found(data))}


def not_found(data):
    """Why no single modem was offered, in plain Turkish."""
    if data['candidates']:
        return ['Birden fazla modem adayı var. Detaylı yapılandırmadan kendi modeminizi seçin.']
    reasons=[f"{r['dev']} · {r['gateway'] or 'ağ geçidi yok'}: {r['reason']}" for r in data.get('rejected',[])]
    if reasons:return ['Modem bulunamadı. Sebebi:']+reasons
    return ['Modem bulunamadı: bu bilgisayarda varsayılan rota yok (internet bağlantısı kurulmamış).']
