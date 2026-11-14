"""Passive VPN/proxy indicators and explicit, revalidated disconnect requests."""
import hashlib
import json
import os
from pathlib import Path
import re
import subprocess
import time

VPN={'openvpn','openconnect','wireguard-go','tailscaled','zerotier-one'}
PROXY={'squid','tinyproxy','privoxy','tor','ss-local','sslocal','xray','sing-box','clash','mihomo'}


def identifier(item):
    return hashlib.sha256(json.dumps(item,sort_keys=True).encode()).hexdigest()


def detect(runner=subprocess.run, processes=None, environ=None):
    import psutil
    items=[];errors=[]
    try:
        result=runner(['/usr/sbin/ip','-j','-d','link','show'],capture_output=True,text=True,timeout=5)
        if result.returncode or len(result.stdout)>1024*1024:raise RuntimeError('Interface inventory unavailable')
        for row in json.loads(result.stdout):
            kind=row.get('linkinfo',{}).get('info_kind')
            if kind in ('tun','wireguard','xfrm'):
                item={'kind':'tunnel_interface','name':row.get('ifname',''),'type':kind,
                      'active':'UP' in row.get('flags',[]),'blockable':False}
                items.append({**item,'id':identifier(item)})
    except (OSError,ValueError,RuntimeError,subprocess.TimeoutExpired) as exc:errors.append(str(exc)[:200])
    try:
        result=runner(['/usr/bin/nmcli','-t','--escape','no','-f','UUID,TYPE,NAME','connection','show','--active'],
                      capture_output=True,text=True,timeout=5)
        if result.returncode:raise RuntimeError('NetworkManager inventory unavailable')
        for line in result.stdout.splitlines():
            fields=line.split(':',2)
            if len(fields)<2:continue
            uuid,kind=fields[:2]
            if kind in ('vpn','wireguard','tun') and re.fullmatch(r'[0-9a-fA-F-]{36}',uuid):
                item={'kind':'managed_vpn','name':fields[2] if len(fields)>2 else uuid,
                      'uuid':uuid,'type':kind,'active':True,'blockable':True}
                items.append({**item,'id':identifier(item)})
    except (OSError,RuntimeError,subprocess.TimeoutExpired) as exc:errors.append(str(exc)[:200])
    try:
        for process in (psutil.process_iter(['pid','exe','create_time']) if processes is None else processes):
            try:
                info=process.info;exe=info.get('exe') or '';name=Path(exe).name
                if name not in VPN|PROXY:continue
                item={'kind':'vpn_process' if name in VPN else 'proxy_process','name':name,
                      'pid':info['pid'],'created_at':info['create_time'],'executable':exe,'blockable':True}
                items.append({**item,'id':identifier(item)})
            except (psutil.Error,OSError):continue
    except (psutil.Error,OSError) as exc:errors.append(str(exc)[:200])
    # Record variable names only. URLs may contain proxy passwords.
    environment=os.environ if environ is None else environ
    present=sorted(k for k in ('HTTP_PROXY','HTTPS_PROXY','ALL_PROXY','http_proxy','https_proxy','all_proxy')
                   if environment.get(k))
    if present:
        item={'kind':'proxy_environment','name':', '.join(present),'blockable':False}
        items.append({**item,'id':identifier(item)})
    return {'updated_at':time.time(),'status':'PARTIAL' if errors else 'OBSERVED','items':items[:1024],
            'errors':errors,'scope':'Local tunnel interfaces, NetworkManager VPNs, known processes and collector proxy variable names; encrypted/remote proxies may be missed.',
            'automatic_blocking':False}


def disconnect(target, confirmed, runner=subprocess.run, detector=detect):
    if confirmed is not True:raise ValueError('VPN/proxy bağlantısını kesmek için açık onay gerekli')
    current=detector(runner=runner)
    item=next((i for i in current['items'] if i['id']==target),None)
    if not item or not item.get('blockable'):raise ValueError('Hedef değişti veya güvenli kapatma desteklenmiyor; yeniden listeleyin')
    if item['kind']=='managed_vpn':
        result=runner(['/usr/bin/nmcli','connection','down','uuid',item['uuid']],
                      capture_output=True,text=True,timeout=15)
        if result.returncode:raise RuntimeError('VPN bağlantısı kapatılamadı')
        after=detector(runner=runner)
        if any(i['id']==target for i in after['items']):raise RuntimeError('VPN bağlantısı hâlâ etkin')
        return {'ok':True,'status':'DISCONNECTED','target':target,'persistent_block':False}
    import psutil
    proc=psutil.Process(item['pid'])
    if proc.create_time()!=item['created_at'] or proc.exe()!=item['executable']:
        raise ValueError('Süreç kimliği değişti; yeniden listeleyin')
    proc.terminate()
    return {'ok':True,'status':'STOP_REQUESTED','target':target,'persistent_block':False,
            'notice':'Yalnız seçilen süreç için kapatma istendi; otomatik yeniden başlatma önlenmez.'}


class WorkerVpnProxy:
    name='vpn_proxy'
    def __init__(self,store,config=None):self.store=store;self.next_check=0
    def tick(self,pipeline=None):
        if time.monotonic()<self.next_check:return {'ok':True,'status':'WAITING'}
        self.next_check=time.monotonic()+30
        result=detect();previous=self.store.get('vpn_proxy',{}) or {}
        self.store.set('vpn_proxy',result)
        self.store.set('worker.vpn_proxy.health',{'updated_at':time.time(),
            'status':'DEGRADED' if result['errors'] else 'RUNNING'})
        before={i['id'] for i in previous.get('items',[])}
        for item in result['items']:
            if item['id'] not in before:
                self.store.add('findings',{'source':'vpn_proxy','rule_id':'SATSUMA-VPN-PROXY-001',
                    'timestamp':time.time(),'severity':'info','classification':'indicator',
                    'title':'VPN/proxy göstergesi gözlendi: '+item['name'],
                    'details':item,'interpretation':'Saldırı kanıtı değildir; bağlantı kesme kullanıcı onayı gerektirir.'})
        return {'ok':not result['errors'],'count':len(result['items'])}
