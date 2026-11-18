"""Ten-minute functional checks and bounded service-only repairs.

No downloads, firewall flush, integrity acceptance, unmasking or arbitrary shell.
The system resolver in /etc/resolv.conf is compared with the resolvers
Satsuma allows; a mismatch, which leaves applications unable to resolve
names (field log 2026-10-25), makes health DEGRADED and names both sides.

On dakikalık işlev denetimleri ve sınırlı, yalnızca servis onarımları.
İndirme, güvenlik duvarı temizleme, bütünlük kabulü, maskeyi kaldırma ya da
rastgele kabuk yoktur. /etc/resolv.conf'taki sistem çözücüsü Satsuma'nın izin
verdiği çözücülerle karşılaştırılır; uygulamaların ad çözememesine yol açan
bir uyumsuzluk (2026-10-25 saha kaydı) sağlık durumunu DEGRADED yapar ve iki
tarafı da adlandırır.
"""
import json
import os
from pathlib import Path
import subprocess
import tempfile
import time

def disabled_dns_check(policy):
    return {'ok':False, 'status':'DISABLED' if 'enabled' in policy else 'NOT_CONFIGURED',
            'configuration_valid':'enabled' in policy, 'protection_active':False,
            'error':'DNS filtresi kapalı; zararlı alan adı engellemesi etkin değil'}


ROOT=Path('/var/lib/satsuma-core/self-health')
# Plain names of the functional checks (panel and notices). İşlev kontrollerinin adları.
CHECK_LABELS={'services':'Servisler','services_after_repair':'Onarım sonrası servisler',
        'integrity':'Uygulama bütünlüğü','response_integrity':'Müdahale için bütünlük doğrulaması',
        'modem_reference':'Modem/ağ geçidi onayı',
        'worker_heartbeats':'Takım çalışma kayıtları','packet_drop':'Paket engelleme testi',
        'production_incoming_rules':'Gelen trafik kuralları','app_control':'Uygulama internet filtresi',
        'nfqueue_consumers':'Ağ kuyruğu servisleri','dns_filter':'DNS filtresi',
        'dns_policy':'DNS yapılandırması','dns_resolver_alignment':'Sistem DNS sunucusu','competing_ips':'Çakışan Suricata servisi','subnet_protection':'Alt ağ engelleyici','integrity_monitor':'Bütünlük izleyici','core_state':'Core durumuna erişim'}


def notice_text(result):
    """Explain the reported failure without promoting unknown evidence to healthy."""
    status=result.get('status','UNKNOWN')
    messages={
        'RUNNING':'Sağlık kontrol ediliyor… Servisler ve engelleme yeteneği sınanıyor.',
        'DEGRADED':'Sağlık kontrolü sorun buldu.',
        'FAILED':'Sağlık kontrolü tamamlanamadı; koruma doğrulanmadı.',
        'STALE':'Sağlık kontrolü güncel değil; koruma doğrulanmadı.',
        'UNAVAILABLE':'Sağlık kontrolü raporuna erişilemiyor.',
        'NOT_RUN':'İlk otomatik sağlık kontrolü bekleniyor.',
    }
    if status=='PASSED':return ''
    text=messages.get(status,'Sağlık durumu doğrulanamadı; Sistem Sağlığı bölümünü inceleyin.')
    if status not in ('DEGRADED','FAILED'):return text
    labels=CHECK_LABELS
    failures=[]
    checks=result.get('checks') or {}
    for name,check in checks.items():
        if not isinstance(check,dict) or check.get('ok') is not False:continue
        label=labels.get(name,name)
        if name.startswith('services'):
            states=check.get('states') or {}
            units=[unit for unit,item in states.items() if item.get('ActiveState')!='active']
            if units:label+=': '+', '.join(units[:5])
        failures.append(label)
    if failures:text+=' Başarısız kontroller: '+'; '.join(failures)+'.'
    else:text+=' Başarısız kontrol ayrıntısı raporda yok.'
    return text+' Ayrıntılar: Sistem Sağlığı.'
UNITS=('satsuma-core-gateway.service','satsuma-core-sentinel.service','satsuma-core.service','satsuma-teams.service','satsuma-reader.service',
       'satsuma-operator.service','satsuma-app-control.service','satsuma-network.service','satsuma-suricata-ips.service',
       'satsuma-suricata-otx-guard.service','satsuma-udev.service','satsuma-rescue.service','satsuma-core-dns.service','satsuma-dns-netns.service',
       'satsuma-core-subnet.service')


def subnet_check(policy,health,now=None):
    """The subnet blocker is network protection on its own; OTX is not needed for it.

    Field 2026-11-10: network protection looked tied to the OTX key while the
    subnet blocker was not checked at all. A blocker locked until boot
    integrity is verified, stopped, failing or silent is a failed check.
    Alt ağ engelleyici tek başına ağ korumasıdır; OTX gerekmez. Açılış
    bütünlüğü doğrulanana kadar kilitli, durmuş, hata veren ya da sessiz
    engelleyici başarısız kontroldür.
    """
    now=time.time() if now is None else now
    policy=policy if isinstance(policy,dict) else {}
    health=health if isinstance(health,dict) else {}
    if policy and policy.get('enabled') is False:
        return {'ok':False,'status':'DISABLED','message':'Alt ağ engelleyici panelden kapatılmış'}
    status=health.get('status');stamp=health.get('updated_at')
    fresh=isinstance(stamp,(int,float)) and 0<=now-stamp<120
    if not fresh:
        return {'ok':False,'status':'NO_RECENT_RESULT','message':'Alt ağ engelleyiciden son iki dakikada sonuç gelmedi'}
    if status=='boot_integrity_locked':
        return {'ok':False,'status':'LOCKED','message':'Alt ağ engelleyici açılış bütünlüğü doğrulanana kadar kilitli; engelleme yapmıyor'}
    if status!='running':
        return {'ok':False,'status':str(status or 'UNKNOWN').upper(),'message':str(health.get('error') or 'Alt ağ engelleyici engel yazamadı')[:250]}
    return {'ok':True,'status':'ACTIVE','threshold':health.get('threshold'),'message':'Aynı /24 içinde eşik sayısı kadar farklı IP engelleniyor'}


def resolv_conf_nameservers(text):
    import ipaddress
    found=[]
    for line in text.splitlines():
        words=line.split('#',1)[0].split()
        if len(words)>=2 and words[0]=='nameserver':
            try:found.append(str(ipaddress.ip_address(words[1].split('%',1)[0])))
            except ValueError:continue
    return found


def dns_resolver_alignment(dns_policy,expected,resolv_text):
    """Every system nameserver must be one Satsuma lets DNS reach."""
    import ipaddress
    allowed=set(expected or [])
    if dns_policy.get('upstream'):
        from .dnsmasq_control import upstream_servers
        try:allowed.update(upstream_servers(dns_policy['upstream']))
        except ValueError:allowed.add(str(dns_policy['upstream']))
    system=resolv_conf_nameservers(resolv_text)
    if not system:
        return {'ok':False,'state':'NO_SYSTEM_RESOLVER','system_resolvers':[],'satsuma_resolvers':sorted(allowed)}
    if not allowed:
        return {'ok':True,'state':'SATSUMA_DNS_NOT_CONFIGURED','system_resolvers':system,'satsuma_resolvers':[]}
    stray=[ip for ip in system if ip not in allowed and not ipaddress.ip_address(ip).is_loopback]
    return {'ok':not stray,'state':'MISMATCH' if stray else 'ALIGNED','system_resolvers':system,
            'satsuma_resolvers':sorted(allowed),'not_allowed':stray}


def competing_ips(state):
    """The distribution's suricata.service fights Satsuma's IPS for queue 100.

    Field log 2026-10-25: an enabled, hand-edited suricata.service with
    -q 100 and Satsuma's Conflicts= stopped each other every few seconds.
    Reported only; disabling it is the operator's decision.

    Dağıtımın suricata.service'i kuyruk 100 için Satsuma IPS'iyle çakışır.
    Yalnızca bildirilir; kapatmak yöneticinin kararıdır.
    """
    if state.get('LoadState')!='loaded':
        return {'ok':True,'state':'NOT_INSTALLED'}
    active=state.get('ActiveState') in ('active','activating','reloading')
    enabled=state.get('UnitFileState') in ('enabled','enabled-runtime','static','alias','linked','linked-runtime')
    if not (active or enabled):
        return {'ok':True,'state':'DISABLED'}
    return {'ok':False,'state':'ACTIVE' if active else 'ENABLED','unit':'suricata.service',
            'error':'İkinci bir Suricata servisi (suricata.service) '+('çalışıyor' if active else 'açılışta başlayacak')
                    +'; Satsuma IPS ile kuyruk 100 için çakışır ve ikisi birbirini durdurur. '
                    +'Kapatmak için: sudo systemctl disable --now suricata.service'}


def repair_allowed(unit,state,history,now):
    return unit in UNITS and state in ('failed','inactive','unhealthy') and len([t for t in history.get(unit,[]) if 0<=now-t<1800])<3


def command(argv,timeout=8):
    with tempfile.TemporaryFile() as out,tempfile.TemporaryFile() as err:
        result=subprocess.run(argv,stdout=out,stderr=err,timeout=timeout)
        out.seek(0);err.seek(0);stdout=out.read(1048577);stderr=err.read(65537)
        if len(stdout)>1048576 or len(stderr)>65536:raise RuntimeError('Health command exceeds capacity')
        if result.returncode:raise RuntimeError(argv[0]+': '+stderr.decode(errors='replace')[-2000:])
        return stdout.decode(errors='replace')


def read_report(path=ROOT/'status.json'):
    import stat
    try:
        fd=os.open(path,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK)
        with os.fdopen(fd,'rb') as stream:
            info=os.fstat(stream.fileno())
            if not stat.S_ISREG(info.st_mode) or info.st_uid not in (0,os.geteuid()) or info.st_mode & 0o022:raise PermissionError('Untrusted health report')
            raw=stream.read(262145)
        if len(raw)>262144:raise ValueError('Health report exceeds capacity')
        result=json.loads(raw)
        if not 0<=time.time()-result.get('updated_at',0)<=900:result={**result,'status':'STALE'}
        return result
    except FileNotFoundError:return {'status':'NOT_RUN'}
    except Exception as exc:return {'status':'UNAVAILABLE','error':str(exc)[:200]}


def report(record):
    from .protected_storage import RootDataStore
    RootDataStore('self-health/status.json').replace(record)


def inspect_units():
    states={}
    for unit in UNITS:
        text=command(['/usr/bin/systemctl','show',unit,'--property=LoadState,ActiveState,UnitFileState'])
        states[unit]=dict(line.split('=',1) for line in text.splitlines() if '=' in line)
    return states


def run():
    from .protected_storage import RootDataStore
    previous=read_report();history=previous.get('repair_history',{})
    started=time.time();checks={};repairs=[]
    base={'status':'RUNNING','message':'Sağlık kontrol ediliyor','started_at':started,'updated_at':started,'repair_history':history}
    report(base)
    try:
        states=inspect_units()
        # DNS is intentionally inactive until the operator has configured a resolver.
        from .store import Store
        dns_policy={}
        try:
            dns_store=Store()
            try:dns_policy=dns_store.get('dns_policy',{}) or {}
            finally:dns_store.close()
        except Exception as exc:
            checks['dns_policy']={'ok':False,'error':str(exc)[:250]}
        if not dns_policy.get('enabled'):
            states.pop('satsuma-core-dns.service',None);states.pop('satsuma-dns-netns.service',None)
        try:
            from .config import load
            expected=load().get('expected_dns_servers',[])
        except Exception:
            expected=[]
        try:resolv_text=Path('/etc/resolv.conf').read_text()
        except OSError:resolv_text=''
        checks['dns_resolver_alignment']=dns_resolver_alignment(dns_policy,expected,resolv_text)
        checks['services']={'ok':all(item.get('ActiveState')=='active' for item in states.values()),'states':states}
        try:
            text=command(['/usr/bin/systemctl','show','suricata.service','--property=LoadState,ActiveState,UnitFileState'])
            checks['competing_ips']=competing_ips(dict(line.split('=',1) for line in text.splitlines() if '=' in line))
        except Exception as exc:checks['competing_ips']={'ok':False,'error':str(exc)[:250]}
        # Confirm current signed application state without replacing its baseline.
        from .self_guard import verify
        try:verify();checks['integrity']={'ok':True}
        except Exception as exc:checks['integrity']={'ok':False,'error':str(exc)[:250]}
        from .store import Store
        try:
            store=Store()
            try:
                runtime=store.get('integrity_runtime',{}) or {}
                checks['response_integrity']={'ok':runtime.get('status')=='HEALTHY' and 0<=time.time()-runtime.get('checked_at',0)<600,'state':runtime.get('status','UNKNOWN')}
                checks['subnet_protection']=subnet_check(store.get('subnet_protection_policy',None),store.get('subnet_health',{}))
                modem=store.get('network_identity',{}) or {}
                checks['modem_reference']={'ok':modem.get('status')=='MATCHED_USER_APPROVAL' and 0<=time.time()-modem.get('updated_at',0)<30,'state':modem.get('status','MODEM_APPROVAL_REQUIRED')}
                rows=store.db.execute("SELECT key,body FROM state WHERE key LIKE 'team.%.health'").fetchall()
                workers={key:json.loads(body) for key,body in rows}
                missing=['team.'+name+'.health' for name in ('network_team','host_team','file_team','identity_team') if 'team.'+name+'.health' not in workers]
                failed={key:item for key,item in workers.items() if not 0<=time.time()-item.get('updated_at',0)<180 or item.get('status')!='RUNNING'}
                checks['worker_heartbeats']={'ok':not missing and not failed,'count':len(workers),'missing':missing,'failed':failed}
            finally:store.close()
        except Exception as exc:checks['core_state']={'ok':False,'error':str(exc)[:250]}
        # Independent kernel probe: namespace failure is a failed check, never a pass/skip.
        try:
            original_netns=os.readlink('/proc/self/ns/net')
            proof=json.loads(command(['/usr/bin/unshare','--net','/usr/bin/python3','-I','-B','/opt/satsuma-core/integrations/network_health_probe.py',
                                      '--parent-netns',original_netns],timeout=20))
            checks['packet_drop']={'ok':proof.get('packet_drop_verified') is True,**proof}
        except Exception as exc:checks['packet_drop']={'ok':False,'error':str(exc)[-1500:]}
        # Verify actual production rule linkage separately from isolated packet capability.
        try:
            import importlib.util
            spec=importlib.util.spec_from_file_location('health_guard','/opt/satsuma-core/integrations/satsuma_guard.py')
            guard=importlib.util.module_from_spec(spec);spec.loader.exec_module(guard)
            guard.Nft().verify_layout();checks['production_incoming_rules']={'ok':True,'scope':'layout_only'}
        except Exception as exc:checks['production_incoming_rules']={'ok':False,'error':str(exc)[:250]}
        try:
            from .app_firewall import status as app_status
            app=app_status()
            checks['app_control']={'ok':app.get('status') == 'ACTIVE',**app}
            queues=Path('/proc/net/netfilter/nfnetlink_queue').read_text()
            bound={int(line.split()[0]) for line in queues.splitlines() if line.split()}
            required={100,201} if app.get('enabled') else {100}
            checks['nfqueue_consumers']={'ok':required.issubset(bound),'bound':sorted(bound)}
        except Exception as exc:checks['app_control']={'ok':False,'error':str(exc)[:250]}
        if dns_policy.get('enabled'):
            try:
                from .dnsmasq_control import probe
                probe(timeout=3)
                from .dns_readiness import probe_system
                evidence=probe_system(timeout=3)
                checks['dns_filter']={'ok':True,'status':'ACTIVE','local_ready':True,**evidence}
            except Exception as exc:
                checks['dns_filter']={'ok':False,'error':str(exc)[:250]}
                states['satsuma-core-dns.service']['ActiveState']='unhealthy'
        else:checks['dns_filter']=disabled_dns_check(dns_policy)
        if checks.get('worker_heartbeats',{}).get('ok') is False and states['satsuma-teams.service'].get('ActiveState')=='active':
            states['satsuma-teams.service']={**states['satsuma-teams.service'],'ActiveState':'unhealthy'}
        # Repairs cannot run modified application payloads or unmask deliberate administrative blocks.
        if checks['integrity']['ok']:
            for unit,item in states.items():
                if item.get('UnitFileState') in ('masked','masked-runtime'):
                    repairs.append({'unit':unit,'status':'MASKED_REQUIRES_OPERATOR'});continue
                if repair_allowed(unit,item.get('ActiveState'),history,time.time()):
                    now=time.time();history[unit]=[t for t in history.get(unit,[]) if 0<=now-t<1800]+[now]
                    # Persist budget BEFORE acting, including on crash/restart.
                    report({**base,'updated_at':now,'repair_history':history,'repairs':repairs})
                    try:
                        command(['/usr/bin/systemctl','reset-failed',unit])
                        command(['/usr/bin/systemctl','restart' if item.get('ActiveState')=='unhealthy' else 'start','--no-block',unit])
                        repairs.append({'unit':unit,'status':'START_REQUESTED'})
                    except Exception as exc:repairs.append({'unit':unit,'status':'FAILED','error':str(exc)[:200]})
        if repairs:
            time.sleep(3)
            after=inspect_units()
            if not dns_policy.get('enabled'):
                after.pop('satsuma-core-dns.service',None);after.pop('satsuma-dns-netns.service',None)
            checks['services_after_repair']={'ok':all(v.get('ActiveState')=='active' for v in after.values()),'states':after}
            # Keep the original evidence, but assess current service state.
            # A recovered service must not leave the pre-repair failure in
            # the final conjunction indefinitely.
            checks['services']={**checks['services_after_repair'], 'before_repair': checks['services']['states']}
        ok=all(item.get('ok') is True for item in checks.values())
        result={**base,'status':'PASSED' if ok else 'DEGRADED','message':'Sağlık kontrolü tamamlandı' if ok else 'Sağlık kontrolü tamamlandı; koruma eksikleri var','updated_at':time.time(),'checks':checks,'repairs':repairs,'repair_history':history,
                'guide':'/usr/share/doc/satsuma-core/SELF-REPAIR-GUIDE.md','scope':'Service status, fresh worker evidence, signed integrity, isolated UDP packet drop and production rule layout; not full attack prevention.'}
        report(result)
        RootDataStore('self-health/events.jsonl').append(result)
        print(json.dumps(result),flush=True)
        return result
    except Exception as exc:
        result={**base,'status':'FAILED','updated_at':time.time(),'error':str(exc)[:300],'checks':checks,'repairs':repairs,'repair_history':history}
        report(result);print(json.dumps(result),flush=True)
        raise


def main():
    import argparse
    parser=argparse.ArgumentParser()
    parser.add_argument('--report',action='store_true',help='Print the latest completed health result')
    args=parser.parse_args()
    result=read_report() if args.report else run()
    if args.report:
        print(json.dumps({'status':result.get('status','UNKNOWN'),
                          'failed_checks':[name for name,item in (result.get('checks') or {}).items()
                                           if isinstance(item,dict) and item.get('ok') is False],
                          'report_path':str(ROOT/'status.json')}),flush=True)
        if result.get('status')!='PASSED':print(notice_text(result),flush=True)
    return 0 if result.get('status')=='PASSED' else 1


if __name__=='__main__':raise SystemExit(main())
