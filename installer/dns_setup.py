"""Configure Satsuma's DNS filter; OpenDNS is the default (and, since 2.2.44, pinned) upstream.

2.2.15 (user decision 2026-10-26): a new installation starts with OpenDNS
(208.67.222.222, with 208.67.220.220 beside it). An upstream the operator
chose is kept. existing_resolver() remains for the operator's own choice.

Satsuma DNS filtresini yapılandırır; varsayılan üst sunucu OpenDNS'tir.
Yeni kurulum OpenDNS ile başlar; operatörün seçtiği üst sunucu korunur.
"""
import ipaddress
from pathlib import Path
import sys
sys.path.insert(0,'/opt/satsuma-core')


def existing_resolver(paths=(Path('/run/NetworkManager/no-stub-resolv.conf'),Path('/etc/resolv.conf'))):
    for path in paths:
        try:lines=path.read_text().splitlines()
        except FileNotFoundError:continue
        for line in lines:
            fields=line.split('#',1)[0].split()
            if len(fields)!=2 or fields[0]!='nameserver':continue
            try:address=ipaddress.ip_address(fields[1])
            except ValueError:continue
            if not (address.is_loopback or address.is_unspecified or address.is_multicast):return str(address)
    raise RuntimeError('No usable existing upstream resolver; DNS setup is incomplete')


def opendns():
    from satsuma.dnsmasq_control import OPENDNS
    return OPENDNS[0]


def opensnitch_rule():
    from satsuma.opensnitch import ensure_dns_rule
    ensure_dns_rule()


EVIDENCE=Path('/var/lib/satsuma-core/evidence')


def _nm_uses_dnsmasq(path):
    try:text=path.read_text()[:65536]
    except OSError:return False
    section=None
    for line in text.splitlines():
        line=line.split('#',1)[0].strip()
        if line.startswith('[') and line.endswith(']'):section=line[1:-1].strip().lower();continue
        if section=='main' and line.replace(' ','').lower()=='dns=dnsmasq':return True
    return False


def retire_system_dnsmasq(runner=None,etc=Path('/etc'),evidence=EVIDENCE,now=None):
    """Stop the distribution's own dnsmasq and keep its configuration as evidence.

    2.2.44 (owner's instruction): Satsuma's filter is the only dnsmasq that
    answers this machine's DNS. Fedora's dnsmasq.service is stopped, disabled
    and masked; /etc/dnsmasq.conf, /etc/dnsmasq.d/* and NetworkManager files
    that set dns=dnsmasq are moved (never deleted) into a dated evidence folder.
    Satsuma's own dnsmasq never reads these: it runs with --conf-file.
    Dağıtımın kendi dnsmasq'ı durdurulur ve maskelenir; yapılandırması silinmez,
    tarihli kanıt klasörüne taşınır.
    """
    import shutil,subprocess,time
    runner=runner or subprocess.run
    def systemctl(*args):
        return runner(['/usr/bin/systemctl',*args],capture_output=True,text=True,timeout=30)
    report={'service':None,'moved':[],'networkmanager_reloaded':False}
    enabled=systemctl('is-enabled','dnsmasq.service').stdout.strip()
    active=systemctl('is-active','dnsmasq.service').returncode==0
    if active or enabled in ('enabled','enabled-runtime','static','indirect'):
        systemctl('stop','dnsmasq.service');systemctl('disable','dnsmasq.service');systemctl('mask','dnsmasq.service')
        report['service']={'was_active':active,'was_enabled':enabled,'now':'masked'}
    candidates=[]
    if report['service']:
        candidates+=[etc/'dnsmasq.conf']+sorted((etc/'dnsmasq.d').glob('*') if (etc/'dnsmasq.d').is_dir() else [])
    nm=[path for path in sorted((etc/'NetworkManager'/'conf.d').glob('*.conf')) if _nm_uses_dnsmasq(path)] if (etc/'NetworkManager'/'conf.d').is_dir() else []
    main=etc/'NetworkManager'/'NetworkManager.conf'
    candidates+=nm
    candidates=[path for path in candidates if path.is_file() and not path.is_symlink()]
    if candidates:
        folder=evidence/('dnsmasq-'+time.strftime('%Y%m%d-%H%M%S',time.localtime(now)))
        folder.mkdir(parents=True,exist_ok=True,mode=0o700)
        for path in candidates:
            target=folder/(str(path.relative_to(etc)).replace('/','__'))
            shutil.move(str(path),str(target))
            report['moved'].append({'from':str(path),'to':str(target)})
        report['evidence']=str(folder)
    if nm:
        reloaded=runner(['/usr/bin/nmcli','general','reload'],capture_output=True,text=True,timeout=30)
        report['networkmanager_reloaded']=reloaded.returncode==0
    if _nm_uses_dnsmasq(main):
        # The main file belongs to the distribution; it is reported, not moved.
        report['networkmanager_main_uses_dnsmasq']=str(main)
    return report


def configure(store,resolver=opendns,refresh=None,rule=opensnitch_rule,retire=retire_system_dnsmasq):
    if refresh is None:
        from satsuma.dnsmasq_control import refresh
    # The DNS filter's OpenSnitch allow rule must exist before dnsmasq is probed
    # (2.2.36); failing to write it never stops DNS setup.
    # DNS filtresinin OpenSnitch izin kuralı dnsmasq sınanmadan önce var olmalı
    # (2.2.36); yazılamaması DNS kurulumunu durdurmaz.
    try:rule()
    except Exception:pass
    try:store.set('system_dnsmasq_retired',retire())
    except Exception as exc:store.set('system_dnsmasq_retired',{'error':str(exc)[:500]})
    policy=store.get('dns_policy',{}) or {}
    # 2.2.44: no downloaded list; the setting is dropped. İndirilen liste yok.
    policy.pop('threat_lists_enabled',None);policy.pop('hagezi_enabled',None)
    # Preserve an explicit operator decision, including a deliberate disable.
    if 'enabled' not in policy:
        policy={**policy,'enabled':True,'upstream':policy.get('upstream') or resolver()}
    store.set('dns_policy',policy)
    if policy.get('enabled'):return refresh(store)
    return {'status':'DISABLED_BY_OPERATOR'}


def main():
    from satsuma.store import Store
    store=Store()
    try:configure(store)
    except Exception as exc:
        import time
        store.set('dns_filter_health',{'status':'FAILED','error':str(exc)[:1000],'updated_at':time.time()})
        raise
    finally:store.close()


if __name__=='__main__':main()
