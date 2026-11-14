"""Revalidate edited policy, retain last valid protection, apply named services."""
import json
import os
import subprocess
import time

UNITS=('satsuma-core.service','satsuma-teams.service','satsuma-core-otx.service',
       'satsuma-core-subnet.service','satsuma-core-audit.service','satsuma-core-finding.service',
       'satsuma-app-control.service')


def apply_features(store, config):
    def update(key, values):
        store.set(key,{**(store.get(key,{}) or {}),**values})
    update('subnet_protection_policy',{'enabled':config.get('subnet_protection_enabled',True)})
    update('operator_otx_policy',{'enabled':config.get('otx_enabled',True),
        'blocker_mode':config.get('otx_blocker_mode',True),'match_mode':config.get('otx_match_mode','threshold')})
    update('auto_action_policy',{'network_enabled':config.get('auto_action_network_enabled',True),
                                'early_guard_required':False})
    dns=store.get('dns_policy',{}) or {}
    from .dnsmasq_control import OPENDNS, is_cloudflare
    if is_cloudflare(dns.get('upstream')):
        dns['upstream']=OPENDNS[0];dns['upstream_source']='opendns_replaced_cloudflare'
    if config.get('dns_filter_enabled',True) and not dns.get('upstream'):
        dns['upstream']=OPENDNS[0];dns['upstream_source']='opendns_default'
    elif dns.get('upstream') and not dns.get('upstream_source'):
        # 2.2.15: an upstream taken automatically from the modem (a LAN
        # address) moves to OpenDNS once; an operator's choice is marked and kept.
        import ipaddress
        try:private=ipaddress.ip_address(dns['upstream']).is_private
        except ValueError:private=True
        dns['upstream_source']='opendns_default' if private else 'kept'
        if private:dns['upstream']=OPENDNS[0]
    # 2.2.38: the lock stays on; the HaGeZi and threat lists are retired (owner, 2026-11-13).
    # 2.2.38: kilit açık kalır; HaGeZi ve tehdit listeleri kaldırıldı.
    dns.update(enabled=config.get('dns_filter_enabled',True),hagezi_enabled=False,threat_lists_enabled=False)
    store.set('dns_policy',dns)
    from .dnsmasq_control import refresh
    refresh(store)
    from .network_modes import NetworkModes,LAN_TABLE
    NetworkModes(store).apply(LAN_TABLE,not config.get('lan_access_enabled',True))
    from .protected_storage import RootDataStore
    from .app_firewall import policy
    data=policy();data['enabled']=config.get('app_control_enabled',True)
    RootDataStore('app-control/policy.json').replace(data)


def reload_configuration(store=None, monitor=None, runner=subprocess.run, apply=apply_features):
    from .config import load_with_policy, remember_policy
    from .integrity_monitor import run_once
    from .store import Store
    report=(monitor or run_once)()
    if report.get('status')!='HEALTHY':
        return {'status':'FAILED','protection_unlocked':False,'integrity':report}
    config,meta,selected_policy=load_with_policy()
    own=store is None;store=store or Store()
    try:
        changed=meta['sha256']!=store.get('configuration.applied_digest')
        units=[]
        if changed:
            apply(store,config)
            for unit in UNITS:
                state=runner(['/usr/bin/systemctl','show',unit,'--property=ActiveState,UnitFileState'],
                             capture_output=True,text=True,timeout=10,check=True)
                values=dict(line.split('=',1) for line in state.stdout.splitlines() if '=' in line)
                if values.get('UnitFileState') in ('masked','masked-runtime','disabled'):continue
                command='try-restart' if values.get('ActiveState')=='active' else 'start'
                runner(['/usr/bin/systemctl',command,'--no-block',unit],check=True,timeout=10)
                units.append(unit)
            remember_policy(selected_policy,meta)
            store.set('configuration.applied_digest',meta['sha256'])
        result={'status':'LAST_VALID' if meta['status']=='last_valid' else 'APPLY_REQUESTED' if changed else 'VALIDATED',
                'updated_at':time.time(),'protection_unlocked':True,'configuration':meta,
                'services_requested':units,'service_readiness_verified':False}
        store.set('configuration_reload',result)
        if meta['status']=='last_valid':
            store.add('findings',{'source':'configuration','classification':'indicator','severity':'high',
                'timestamp':time.time(),'rule_id':'SATSUMA-CONFIG-001',
                'title':'Yeni ayar reddedildi; koruma son geçerli ayarlarla devam ediyor',
                'details':meta})
        runner(['/usr/bin/systemctl','start','--no-block','satsuma-self-health.service'],check=True,timeout=10)
        return result
    finally:
        if own:store.close()


def main():
    if os.geteuid()!=0:raise PermissionError('Root required')
    time.sleep(.25)
    result=reload_configuration()
    print(json.dumps(result))
    return 1 if result['status']=='FAILED' else 0


if __name__=='__main__':raise SystemExit(main())
