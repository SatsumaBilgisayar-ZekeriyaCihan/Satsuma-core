"""Root operator channel. Typed requests, server-side sessions and peer binding.

Lowering protection is never easier than raising it (audit K7): pausing,
stopping a service, adding an allowed IP or domain, unblocking, resetting
the integrity baseline or switching a filter off needs the admin password
again, not just the session, and every such change is recorded as
critical in ``protection_changes``. Importing or connecting a WireGuard
profile also asks for the password, because it opens a port and changes
where traffic goes; the uploaded file text is never recorded. A background
thread keeps the WireGuard port in step with NetworkManager and writes
Satsuma's OpenSnitch allow rules (wireguard_loop).

Root operatör kanalı. Tipli istekler, sunucu tarafı oturumlar ve eş bağlama.

Korumayı azaltmak hiçbir zaman artırmaktan kolay değildir (denetim K7):
duraklatma, servis durdurma, izinli IP ya da alan adı ekleme, engel
kaldırma, bütünlük tabanını sıfırlama ya da bir filtreyi kapatma yalnızca
oturum değil yönetici parolasının yeniden girilmesini ister; her biri
``protection_changes`` altında kritik olarak kaydedilir. WireGuard profilini
içe aktarmak ya da bağlamak da parola ister, çünkü port açar ve trafiğin
yolunu değiştirir; yüklenen dosya metni hiçbir yere kaydedilmez. Arka plandaki
bir iş parçacığı WireGuard portunu NetworkManager ile eşit tutar ve
Satsuma'nın OpenSnitch izin kurallarını yazar.
"""
import grp
import ipaddress
import json
import os
import re
import socket
import struct
import subprocess
import time
from .dashboard_auth import AuthManager
from .store import Store
from .config import load
from .response import ResponseWorker

SOCKET_PATH = '/run/satsuma/operator.sock'
SERVICES = ('satsuma-core-gateway.service', 'satsuma-core-sentinel.service', 'satsuma-network-identity.service', 'satsuma-rescue.service', 'satsuma-network.service', 'satsuma-suricata-ips.service', 'satsuma-core-dns.service', 'satsuma-core-otx.service', 'satsuma-core-subnet.service', 'satsuma-early-guard.service', 'satsuma-guardian.service', 'satsuma-core.service', 'satsuma-teams.service', 'satsuma-core-audit.service',
            'satsuma-core-finding.service', 'satsuma-reader.service', 'satsuma-udev.service', 'satsuma-integrity-check.service', 'satsuma-suricata-otx-guard.service')


def weakens(method, params):
    """True when the request lowers protection (audit K7)."""
    enabled = params.get('enabled')
    if method in ('process_approval_decide', 'deep_rule_review_decide', 'interactive_process_test_mode'):
        return True  # Explicit password for every decision and mode change.
    if method == 'rule_response_set_requirement':
        return True  # Per-rule evidence-policy edits require fresh administrator authentication.
    if method in ('integrity_rebaseline', 'allow_ip', 'allow_domain', 'unblock'):
        return True
    if method == 'lan_access':
        return enabled is True
    if method in ('subnet_protection', 'otx_enabled', 'otx_blocker', 'dns_filter', 'hagezi_enabled', 'auto_network', 'enforcement'):
        return enabled is False
    if method == 'service':
        return params.get('action') == 'stop'
    if method == 'application_control':
        return params.get('action') == 'disable'
    if method == 'egress_profile' and params.get('action') == 'set':
        from .egress_profiles import opens_more
        return opens_more(params.get('selection'))
    if method == 'wireguard':
        # Importing or connecting opens a port and changes where traffic goes.
        return params.get('action') in ('import', 'up')
    return False


class OperatorController:
    def __init__(self, store, auth=None, config=None, runner=subprocess.run, boot_provider=None, jobs=None):
        self.store, self.auth = store, auth or AuthManager()
        self.config, self.runner = config or {}, runner
        self.owners = {}
        from .early_guard import read_verdict
        from .maintenance_jobs import MaintenanceJobs
        self.boot_provider = boot_provider or read_verdict
        self.jobs = jobs or MaintenanceJobs(store)

    def dispatch(self, uid, method, params):
        if method == 'login':
            self.owners = {token: owner for token, owner in self.owners.items() if self.auth.validate_session(token)}
            result = self.auth.login(str(params.get('password', '')), client=str(uid))
            if result.get('ok'):
                self.owners[result['token']] = uid
            return result
        token = str(params.get('token', ''))
        if self.owners.get(token) != uid or not self.auth.validate_session(token):
            raise PermissionError('Yönetici oturumu gerekli / süresi doldu')
        if method.startswith('deepseek_'):
            from .deepseek_workflow import dispatch
            return dispatch(self.store, uid, method, params, self.config)
        lowered = weakens(method, params)
        if lowered:
            # Audit K7: a session alone is not enough to lower protection.
            check = self.auth.login(str(params.get('password', '')), client=str(uid))
            if not check.get('ok'):
                self.store.add('protection_changes', {'timestamp': time.time(), 'severity': 'critical',
                    'method': method, 'operator_uid': uid, 'status': 'refused_password',
                    'reason': check.get('error', 'invalid_credentials')})
                raise PermissionError('Korumayı azaltan işlem için yönetici parolasını yeniden girin (denetim K7)')
            self.auth.logout(check['token'])
        if method == 'logout':
            self.auth.logout(token)
            self.owners.pop(token, None)
            return {'ok': True}
        if method == 'status':
            from .dashboard_api import m_health_summary
            from .intervention_guard import evaluate
            return {'ok': True, 'vpn_proxy':self.store.get('vpn_proxy',{'status':'NOT_RUN','items':[]}),
                    'wireguard': __import__('satsuma.wireguard', fromlist=['status']).status(self.store, self.runner),
                    'opensnitch': __import__('satsuma.opensnitch', fromlist=['status']).status(),
                    'dns_threat_feeds':{name:self.store.get('dns_threat_feed.'+name,{}) for name in ('malware','ransomware')},
                    'verification': evaluate(self.store, self.boot_provider), 'health_summary': m_health_summary(),
                    'policy': self.store.get('auto_action_policy', {}),
                    'allow_ips': self.store.get('operator_allow_ips', []),
                    'lan': self.store.get('satsuma_lan_state', {}), 'subnet': self.store.get('subnet_protection_policy', {}), 'dns': self.store.get('dns_policy', {}), 'otx': self.store.get('operator_otx_policy', {}), 'hagezi': self.store.get('hagezi_list', {}), 'otx_dns': __import__('satsuma.otx',fromlist=['dns_status']).dns_status(self.store), 'services': list(SERVICES), 'early_boot': self.boot_provider(), 'app_control': __import__('satsuma.app_firewall',fromlist=['status']).status(), 'maintenance': self.jobs.status(), 'interactive_process_test_mode': self.store.get('interactive_process_test_mode', False), 'process_approval_pending': __import__('satsuma.process_approval', fromlist=['public_pending']).public_pending(self.store), 'deep_rule_review_pending': __import__('satsuma.deep_rule_review', fromlist=['pending']).pending(self.store), 'enforcement': __import__('satsuma.enforcement',fromlist=['describe']).describe(self.store), 'egress': __import__('satsuma.egress_profiles',fromlist=['describe']).describe(__import__('satsuma.egress_profiles',fromlist=['load']).load())}
        if method == 'interactive_process_test_mode':
            enabled = params.get('enabled')
            if type(enabled) is not bool:
                raise ValueError('Explicit boolean required')
            # Revoke stale approvals BEFORE restoring ordinary auto-response.
            # Previously queued requests cannot be resurrected by toggling
            # test mode off/on.  Auth above is fresh for this change.
            cancelled = 0
            if enabled is False:
                from .process_approval import cancel_all_pending
                cancelled = cancel_all_pending(self.store)
                from .deep_rule_review import cancel_all
                cancelled += cancel_all(self.store)
            self.store.set('interactive_process_test_mode', enabled)
            result = {'ok': True, 'enabled': enabled, 'cancelled_requests': cancelled}
        elif method == 'deep_rule_review_decide':
            from .deep_rule_review import decide
            result = decide(self.store, params.get('request_id'), params.get('decision'), uid)
        elif method == 'process_approval_decide':
            from .process_approval import decide
            from .auto_process import respond as respond_process
            from . import enforcement
            def guarded_process(finding, request_id):
                if self.store.get('interactive_process_test_mode', False) is not True:
                    return {'status': 'test_mode_disabled', 'signal_sent': False}
                config = enforcement.apply(self.store, dict(self.config))
                return respond_process(self.store, config, finding,
                                       ResponseWorker(self.store, config),
                                       approved_request=request_id)
            result = decide(self.store, params.get('request_id'),
                            params.get('decision'), uid,
                            process_handler=guarded_process)
        elif method == 'rule_response_set_requirement':
            from .rule_response import set_requirement
            result = set_requirement(self.store, params.get('rule_id'), params.get('minimum_sources'), uid, expected_hash=params.get('detection_sha256'), required_sources=params.get('required_sources'))
        elif method in ('boot_check','systemd_security','device_inventory','security_scan'):
            if method == 'security_scan' and not self.boot_provider().get('response_unlocked'):
                raise RuntimeError('Tarama başlatılmadan uygulama bütünlüğü doğrulanmalı')
            result = self.jobs.start(method)
        elif method == 'quarantine_scan_file':
            if params.get('confirmed') is not True:
                raise ValueError('Dosya karantinası için açık onay gerekli')
            scan_id=params.get('scan_id');file_index=params.get('file_index')
            if type(scan_id) is not int or type(file_index) is not int or file_index<0:
                raise ValueError('Geçerli tarama kaydı ve dosya seçimi gerekli')
            from .host_store import HostStore
            from .scan_quarantine import quarantine_target
            host=HostStore()
            try:
                row=host.db.execute("SELECT body FROM records WHERE id=? AND kind='security_scan'",(scan_id,)).fetchone()
                scan=json.loads(row[0]) if row else {}
                if scan.get('tool')!='clamav' or scan.get('exit_code')!=1 or scan.get('status')!='FINDINGS':
                    raise ValueError('Dosya içeren ClamAV bulgu kaydı gerekli')
                files=scan.get('files',[])
                if file_index>=len(files) or not files[file_index].get('sha256'):
                    raise ValueError('Dosya kimliği doğrulanamadı; yeniden tarayın')
                target=files[file_index]
            finally:host.close()
            result=quarantine_target(target,lambda record:self.store.add('quarantine_actions',
                {**record,'operator_uid':uid,'scan_id':scan_id,'timestamp':time.time()}))
            result={'ok':result['status']=='quarantined',**result}
        elif method in ('quarantine_system_file', 'quarantine_restore'):
            # 2.2.15: the user quarantines a program the audit proposed, or puts
            # a quarantined file back. Only proposed paths with the same digest.
            if params.get('confirmed') is not True:
                raise ValueError('Açık onay gerekli')
            from . import scan_quarantine
            audit=lambda record:self.store.add('quarantine_actions',{**record,'operator_uid':uid,'timestamp':time.time()})
            if method == 'quarantine_restore':
                result={'ok':True,**scan_quarantine.restore_target(str(params.get('quarantine_id','')),audit)}
            else:
                from .host_store import HostStore
                from .binary_audit import quarantine_allowed
                host=HostStore()
                try:state=host.get('binary_audit',{}) or {}
                finally:host.close()
                item=next((i for i in state.get('items',[]) if (i.get('quarantine_proposal') or {}).get('path')==params.get('path')
                           and i.get('sha256')==params.get('sha256')),None)
                if item is None or not quarantine_allowed(item):
                    raise ValueError('Bu dosya son denetimin karantina önerileri arasında değil; yeniden tarayın')
                target=scan_quarantine.inspect_target(item['path'])
                if target['sha256']!=item['sha256']:
                    raise ValueError('Dosya denetimden sonra değişmiş; yeniden tarayın')
                result={'ok':True,**scan_quarantine.quarantine_target(target,audit,system_ok=True)}
        elif method in ('ssh_key_decision', 'ssh_server_off'):
            # 2.2.15: every unconfirmed SSH key is a question to the user:
            # known, or quarantine. Only keys of the last audit are accepted.
            if params.get('confirmed') is not True:
                raise ValueError('Açık onay gerekli')
            from . import ssh_keys, scan_quarantine
            from .host_store import HostStore
            audit=lambda record:self.store.add('quarantine_actions',{**record,'operator_uid':uid,'timestamp':time.time()})
            if method == 'ssh_server_off':
                result={'ok':True,**ssh_keys.disable_sshd()}
            else:
                host=HostStore()
                try:
                    state=host.get('ssh_keys',{}) or {}
                    item=next((i for i in state.get('pending',[]) if i.get('id')==params.get('id')
                               and i.get('file')==params.get('file')),None)
                    if item is None or params.get('decision') not in ('known','quarantine'):
                        raise ValueError('Bu anahtar son SSH denetiminde onay bekleyenler arasında değil; yeniden tarayın')
                    if params['decision'] == 'known':
                        result={'ok':True,**ssh_keys.mark_known(host,item['id'])}
                    elif item['kind'] == 'authorized':
                        result={'ok':True,**ssh_keys.quarantine_authorized(item['file'],item['fingerprint'],audit)}
                    else:
                        result={'ok':True,**scan_quarantine.quarantine_target(scan_quarantine.inspect_target(item['path']),audit)}
                finally:host.close()
        elif method == 'device_decision':
            ident=params.get('device_id')
            choice=params.get('decision')
            devices=self.store.get('network_devices', {}) or {}
            if not isinstance(ident,str) or ident not in devices or choice not in ('allow','block'):
                raise ValueError('Geçerli cihaz ve engelle/izin ver kararı gerekli')
            device=devices[ident]
            observed=self.store.get('network_discovery', {}) or {}
            fresh=0<=time.time()-device.get('last_seen',0)<90
            matches=any(all(row.get(k)==device.get(k) for k in ('ip','mac','interface'))
                        for row in observed.get('neighbors',[]))
            if not fresh or not matches:
                raise ValueError('Cihaz kimliği güncel değil; keşfi yenileyip tekrar seçin')
            if not self.boot_provider().get('response_unlocked'):
                raise RuntimeError('Cihaz kararı için uygulama bütünlüğü doğrulanmalı')
            worker=ResponseWorker(self.store,{**self.config,'response_enabled':True},runner=self.runner)
            if choice=='block':
                applied=worker.block_ip(device['ip'],'Operator device decision: '+ident,manual=True)
                ok=applied.get('status')=='set_membership_confirmed'
            elif device.get('decision')=='block':
                applied=worker.unblock_ip(device['ip'],'Operator device allow: '+ident,manual=True)
                ok=applied.get('ok') is True
            else:
                applied={'status':'device_allowed','scope':'device_review_only'};ok=True
            if ok:
                device['decision']=choice
                device['decision_at']=time.time()
                device['decision_result']=applied
                self.store.set('network_devices',devices)
            result={'ok':ok,'device_id':ident,'decision':choice,'result':applied,
                    'scope':'Bu bilgisayarla IP bağlantısı; diğer cihazları ağdan çıkarmaz'}
        elif method == 'modem_inventory':
            from .modem_identity import inventory
            result={'ok':True,'modem_inventory':inventory()}
        elif method == 'modem_approve':
            from .modem_identity import approve
            fingerprint=params.get('route_fingerprint')
            if not isinstance(fingerprint,str) or not re.fullmatch('[a-f0-9]{64}',fingerprint):
                raise ValueError('Önce ayarları görüntüleyip onaylayın')
            result={'ok':True,**approve(params.get('candidate_id'),uid,params.get('confirmed'),expected_fingerprint=fingerprint)}
        elif method == 'modem_manual':
            from .modem_identity import approve_manual
            result={'ok':True,**approve_manual(params.get('mac'),uid,params.get('confirmed'))}
        elif method == 'vpn_proxy_disconnect':
            if not self.boot_provider().get('response_unlocked'):
                raise RuntimeError('VPN/proxy işlemi için güncel uygulama bütünlüğü doğrulanmalı')
            from .vpn_proxy import disconnect
            result=disconnect(params.get('target_id'),params.get('confirmed'),runner=self.runner)
            self.store.add('vpn_proxy_actions',{**result,'operator_uid':uid,'timestamp':time.time()})
        elif method == 'application_control':
            from .app_firewall import control
            action=params.get('action')
            if action in ('enable','decision','rule') and not self.boot_provider().get('response_unlocked'):
                raise RuntimeError('Güncel uygulama bütünlüğü doğrulanmalı')
            result={'ok':True,'application_control':control(action, {k:v for k,v in params.items() if k not in ('token','action')})}
        elif method == 'lan_access':
            if type(params.get('enabled')) is not bool:
                raise ValueError('enabled boolean gerekli')
            from .network_modes import NetworkModes, LAN_TABLE
            result = NetworkModes(self.store, self.runner).apply(LAN_TABLE, not params['enabled'])
        elif method == 'subnet_protection':
            if type(params.get('enabled')) is not bool:
                raise ValueError('enabled boolean gerekli')
            self.store.set('subnet_protection_policy', {'enabled': params['enabled'], 'threshold': 10, 'count_mode': 'subnet_distinct_peer_ips'})
            result = {'ok': True, 'enabled': params['enabled'], 'threshold': 10}
        elif method == 'otx_enabled':
            if type(params.get('enabled')) is not bool:
                raise ValueError('enabled boolean gerekli')
            if params['enabled']:
                from .otx import load_config
                if not load_config()['api_key']:
                    raise ValueError('OTX anahtarı eksik: root terminalinde satsuma-admin set-otx-key çalıştırın')
            self.store.set('operator_otx_policy', {**(self.store.get('operator_otx_policy', {}) or {}), 'enabled': params['enabled']})
            result = {'ok': True, 'enabled': params['enabled']}
        elif method == 'otx_blocker':
            if type(params.get('enabled')) is not bool:
                raise ValueError('enabled boolean gerekli')
            mode = params.get('match_mode')
            if mode == 'any_pulse':
                # Audit K3: anyone can publish a pulse; one must not block.
                raise ValueError('Tek OTX kaydıyla engelleme kaldırıldı (denetim K3); match_mode threshold olmalı')
            if mode is not None and mode != 'threshold':
                raise ValueError('match_mode threshold olmalı')
            policy = dict(self.store.get('operator_otx_policy', {}) or {})
            if params['enabled']:
                if not self.boot_provider().get('response_unlocked'):
                    raise RuntimeError('Erken açılış bütünlük kontrolü doğrulanmalı')
                from .otx import load_config
                if not load_config()['api_key']:
                    raise ValueError('OTX anahtarı eksik')
                from .network_control import validate_layout
                table = self.runner(['nft','-j','list','table','inet','satsuma_core'], capture_output=True,text=True,timeout=10)
                if table.returncode != 0 or not validate_layout(json.loads(table.stdout)):
                    raise RuntimeError('Strict firewall ve NFQUEUE 100 kuralları doğrulanmalı')
                policy['enabled'] = True
            policy['blocker_mode'] = params['enabled']
            if mode is not None:
                policy['match_mode'] = mode
            self.store.set('operator_otx_policy', policy)
            result = {'ok':True, **policy}
        elif method == 'dns_filter':
            enabled = params.get('enabled')
            if type(enabled) is not bool:
                raise ValueError('enabled boolean gerekli')
            policy = self.store.get('dns_policy', {}) or {}
            previous_policy = dict(policy)
            from .network_modes import NetworkModes, DNS_TABLE
            if enabled:
                resolver = ipaddress.ip_address(params.get('upstream', policy.get('upstream', '')))
                if resolver.is_loopback or resolver.is_unspecified or resolver.is_multicast:
                    raise ValueError('DNS upstream gerçek DNS sunucusu olmalı; loopback olamaz')
                policy = {**policy, 'enabled': True, 'upstream': str(resolver)}
                if 'upstream' in params:
                    policy['upstream_source'] = 'operator'
                self.store.set('dns_policy', policy)
                try:
                    from .dnsmasq_control import refresh
                    refresh(self.store, self.runner)
                    # Type=simple may return before the large list has loaded.
                    # Require actual TCP listeners and a DNS reply before redirecting.
                    from .dnsmasq_control import probe
                    probe()
                    result = NetworkModes(self.store, self.runner).apply(DNS_TABLE, True)
                    from .dnsmasq_control import record_readiness
                    record_readiness(self.store)
                except Exception:
                    self.store.set('dns_policy', previous_policy)
                    raise
            else:
                result = NetworkModes(self.store, self.runner).apply(DNS_TABLE, False)
                self.store.set('dns_policy', {**policy, 'enabled': False})
        elif method in ('custom_list_update','custom_list_remove'):
            from .custom_dns_lists import change
            from .dnsmasq_control import refresh
            result=change(self.store,params.get('url'),'update' if method=='custom_list_update' else 'remove',lambda:refresh(self.store,self.runner))
        elif method == 'custom_lists_status':
            from .custom_dns_lists import status
            result={'ok':True,'custom_lists':status(self.store)}
        elif method == 'hagezi_update':
            from .domain_lists import update
            info = update(self.store)
            from .dnsmasq_control import refresh
            refresh(self.store, self.runner)
            result = {'ok': True, **info}
        elif method == 'hagezi_enabled':
            if type(params.get('enabled')) is not bool:
                raise ValueError('enabled boolean gerekli')
            policy = self.store.get('dns_policy', {}) or {}
            previous_policy = dict(policy)
            if params['enabled']:
                upstream = params.get('upstream') or policy.get('upstream')
                if not upstream:
                    raise ValueError('Önce DNS sunucusunun IP adresini girin')
                from .domain_lists import LIST_PATH, update
                if not LIST_PATH.exists():
                    update(self.store)
                self.store.set('dns_policy', {**policy, 'hagezi_enabled': True})
                try:
                    result = self.dispatch(uid, 'dns_filter', {**params, 'upstream':upstream, 'enabled':True})
                except Exception:
                    self.store.set('dns_policy', previous_policy)
                    raise
            else:
                self.store.set('dns_policy', {**policy, 'hagezi_enabled': False})
                from .dnsmasq_control import refresh
                refresh(self.store, self.runner)
                result = {'ok':True, 'enabled':False}
        elif method in ('allow_domain', 'remove_allow_domain'):
            from .domain_lists import domain
            name = domain(params.get('domain', ''))
            allowed = set(self.store.get('dns_allowed_domains', []) or [])
            allowed.add(name) if method == 'allow_domain' else allowed.discard(name)
            self.store.set('dns_allowed_domains', sorted(allowed))
            from .dnsmasq_control import refresh
            refresh(self.store, self.runner)
            result = {'ok': True, 'allowed_domains': sorted(allowed)}
        elif method == 'integrity_rebaseline':
            self.store.set('critical_paths_baseline', {})
            result = {'ok': True, 'status': 'baseline_reset_pending'}
        elif method == 'auto_network':
            if type(params.get('enabled')) is not bool:
                raise ValueError('enabled boolean gerekli')
            if params['enabled']:
                from .network_control import validate_layout
                table = self.runner(['nft', '-j', 'list', 'table', 'inet', 'satsuma_core'], capture_output=True, text=True, timeout=10)
                if table.returncode != 0 or not validate_layout(json.loads(table.stdout)):
                    raise RuntimeError('Satsuma firewall tablosu ve DROP kuralları hazır değil')
            self.store.set('auto_action_policy', {'network_enabled': params['enabled'], 'early_guard_required': False})
            result = {'ok': True, 'network_enabled': params['enabled']}
        elif method in ('allow_ip', 'remove_allow_ip'):
            ip = str(ipaddress.ip_address(params.get('ip', '')))
            current = set(self.store.get('operator_allow_ips', []) or [])
            current.add(ip) if method == 'allow_ip' else current.discard(ip)
            self.store.set('operator_allow_ips', sorted(current))
            result = {'ok': True, 'allow_ips': sorted(current)}
        elif method == 'unblock':
            config = {**self.config, 'response_enabled': True}
            result = ResponseWorker(self.store, config).unblock_ip(str(ipaddress.ip_address(params.get('ip', ''))), 'Yönetici kaldırdı', manual=True)
        elif method == 'enforcement':
            if type(params.get('enabled')) is not bool:
                raise ValueError('enabled boolean gerekli')
            from .enforcement import set_policy
            result = {'ok': True, 'enforcement': set_policy(self.store, params['enabled'], uid)}
        elif method == 'egress_profile':
            from . import egress_profiles
            action = params.get('action')
            if action == 'status':
                result = {'ok': True, 'profile': egress_profiles.describe(egress_profiles.load())}
            elif action == 'set':
                from .network_control import apply_profile
                selection = egress_profiles.normalize(params.get('selection'))
                # The WireGuard ports belong to satsuma.wireguard; the panel never drops them.
                selection['wireguard'] = egress_profiles.load()['wireguard']
                applied = apply_profile(selection, runner=self.runner)
                self.store.set('egress_profile', {'selection': selection, 'ports': applied['ports'], 'updated_at': time.time()})
                result = {'ok': True, 'profile': egress_profiles.describe(selection)}
            else:
                raise ValueError('Desteklenmeyen profil işlemi')
        elif method == 'wireguard':
            from . import wireguard
            action = params.get('action')
            if action == 'status':
                result = wireguard.status(self.store, self.runner)
            elif action == 'import':
                result = wireguard.import_profile(self.store, params.get('name'), params.get('text'), self.runner)
            elif action == 'up':
                result = wireguard.up(self.store, params.get('name'), self.runner)
            elif action == 'down':
                result = wireguard.down(self.store, params.get('name'), self.runner)
            elif action == 'remove':
                result = wireguard.remove(self.store, params.get('name'), self.runner)
            else:
                raise ValueError('Desteklenmeyen WireGuard işlemi')
            params = {k: v for k, v in params.items() if k != 'text'}
        elif method == 'service':
            name, action = params.get('name'), params.get('action')
            if name not in SERVICES or action not in ('start', 'stop', 'restart', 'status'):
                raise ValueError('Desteklenmeyen servis veya işlem')
            args = ['/usr/bin/systemctl', 'show', '--property=ActiveState,SubState', name] if action == 'status' else ['/usr/bin/systemctl', action, name]
            completed = self.runner(args, capture_output=True, text=True, timeout=20)
            result = {'ok': completed.returncode == 0, 'output': (completed.stdout + completed.stderr)[-4000:]}
        else:
            raise ValueError('Desteklenmeyen yönetim işlemi')
        if lowered:
            self.store.add('protection_changes', {'timestamp': time.time(), 'severity': 'critical',
                'method': method, 'operator_uid': uid, 'status': 'applied',
                'params': {k: v for k, v in params.items() if k not in ('token', 'password')}})
        operation = result.get('application_control') or result
        pending = operation.get('status') in ('RUNNING', 'REQUESTED')
        self.store.add('actions', {'action': 'operator.' + method, 'operator_uid': uid,
                                  'command_id': operation.get('command_id'),
                                  'status': operation['status'] if pending else
                                            'completed' if result.get('ok') else result.get('status', 'failed'),
                                  'result': result})
        return result


def read_exact(conn, count):
    data = bytearray()
    while len(data) < count:
        part = conn.recv(count - len(data))
        if not part:
            raise ConnectionError('Bağlantı kesildi')
        data.extend(part)
    return bytes(data)


def wireguard_loop(interval=20, stop=None):
    """Keep the firewall port of Satsuma WireGuard profiles in step with NetworkManager.

    A profile switched on or off from the desktop network menu gets its port
    opened or closed within ``interval`` seconds. Masaüstü ağ menüsünden
    açılıp kapatılan profilin portu da birkaç saniye içinde açılır ya da kapanır.
    """
    import threading
    from . import wireguard
    stop = stop or threading.Event()
    while not stop.wait(interval):
        store = Store()
        try:
            if store.get(wireguard.STATE_KEY):
                wireguard.sync(store)
            from . import egress_profiles, opensnitch
            opensnitch.sync_rules(opensnitch.wanted_rules(egress_profiles.load()['wireguard']['udp'], opensnitch.dns_uid()))
        except Exception as exc:
            try:
                store.add('errors', {'component': 'wireguard_sync', 'error': str(exc)[:200], 'timestamp': time.time()})
            except Exception:
                pass
        finally:
            store.close()


def run():
    if os.geteuid() != 0:
        raise PermissionError('Yönetim servisi root olarak çalışmalı')
    import threading
    threading.Thread(target=wireguard_loop, name='wireguard-sync', daemon=True).start()
    store = Store()
    controller = OperatorController(store, config=load())
    # RuntimeDirectory is created by systemd, owned by root, mode 0750.
    server = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    if os.path.lexists(SOCKET_PATH):
        raise RuntimeError('Socket exists; refusing to replace it')
    server.bind(SOCKET_PATH)
    os.chown(SOCKET_PATH, 0, grp.getgrnam('satsuma-reader').gr_gid)
    os.chmod(SOCKET_PATH, 0o660)
    server.listen(8)
    try:
        while True:
            conn, _ = server.accept()
            with conn:
                conn.settimeout(5)
                try:
                    _, uid, _ = struct.unpack('3i', conn.getsockopt(socket.SOL_SOCKET, socket.SO_PEERCRED, 12))
                    size = struct.unpack('>I', read_exact(conn, 4))[0]
                    if size > 65536:
                        raise ValueError('İstek çok büyük')
                    request = json.loads(read_exact(conn, size))
                    result = controller.dispatch(uid, request['method'], request.get('params') or {})
                    response = {'result': result}
                except Exception as exc:
                    response = {'error': str(exc)[:300]}
                body = json.dumps(response, ensure_ascii=False).encode()
                try:
                    conn.sendall(struct.pack('>I', len(body)) + body)
                except OSError:
                    pass
    finally:
        server.close()
        os.unlink(SOCKET_PATH)
        store.close()


if __name__ == '__main__':
    run()
