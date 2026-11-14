"""Core configuration loading and validation.

An old ``otx_match_mode: any_pulse`` is read as ``threshold`` (audit K3).

Core yapılandırmasının yüklenmesi ve doğrulanması.

Eski ``otx_match_mode: any_pulse`` ayarı ``threshold`` olarak okunur
(denetim K3).
"""
import json
import os
import re
from pathlib import Path
from .response import address
from .dns import domain

# Retired web-research keys remain accepted only for legacy config migration.
RETIRED_WEB_KEYS = frozenset({'investigation_web_enabled', 'investigation_trusted_sources'})

# Destructive (yıkıcı) response aksiyonları — policy ile açıkça yetkilendirilmeli.
DESTRUCTIVE_ACTIONS = ('network_isolate', 'process_kill', 'file_quarantine', 'user_disable')

DEFAULT={
 'eve_path':'/var/log/suricata/eve.json','eve_writer_uid':'managed_suricata',
 'auto_action_network_enabled':True,
 # Requires the global response switch and explicit process_kill policy too.
 'auto_action_process_enabled':True,
 'network_discovery_enabled':True, 'subnet_protection_enabled':True,
 'app_control_enabled':True, 'dns_filter_enabled':True, 'hagezi_enabled':True,
 'dns_threat_lists_enabled':True,
 'lan_access_enabled':True, 'otx_match_mode':'threshold',
 'response_enabled':True,'nft_family':'inet','nft_table':'satsuma_core','nft_set':'blocked_ips','nft_set_v6':'blocked_ips_v6',
 'frequency_window_seconds':300,'expected_dns_servers':[], 'watch_domains':[], 'dns_actions':[],
 # Local investigation remains enabled; no web research is performed.
 'investigation_enabled':True,
 # Otomatik kural adaptörü — web'den gelen bilgiyi kurala çevirir (açık).
 'rule_adapter_enabled':True,
 'rule_adapter_output_dir':'/var/lib/satsuma-core/generated_rules',
 'rule_adapter_require_review':True,
 # DeepSeek API — güncel tehdit araştırması için. API anahtarı ZORUNLU.
 # Anahtar /etc/satsuma-core/deepseek.key (0600 root:root; yalnız yetkili arka uç) dosyasında.
 'deepseek_enabled':True,
 'deepseek_endpoint':'https://api.deepseek.com/v1/chat/completions',
 'deepseek_model':'deepseek-chat',
 'deepseek_timeout':30,
 # Yerel istek sınırı (2.2.19): saatte en fazla bu kadar başarılı/süren istek, arada 3 saniye.
 'deepseek_requests_per_hour':60,
 # OTX tehdit istihbaratı — servis bazlı yönetim.
 # blocker_mode: OTX tek başına bloker olarak kullanılabilir (TLS + taze pulse şartıyla).
 'otx_enabled':True,
 'otx_blocker_mode':True,
 'otx_pulse_threshold':11,
 'otx_recent_pulse_days':14,
 'otx_require_tls':True,
 # Yıkıcı yanıt: bütün eylemler açık (tam koruma, 2.2.9).
 'destructive_response_enabled':True,
 'destructive_allowed_actions':list(DESTRUCTIVE_ACTIONS),
 # Parolasız sudo (NOPASSWD) oto-blok — varsayılan AÇIK.
 # Tespit edilirse süreç öldürülür (Satsuma kullanıcıları hariç).
 'sudo_autoblock_enabled':True,
}

def validate(config):
    unknown=set(config)-set(DEFAULT)-{'schema_version'}-RETIRED_WEB_KEYS
    if unknown:raise ValueError('Unknown configuration keys: '+','.join(sorted(unknown)))
    if 'schema_version' in config:
        version=config['schema_version']
        if type(version) is not int or version>2:raise ValueError('Unsupported config schema_version')
    out={**DEFAULT,**{key:value for key,value in config.items() if key in DEFAULT}}
    for key in ('network_discovery_enabled','subnet_protection_enabled','app_control_enabled','dns_filter_enabled','hagezi_enabled','dns_threat_lists_enabled','lan_access_enabled'):
        if type(out[key]) is not bool:raise ValueError(key+' must be boolean')
    if out['otx_match_mode'] not in ('threshold','any_pulse'):raise ValueError('Invalid OTX match mode')
    # Audit K3: a stored any_pulse (one pulse blocks) is read as threshold.
    out['otx_match_mode']='threshold'
    p=Path(out['eve_path'])
    if not p.is_absolute() or not p.is_relative_to('/var/log') or '..' in p.parts:raise ValueError('EVE must be under /var/log')
    uid=out['eve_writer_uid']
    if uid != 'managed_suricata' and (type(uid) is not int or uid<0):raise ValueError('invalid writer UID')
    if type(out['auto_action_network_enabled']) is not bool:raise ValueError('auto_action_network_enabled must be boolean')
    if type(out['auto_action_process_enabled']) is not bool:raise ValueError('auto_action_process_enabled must be boolean')
    if type(out['response_enabled']) is not bool:raise ValueError('response_enabled must be boolean')
    if out['nft_family'] not in ('ip','ip6','inet'):raise ValueError('invalid nft family')
    for key in ('nft_table','nft_set','nft_set_v6'):
        if not isinstance(out[key],str) or not re.fullmatch(r'[A-Za-z_][A-Za-z0-9_]{0,63}',out[key]):raise ValueError('invalid nft name')
    if type(out['frequency_window_seconds']) is not int or not 1<=out['frequency_window_seconds']<=86400:raise ValueError('invalid frequency window')
    for key in ('expected_dns_servers','watch_domains','dns_actions'):
        if not isinstance(out[key],list) or len(out[key])>4096:raise ValueError('invalid policy list')
    out['expected_dns_servers']=[address(x) for x in out['expected_dns_servers']]
    out['watch_domains']=[domain(x) for x in out['watch_domains']]
    for rule in out['dns_actions']:
        if not isinstance(rule,dict) or rule.get('action') not in ('watch','block_ip'):raise ValueError('invalid DNS action')
        rule['domain']=domain(rule['domain'])
        if rule['action']=='block_ip':rule['target_ip']=address(rule['target_ip'])
    # Investigation ayarları
    if type(out['investigation_enabled']) is not bool:raise ValueError('investigation_enabled must be boolean')
    # Kural adaptörü
    if type(out['rule_adapter_enabled']) is not bool:raise ValueError('rule_adapter_enabled must be boolean')
    if type(out['rule_adapter_require_review']) is not bool:raise ValueError('rule_adapter_require_review must be boolean')
    outdir=out['rule_adapter_output_dir']
    if not isinstance(outdir,str) or not outdir.startswith('/var/lib/satsuma-core/'):
        raise ValueError('rule_adapter_output_dir must be under /var/lib/satsuma-core/')
    # DeepSeek ayarları
    if type(out['deepseek_enabled']) is not bool:raise ValueError('deepseek_enabled must be boolean')
    if not isinstance(out['deepseek_endpoint'],str) or not out['deepseek_endpoint'].startswith('https://'):
        raise ValueError('deepseek_endpoint must be an https URL')
    if not isinstance(out['deepseek_model'],str) or not out['deepseek_model']:
        raise ValueError('deepseek_model must be a non-empty string')
    if type(out['deepseek_timeout']) is not int or not 1<=out['deepseek_timeout']<=120:
        raise ValueError('deepseek_timeout must be 1-120 seconds')
    if type(out['deepseek_requests_per_hour']) is not int or not 1<=out['deepseek_requests_per_hour']<=600:
        raise ValueError('deepseek_requests_per_hour must be 1-600')
    # OTX ayarları
    if type(out['otx_enabled']) is not bool:raise ValueError('otx_enabled must be boolean')
    if type(out['otx_blocker_mode']) is not bool:raise ValueError('otx_blocker_mode must be boolean')
    if type(out['otx_require_tls']) is not bool:raise ValueError('otx_require_tls must be boolean')
    if type(out['otx_pulse_threshold']) is not int or not 1<=out['otx_pulse_threshold']<=10000:
        raise ValueError('otx_pulse_threshold must be 1-10000')
    if type(out['otx_recent_pulse_days']) is not int or not 1<=out['otx_recent_pulse_days']<=365:
        raise ValueError('otx_recent_pulse_days must be 1-365')
    # Destructive response policy
    if type(out['destructive_response_enabled']) is not bool:
        raise ValueError('destructive_response_enabled must be boolean')
    actions=out['destructive_allowed_actions']
    if not isinstance(actions,list):raise ValueError('destructive_allowed_actions must be a list')
    unknown_actions=[a for a in actions if a not in DESTRUCTIVE_ACTIONS]
    if unknown_actions:raise ValueError('unknown destructive action(s): '+','.join(unknown_actions))
    # Sudo oto-blok
    if type(out['sudo_autoblock_enabled']) is not bool:
        raise ValueError('sudo_autoblock_enabled must be boolean')
    return out

def _read_secure_json(path):
    """Read a root-owned, non-symlink JSON file through a verified directory.

    This is the single raw-document read point used by the production config
    loader.  The directory helper refuses symlinked parents and root-unsafe
    directories; the final component is opened with ``O_NOFOLLOW`` and must be
    a root-owned regular file that is not writable by group/others.
    """
    path=Path(path)
    if not path.is_absolute() or '..' in path.parts:
        raise ValueError('absolute configuration path required')
    from .protected_storage import open_directory
    directory_fd=open_directory(path.parent)
    try:
        file_fd=os.open(path.name,os.O_RDONLY|os.O_NOFOLLOW,dir_fd=directory_fd)
        try:
            st=os.fstat(file_fd)
            import stat as _stat
            if not _stat.S_ISREG(st.st_mode):
                raise PermissionError('configuration must be a regular file')
            if st.st_uid!=0 or st.st_mode & 0o022 or st.st_nlink != 1:
                raise PermissionError('Configuration is not root protected')
            with os.fdopen(os.dup(file_fd),encoding='utf-8') as stream:
                return json.load(stream)
        finally:
            os.close(file_fd)
    finally:
        os.close(directory_fd)


def load():
    return load_with_policy()[0]


LAST_VALID_POLICY=Path('/var/lib/satsuma-core/configuration/last-valid-policy.json')

def load_with_policy(*, persist=False):
    """Canonical production config load path.

    All migration is applied here, exactly once, in memory.  The raw JSON file
    is never overwritten; an explicit atomic persistence operation remains a
    separate operator action.
    """
    from .config_migration import migrate_config_document
    from .policy import POLICY_PATH,digest
    policy_path=Path(POLICY_PATH)
    from .configuration_status import ConfigurationError
    def document(path, code):
        try:
            return migrate_config_document(_read_secure_json(path))
        except (ValueError, OSError, TypeError, KeyError) as exc:
            raise ConfigurationError(code, path, str(exc)) from exc
    selected=policy_path if policy_path.exists() or policy_path.is_symlink() else Path('/etc/satsuma-core/config.json')
    code='POLICY_INVALID' if selected==policy_path else 'CONFIG_UNSUPPORTED'
    try:
        config,policy=document(selected,code)
        meta={'schema_version':policy['schema_version'],'revision':policy['revision'],
              'sha256':digest(policy),'path':str(selected),'status':'validated'}
    except ConfigurationError as exc:
        # Only a previously validated, protected policy may sustain protection.
        # The invalid edited document is retained for the administrator to fix.
        try:
            config,policy=document(LAST_VALID_POLICY,code)
        except ConfigurationError:
            raise exc
        meta={'schema_version':policy['schema_version'],'revision':policy['revision'],
              'sha256':digest(policy),'path':str(selected),'status':'last_valid',
              'rejected_code':exc.code,'error':exc.detail,'active_path':str(LAST_VALID_POLICY)}
    if persist:remember_policy(policy,meta)
    from .full_protection import apply as full_protection
    return full_protection(config),meta,policy


def remember_policy(policy, meta):
    """Persist only a selected validated snapshot; read-only consumers never write."""
    if os.geteuid()!=0:return
    from .protected_storage import RootDataStore
    from .policy import validate as validate_policy,digest
    if meta['status']=='validated':
        policy=validate_policy(policy)
        if digest(policy)!=meta['sha256']:raise ValueError('Policy snapshot digest changed')
        try:cached=_read_secure_json(LAST_VALID_POLICY)
        except (OSError,ValueError,TypeError):cached=None
        if cached!=policy:RootDataStore('configuration/last-valid-policy.json').replace(policy)
    RootDataStore('configuration/status.json').replace(meta)
