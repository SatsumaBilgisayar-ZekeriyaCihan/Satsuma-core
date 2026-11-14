"""Strict, data-only policy layer for the 0.2.x worker pipeline."""
import hashlib
import json
import os
import stat
import tempfile
from pathlib import Path

POLICY_PATH = Path('/etc/satsuma-core/policy.json')

# Default scan schedule; policy may select enabled engines, order and interval.
# Concurrent scans remain unsupported; ClamAV detections are quarantined
# automatically (2.2.11, satsuma.security_scan).
FIXED_SCAN_POLICY = {
    'enabled': True,
    'interval_seconds': 3600,
    'order': ['clamav', 'rkhunter', 'chkrootkit'],
    'overlap': False,
    'automatic_quarantine': True,
}

# OTX worker varsayılanları — policy'de yoksa bu değerler kullanılır.
DEFAULT_OTX = {
    'enabled': True,
    'blocker_mode': True,
    'pulse_threshold': 11,
    'recent_pulse_days': 14,
    'require_tls': True,
}

# Destructive response varsayılanları — tam koruma (2.2.9): hepsi açık.
DEFAULT_DESTRUCTIVE = {
    'enabled': True,
    'allowed_actions': ['network_isolate', 'process_kill', 'file_quarantine', 'user_disable'],
    'sudo_autoblock_enabled': True,
}


def _exact_keys(value, allowed, label):
    if not isinstance(value, dict):
        raise ValueError(label + ' must be an object')
    unknown = set(value) - set(allowed)
    missing = set(allowed) - set(value)
    if unknown:
        raise ValueError(label + ' has unknown keys: ' + ','.join(sorted(unknown)))
    if missing:
        raise ValueError(label + ' is missing keys: ' + ','.join(sorted(missing)))


def _boolean(value, label):
    if type(value) is not bool:
        raise ValueError(label + ' must be boolean')
    return value


def feature_keys():
    from .config import DEFAULT
    mirrored = {'eve_path','eve_writer_uid','response_enabled','auto_action_network_enabled',
                'nft_family','nft_table','nft_set','nft_set_v6','frequency_window_seconds',
                'expected_dns_servers','watch_domains','dns_actions','otx_enabled','otx_blocker_mode',
                'otx_pulse_threshold','otx_recent_pulse_days','otx_require_tls',
                'destructive_response_enabled','destructive_allowed_actions','sudo_autoblock_enabled'}
    return set(DEFAULT) - mirrored


def from_legacy(config, revision=1):
    """Translate a validated 0.2.1 config without changing its values.

    Accepts either the strict flat legacy view or the expanded effective view
    produced by :func:`satsuma.policy.effective`; extra effective keys are
    ignored rather than rejected.
    """
    from .config import DEFAULT, validate
    flat={key: config.get(key, default) for key, default in DEFAULT.items()}
    if "schema_version" in config:
        flat["schema_version"]=config["schema_version"]
    current = validate(flat)
    return {
        'schema_version': 1,
        'revision': revision,
        'workers': {
            'suricata_collector': {
                'enabled': True,
                'eve_path': current['eve_path'],
                'writer_uid': current['eve_writer_uid'],
            },
            'dns_monitor': {
                'enabled': True,
                'expected_servers': current['expected_dns_servers'],
                'watch_domains': current['watch_domains'],
                'actions': current['dns_actions'],
            },
            'response': {
                'enabled': current['response_enabled'],
                'nft': {
                    'family': current['nft_family'],
                    'table': current['nft_table'],
                    'ipv4_set': current['nft_set'],
                    'ipv6_set': current['nft_set_v6'],
                },
                'destructive': {
                    'enabled': current['destructive_response_enabled'],
                    'allowed_actions': list(current['destructive_allowed_actions']),
                    'sudo_autoblock_enabled': current['sudo_autoblock_enabled'],
                },
            },
            'otx': {
                'enabled': current['otx_enabled'],
                'blocker_mode': current['otx_blocker_mode'],
                'pulse_threshold': current['otx_pulse_threshold'],
                'recent_pulse_days': current['otx_recent_pulse_days'],
                'require_tls': current['otx_require_tls'],
            },
            'audit': {
                'enabled': True,
                'log_path': '/var/log/audit/audit.log',
            },
            'finding': {
                'enabled': True,
                'correlation_window_seconds': 7 * 86400,
                'audit_candidate_limit': 20,
            },
            'evidence': {
                'enabled': True,
                'archive_budget_bytes': 1024**3,
            },
        },
        'correlation': {
            'frequency_window_seconds': current['frequency_window_seconds'],
        },
        'scheduled_scans': dict(FIXED_SCAN_POLICY),
        'features': {key: current[key] for key in feature_keys()},
    }


def validate(policy):
    """Reject executable/unknown policy data and return normalized policy."""
    # Older 0.2.x policy files are migrated in memory by adding the fixed scan rule.
    if isinstance(policy, dict) and 'scheduled_scans' not in policy:
        policy = dict(policy); policy['scheduled_scans'] = dict(FIXED_SCAN_POLICY)
    policy = dict(policy)
    features = policy.get('features', {})
    if not isinstance(features, dict) or set(features) - feature_keys():
        raise ValueError('Unknown or invalid policy.features')
    policy.setdefault('features', {})
    _exact_keys(policy, ('schema_version', 'revision', 'workers', 'correlation', 'scheduled_scans', 'features'), 'policy')
    if policy['schema_version'] != 1 or type(policy['schema_version']) is not int:
        raise ValueError('unsupported policy schema')
    if type(policy['revision']) is not int or not 1 <= policy['revision'] <= 2**63 - 1:
        raise ValueError('invalid policy revision')
    workers = policy['workers']
    # ``otx`` opsiyoneldir: eski policy dosyalarında yoksa default ile doldurulur.
    if isinstance(workers, dict) and 'otx' not in workers:
        workers = dict(workers); workers['otx'] = dict(DEFAULT_OTX)
    _exact_keys(workers, ('suricata_collector', 'dns_monitor', 'response',
                          'otx', 'audit', 'finding', 'evidence'), 'workers')
    collector = workers['suricata_collector']
    dns = workers['dns_monitor']
    response = workers['response']
    otx = workers['otx']
    audit = workers['audit']
    finding = workers['finding']
    evidence = workers['evidence']
    correlation = policy['correlation']
    scans = policy['scheduled_scans']
    legacy_scans = {**FIXED_SCAN_POLICY, 'order':['clamav','maldet']}
    if scans == legacy_scans:
        scans = dict(FIXED_SCAN_POLICY)
    _exact_keys(scans, tuple(FIXED_SCAN_POLICY), 'scheduled_scans')
    _boolean(scans['enabled'], 'scheduled_scans.enabled')
    if type(scans['interval_seconds']) is not int or not 60 <= scans['interval_seconds'] <= 604800:
        raise ValueError('Invalid scan interval')
    if not isinstance(scans['order'], list) or not scans['order'] or any(tool not in ('clamav','rkhunter','chkrootkit') for tool in scans['order']) or len(set(scans['order'])) != len(scans['order']):
        raise ValueError('Invalid scanner order')
    if scans['overlap'] is not False:
        raise ValueError('Parallel scanning is unsupported')
    _boolean(scans['automatic_quarantine'], 'scheduled_scans.automatic_quarantine')
    _exact_keys(collector, ('enabled', 'eve_path', 'writer_uid'), 'suricata_collector')
    _exact_keys(dns, ('enabled', 'expected_servers', 'watch_domains', 'actions'), 'dns_monitor')
    # ``response.destructive`` opsiyoneldir: eski policy dosyalarında yoksa default ile doldurulur.
    if isinstance(response, dict) and 'destructive' not in response:
        response = dict(response); response['destructive'] = dict(DEFAULT_DESTRUCTIVE)
    _exact_keys(response, ('enabled', 'nft', 'destructive'), 'response')
    _exact_keys(response['nft'], ('family', 'table', 'ipv4_set', 'ipv6_set'), 'response.nft')
    _exact_keys(response['destructive'], ('enabled', 'allowed_actions', 'sudo_autoblock_enabled'), 'response.destructive')
    _exact_keys(otx, ('enabled', 'blocker_mode', 'pulse_threshold', 'recent_pulse_days', 'require_tls'), 'otx')
    _exact_keys(audit, ('enabled', 'log_path'), 'audit')
    _exact_keys(finding, ('enabled', 'correlation_window_seconds',
                          'audit_candidate_limit'), 'finding')
    _exact_keys(evidence, ('enabled', 'archive_budget_bytes'), 'evidence')
    _exact_keys(correlation, ('frequency_window_seconds',), 'correlation')
    _boolean(collector['enabled'], 'suricata_collector.enabled')
    _boolean(dns['enabled'], 'dns_monitor.enabled')
    _boolean(response['enabled'], 'response.enabled')
    _boolean(response['destructive']['enabled'], 'response.destructive.enabled')
    _boolean(response['destructive']['sudo_autoblock_enabled'], 'response.destructive.sudo_autoblock_enabled')
    _boolean(otx['enabled'], 'otx.enabled')
    _boolean(otx['blocker_mode'], 'otx.blocker_mode')
    _boolean(otx['require_tls'], 'otx.require_tls')
    for name,value in (('audit',audit),('finding',finding),('evidence',evidence)):
        _boolean(value['enabled'], name+'.enabled')
    for path,label in ((audit['log_path'],'audit.log_path'),):
        if not isinstance(path,str) or not Path(path).is_absolute() or '..' in Path(path).parts:
            raise ValueError(label+' must be an absolute path without ..')
    limits=(
            ('finding.correlation_window_seconds',finding['correlation_window_seconds'],1,90*86400),
            ('finding.audit_candidate_limit',finding['audit_candidate_limit'],1,1000),
            ('evidence.archive_budget_bytes',evidence['archive_budget_bytes'],1024**2,100*1024**3),
            ('otx.pulse_threshold',otx['pulse_threshold'],1,10000),
            ('otx.recent_pulse_days',otx['recent_pulse_days'],1,365))
    for label,value,minimum,maximum in limits:
        if type(value) is not int or not minimum <= value <= maximum:
            raise ValueError('invalid '+label)
    # Destructive allowed_actions — yalnızca bilinen aksiyonlar.
    from .config import DESTRUCTIVE_ACTIONS
    allowed = response['destructive']['allowed_actions']
    if not isinstance(allowed, list):
        raise ValueError('response.destructive.allowed_actions must be a list')
    unknown_actions = [a for a in allowed if a not in DESTRUCTIVE_ACTIONS]
    if unknown_actions:
        raise ValueError('unknown destructive action(s): ' + ','.join(unknown_actions))
    flat = {
        'eve_path': collector['eve_path'],
        'eve_writer_uid': collector['writer_uid'],
        'response_enabled': response['enabled'],
        'nft_family': response['nft']['family'],
        'nft_table': response['nft']['table'],
        'nft_set': response['nft']['ipv4_set'],
        'nft_set_v6': response['nft']['ipv6_set'],
        'frequency_window_seconds': correlation['frequency_window_seconds'],
        'expected_dns_servers': dns['expected_servers'],
        'watch_domains': dns['watch_domains'],
        'dns_actions': dns['actions'],
        'otx_enabled': otx['enabled'],
        'otx_blocker_mode': otx['blocker_mode'],
        'otx_pulse_threshold': otx['pulse_threshold'],
        'otx_recent_pulse_days': otx['recent_pulse_days'],
        'otx_require_tls': otx['require_tls'],
        'destructive_response_enabled': response['destructive']['enabled'],
        'destructive_allowed_actions': list(allowed),
        'sudo_autoblock_enabled': response['destructive']['sudo_autoblock_enabled'],
    }
    from .config import validate as validate_config
    flat.update(features)
    normalized = from_legacy(validate_config(flat), policy['revision'])
    normalized['workers']['suricata_collector']['enabled'] = collector['enabled']
    normalized['workers']['dns_monitor']['enabled'] = dns['enabled']
    normalized['scheduled_scans'] = dict(scans)
    for name in ('audit','finding','evidence'):
        normalized['workers'][name] = dict(workers[name])
    return normalized


def effective(policy):
    policy = validate(policy)
    workers = policy['workers']
    nft = workers['response']['nft']
    return {
        **policy['features'],
        'eve_path': workers['suricata_collector']['eve_path'],
        'eve_writer_uid': workers['suricata_collector']['writer_uid'],
        'response_enabled': workers['response']['enabled'],
        'auto_action_network_enabled': bool(workers['response']['enabled'] and workers['response']['destructive']['enabled']
            and 'network_isolate' in workers['response']['destructive']['allowed_actions']),
        'nft_family': nft['family'],
        'nft_table': nft['table'],
        'nft_set': nft['ipv4_set'],
        'nft_set_v6': nft['ipv6_set'],
        'frequency_window_seconds': policy['correlation']['frequency_window_seconds'],
        'expected_dns_servers': workers['dns_monitor']['expected_servers'],
        'watch_domains': workers['dns_monitor']['watch_domains'],
        'dns_actions': workers['dns_monitor']['actions'],
        'otx_enabled': workers['otx']['enabled'],
        'otx_blocker_mode': workers['otx']['blocker_mode'],
        'otx_pulse_threshold': workers['otx']['pulse_threshold'],
        'otx_recent_pulse_days': workers['otx']['recent_pulse_days'],
        'otx_require_tls': workers['otx']['require_tls'],
        'destructive_response_enabled': workers['response']['destructive']['enabled'],
        'destructive_allowed_actions': list(workers['response']['destructive']['allowed_actions']),
        'sudo_autoblock_enabled': workers['response']['destructive']['sudo_autoblock_enabled'],
        'suricata_collector_enabled': workers['suricata_collector']['enabled'],
        'dns_monitor_enabled': workers['dns_monitor']['enabled'],
        'audit_enabled': workers['audit']['enabled'],
        'audit_log_path': workers['audit']['log_path'],
        'finding_enabled': workers['finding']['enabled'],
        'correlation_window_seconds': workers['finding']['correlation_window_seconds'],
        'audit_candidate_limit': workers['finding']['audit_candidate_limit'],
        'evidence_enabled': workers['evidence']['enabled'],
        'archive_budget_bytes': workers['evidence']['archive_budget_bytes'],
        'scheduled_scans': dict(policy['scheduled_scans']),
    }


def digest(policy):
    encoded = json.dumps(validate(policy), ensure_ascii=False, sort_keys=True,
                         separators=(',', ':')).encode('utf-8')
    return hashlib.sha256(encoded).hexdigest()


def _read_secure(path):
    path = Path(path)
    if not path.is_absolute() or '..' in path.parts:
        raise ValueError('absolute policy path required')
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
    try:
        info = os.fstat(fd)
        if not stat.S_ISREG(info.st_mode) or info.st_uid != 0 or info.st_nlink != 1:
            raise PermissionError('policy must be a root-owned regular file')
        if info.st_mode & 0o022:
            raise PermissionError('policy must not be writable by group or others')
        with os.fdopen(os.dup(fd), encoding='utf-8') as stream:
            return json.load(stream)
    finally:
        os.close(fd)


def load(path=POLICY_PATH):
    policy = validate(_read_secure(path))
    meta = {'schema_version': policy['schema_version'], 'revision': policy['revision'],
            'sha256': digest(policy), 'path': str(path), 'status': 'validated'}
    return policy, effective(policy), meta


def write_atomic(policy, path=POLICY_PATH):
    """Create the first policy atomically; never overwrite an existing policy."""
    policy = validate(policy)
    path = Path(path)
    path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    parent = path.parent.lstat()
    if not stat.S_ISDIR(parent.st_mode) or parent.st_uid != 0 or parent.st_mode & 0o022:
        raise PermissionError('policy directory must be root protected')
    if path.exists() or path.is_symlink():
        raise FileExistsError(str(path))
    fd, temporary = tempfile.mkstemp(prefix='.policy-', dir=path.parent)
    try:
        os.fchmod(fd, 0o600)
        with os.fdopen(fd, 'w', encoding='utf-8') as stream:
            json.dump(policy, stream, ensure_ascii=False, indent=2)
            stream.write('\n');stream.flush();os.fsync(stream.fileno())
        os.replace(temporary, path)
        directory = os.open(path.parent, os.O_RDONLY | os.O_DIRECTORY)
        try:os.fsync(directory)
        finally:os.close(directory)
    finally:
        try:os.unlink(temporary)
        except FileNotFoundError:pass
    return policy
