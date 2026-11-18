"""Typed DeepSeek operations, reachable only after Operator IPC authorization."""
import hashlib
import json
import re
import sqlite3
import time
from . import ai_rule_package as pkg, deepseek_client as client, rule_adapter as adapter

METHODS = {'deepseek_status','deepseek_test_connection','deepseek_research','deepseek_generate',
           'deepseek_validate_detection','deepseek_validate_response','deepseek_validate_identity',
           'deepseek_test_rule','deepseek_evaluate_response','deepseek_submit','deepseek_list',
           'deepseek_approve','deepseek_reject','deepseek_verify_signature','deepseek_activate',
           'deepseek_activation_status','deepseek_export'}
NETWORK_METHODS = {'deepseek_test_connection','deepseek_research','deepseek_generate'}


SPACING_SECONDS = 3


def _limit(config):
    value = (config or {}).get('deepseek_requests_per_hour', 60)
    return value if type(value) is int and 1 <= value <= 600 else 60


def _recent_network_requests(store):
    """(count, newest) of API requests in the last hour that succeeded or are still running.

    A request that failed (no DNS, timeout, rejected key) does not use up the hour.
    Başarısız istek (DNS yok, zaman aşımı, reddedilen anahtar) saatlik hakkı tüketmez.
    """
    try:
        # A generation may send a second, corrected request (2.2.47); it counts too.
        return store.db.execute("SELECT coalesce(sum(coalesce(json_extract(result,'$.api_requests'),1)),0),max(created) "
                                "FROM deepseek_requests WHERE method IN "
                                "('deepseek_test_connection','deepseek_research','deepseek_generate') AND created>? "
                                "AND (result IS NULL OR json_extract(result,'$.ok')=1)",
                                (time.time()-3600,)).fetchone()
    except sqlite3.Error:
        return (0, None)


def _code(exc):
    """A short machine code from our own exceptions; anything else stays generic."""
    text = str(exc)
    return text if re.fullmatch(r'[a-z][a-z0-9_]{2,80}', text) else 'operation_preconditions_failed'


def _perform(store, uid, method, params, config):
    package = params.get('package')
    # The approval envelope from tab 3 ({"approval", "package"}) is unwrapped to its package.
    if isinstance(package, dict) and set(package) == {'approval', 'package'} and isinstance(package['package'], dict):
        package = params['package'] = package['package']
    package = pkg.bind_detection_digest(package)
    rule_id = params.get('rule_id')
    if method == 'deepseek_status':
        recent = _recent_network_requests(store)
        return {'ok': True, 'key_available': client.is_available(), 'key_problem': client.key_problem(),
                'network_requests_last_hour': recent[0], 'network_requests_left_this_hour': max(0, _limit(config) - recent[0]),
                'network_requests_per_hour': _limit(config),
                'enabled': config.get('deepseek_enabled') is True,
                'network_request_sent': False, 'signing': 'external_operator_gpg',
                'supported_sources': ['sys_proc','memory'], 'api_verified': False}
    if method == 'deepseek_list':
        return {'ok': True, 'items': adapter.list_rules(store)}
    if method == 'deepseek_activation_status':
        return {'ok': True, **adapter.activation_status(store, rule_id)}
    if method == 'deepseek_export':
        row = adapter._row(store, rule_id)
        adapter._checked_package(row)
        if row['status'] not in ('approved_for_signing','signing_failed','signed','activation_failed','activated'):
            raise ValueError('approval_required')
        return {'ok': True, 'signing_payload': row['approved_payload'], 'content_hash': row['content_hash']}
    if method in NETWORK_METHODS:
        if params.get('confirmed') is not True:
            raise ValueError('explicit_network_consent_required')
        if method == 'deepseek_test_connection':
            return {'ok': True, **client.connection_test(config, confirmed=True)}
        return {'ok': True, **adapter.research_and_generate(store, params.get('technique'),
                    params.get('attack_type'), config, confirmed=True)}
    if method == 'deepseek_validate_detection':
        errors = pkg.validate_detection(package.get('detection') if isinstance(package, dict) else None)
        return {'ok': not errors, 'errors': errors, 'stage': 'detection_schema'}
    if method in ('deepseek_validate_response','deepseek_validate_identity'):
        errors = pkg.validate_package(package)
        return {'ok': not errors, 'errors': errors, 'stage': method.removeprefix('deepseek_validate_')}
    if method == 'deepseek_test_rule':
        report = pkg.test_package(package)
        return {'ok': report['passed'], 'test_report': report}
    if method == 'deepseek_evaluate_response':
        return {'ok': True, 'evaluation': pkg.evaluate_response(package)}
    if method == 'deepseek_submit':
        return adapter.queue_package(store, package, authorized=True, reviewer=uid)
    if method == 'deepseek_approve':
        return adapter.approve_rule(store, rule_id, authorized=True, reviewer=uid)
    if method == 'deepseek_reject':
        return adapter.reject_rule(store, rule_id, authorized=True, reviewer=uid, reason=params.get('reason',''))
    if method == 'deepseek_verify_signature':
        return adapter.verify_rule_signature(store, rule_id, params.get('signature'), authorized=True, reviewer=uid)
    if method == 'deepseek_activate':
        if params.get('confirmed') is not True:
            raise ValueError('explicit_activation_consent_required')
        return adapter.activate_rule(store, rule_id, authorized=True, reviewer=uid)
    raise ValueError('unsupported_deepseek_operation')


def dispatch(store, uid, method, params, config):
    if method not in METHODS:
        raise ValueError('unsupported_deepseek_operation')
    # Read/status/validation operations have no mutation or network side effects.
    readonly = {'deepseek_status','deepseek_list','deepseek_export','deepseek_activation_status',
                'deepseek_validate_detection','deepseek_validate_response','deepseek_validate_identity',
                'deepseek_test_rule','deepseek_evaluate_response'}
    if method in readonly:
        return _perform(store, uid, method, params, config)
    ident = params.get('request_id')
    if not isinstance(ident, str) or not re.fullmatch(r'[a-f0-9]{32}', ident):
        raise ValueError('request_id_required')
    safe_params = {k:v for k,v in params.items() if k not in ('token','password','request_id')}
    request_hash = pkg.digest({'method': method, 'params': safe_params})
    store.db.execute('''CREATE TABLE IF NOT EXISTS deepseek_requests (
        uid INTEGER, request_id TEXT, request_hash TEXT, method TEXT, created REAL,
        result TEXT, PRIMARY KEY(uid,request_id))''')
    store.db.commit()
    with store.db:
        store.db.execute('BEGIN IMMEDIATE')
        existing = store.db.execute('SELECT request_hash,result FROM deepseek_requests WHERE uid=? AND request_id=?', (uid, ident)).fetchone()
        if existing:
            if existing[0] != request_hash:
                raise ValueError('request_id_content_mismatch')
            return json.loads(existing[1]) if existing[1] else {'ok': False, 'status': 'running_or_interrupted_do_not_resubmit'}
        if method in NETWORK_METHODS:
            if params.get('confirmed') is not True:
                raise ValueError('explicit_network_consent_required')
            recent = _recent_network_requests(store)
            if recent[0] >= _limit(config) or (recent[1] is not None and time.time()-recent[1] < SPACING_SECONDS):
                raise ValueError('api_rate_limit_reached')
        store.db.execute('INSERT INTO deepseek_requests VALUES(?,?,?,?,?,NULL)', (uid,ident,request_hash,method,time.time()))
    try:
        result = _perform(store, uid, method, params, config)
        result.setdefault('ok', bool(result.get('queued') or result.get('approved') or result.get('rejected') or result.get('valid') or result.get('activated')))
    except client.DeepSeekError as exc:
        result = {'ok': False, 'error': str(exc)}
    except (ValueError, sqlite3.Error, OSError, TypeError, KeyError) as exc:
        result = {'ok': False, 'error': _code(exc), 'operation': method}
    with store.db:
        store.db.execute('UPDATE deepseek_requests SET result=? WHERE uid=? AND request_id=?', (json.dumps(result),uid,ident))
    store.add('actions', {'action': 'operator.' + method, 'operator_uid': uid,
                         'request_id': ident, 'rule_id': rule_id_from(params, result),
                         'status': 'completed' if result.get('ok') else 'failed',
                         'error': result.get('error'), 'content_hash': result.get('content_hash')})
    return result


def rule_id_from(params, result):
    return params.get('rule_id') or result.get('rule_id') or (params.get('package') or {}).get('rule_id')
