"""Authenticated review queue; approval, signature and publication are distinct.

Only OperatorController calls mutation functions. Reader/list functions do no
DDL and never commit. Legacy queue rows and their decisions remain untouched.
"""
from __future__ import annotations
import json
import os
import shutil
import sqlite3
import stat
import tempfile
import time
from pathlib import Path
import yaml
from . import ai_rule_package as pkg
from . import rule_signing
from .deepseek_client import DeepSeekError, generate_rule, is_available

DEFAULT_OUTPUT_DIR = Path('/var/lib/satsuma-core/generated_rules')
ACTIVE_RULES_DIR = rule_signing.MANAGED_RULES_DIR
SAFE_ADAPTER_ACTIONS = pkg.SAFE_ACTIONS
_transport_schema = json.loads(pkg.SCHEMA_PATH.read_text())
_transport_schema['properties']['response_proposal']['required'].remove('detection_sha256')
SCHEMA_HINT = json.dumps(_transport_schema)


def _sanitize_rule(rule):
    """Compatibility name: retain exact data, never invent matchers or strip risks."""
    return json.loads(pkg.canonical(rule))


def validate_generated_rule(rule):
    return pkg.validate_detection(rule)


def _ensure_queue(store):
    store.db.execute('''CREATE TABLE IF NOT EXISTS rule_adapter_queue (
        rule_id TEXT PRIMARY KEY, rule_yaml TEXT, source TEXT, technique TEXT,
        status TEXT DEFAULT 'pending', created_at REAL, reviewed_at REAL, reviewer TEXT)''')
    existing = {r[1] for r in store.db.execute('PRAGMA table_info(rule_adapter_queue)')}
    columns = {'package_json': 'TEXT', 'content_hash': 'TEXT', 'test_report': 'TEXT',
               'approved_payload': 'TEXT', 'signature': 'TEXT', 'signature_fingerprint': 'TEXT',
               'last_error': 'TEXT', 'activation': 'TEXT', 'revision': 'INTEGER DEFAULT 0'}
    for name, kind in columns.items():
        if name not in existing:
            store.db.execute('ALTER TABLE rule_adapter_queue ADD COLUMN ' + name + ' ' + kind)
    store.db.execute('''CREATE TABLE IF NOT EXISTS rule_adapter_history (
        id INTEGER PRIMARY KEY, rule_id TEXT, operation TEXT, old_status TEXT,
        new_status TEXT, actor TEXT, created REAL, content_hash TEXT, reason TEXT)''')
    store.db.commit()


def list_pending(store):
    """Read-only compatibility path, including on an unmigrated database."""
    if not store.db.execute("SELECT 1 FROM sqlite_master WHERE type='table' AND name='rule_adapter_queue'").fetchone():
        return []
    rows = store.db.execute("SELECT rule_id,source,technique,created_at,status FROM rule_adapter_queue "
                            "WHERE status IN ('pending','pending_review') ORDER BY created_at DESC,rule_id").fetchall()
    return [dict(zip(('rule_id', 'source', 'technique', 'created_at', 'status'), row)) for row in rows]


def list_rules(store):
    if not store.db.execute("SELECT 1 FROM sqlite_master WHERE type='table' AND name='rule_adapter_queue'").fetchone():
        return []
    columns = {r[1] for r in store.db.execute('PRAGMA table_info(rule_adapter_queue)')}
    names = ['rule_id', 'source', 'technique', 'status', 'created_at', 'reviewed_at', 'reviewer']
    names += [n for n in ('content_hash','test_report','last_error','activation','signature_fingerprint','revision') if n in columns]
    # Rejected rules leave the working list; their history stays in rule_adapter_history.
    return [dict(zip(names, r)) for r in store.db.execute('SELECT ' + ','.join(names) +
        " FROM rule_adapter_queue WHERE status!='rejected' ORDER BY created_at DESC,rule_id LIMIT 200")]


def _authorized(authorized):
    if authorized is not True:
        raise PermissionError('operator_session_required')


def _history(store, rule_id, operation, old, new, actor, digest, reason=None):
    store.db.execute('INSERT INTO rule_adapter_history(rule_id,operation,old_status,new_status,actor,created,content_hash,reason) VALUES(?,?,?,?,?,?,?,?)',
                     (rule_id, operation, old, new, str(actor), time.time(), digest, reason))


def _row(store, rule_id):
    cursor = store.db.execute('SELECT * FROM rule_adapter_queue WHERE rule_id=?', (rule_id,))
    row = cursor.fetchone()
    if not row:
        raise ValueError('rule_not_found')
    return dict(zip([c[0] for c in cursor.description], row))


def _checked_package(row):
    if not row.get('package_json'):
        raise ValueError('legacy_rule_requires_explicit_resubmission_with_new_id')
    package = json.loads(row['package_json'])
    errors = pkg.validate_package(package)
    if errors or pkg.digest(package) != row['content_hash'] or package['rule_id'] != row['rule_id']:
        raise ValueError('package_changed_or_invalid')
    return package


def _taken_rule_ids(store):
    """rule_id -> detection hash for active engine rules and queued (non-rejected) rules."""
    from .smart_rules import SmartRuleEngine
    taken = {r['_id']: r.get('_content_hash') for r in SmartRuleEngine().rules}
    try:
        for rule_id, package_json in store.db.execute(
                "SELECT rule_id,package_json FROM rule_adapter_queue WHERE status!='rejected'"):
            try:
                taken.setdefault(rule_id, pkg.digest(json.loads(package_json)['detection']))
            except (TypeError, ValueError, KeyError):
                taken.setdefault(rule_id, None)
    except sqlite3.Error:
        pass
    return taken


def give_unique_rule_id(store, package):
    """Models reuse one id per topic; a new rule under a taken id gets a content-derived suffix.

    Returns (package, note). An identical detection that is already present is not renamed.
    Model aynı konuya hep aynı kimliği verir; dolu kimlikteki yeni kurala içerikten türetilen ek verilir.
    """
    if not isinstance(package, dict) or not isinstance(package.get('detection'), dict):
        return package, None
    taken = _taken_rule_ids(store)
    rule_id = package.get('rule_id')
    if rule_id not in taken:
        return package, None
    detection_hash = pkg.digest(package['detection'])
    if taken[rule_id] == detection_hash:
        return package, 'identical_rule_already_present'
    base = str(rule_id)[:72]
    for length in (6, 8, 12):
        candidate = f'{base}-{detection_hash[:length].upper()}'
        if candidate not in taken and pkg.AI_ID.fullmatch(candidate):
            break
    else:
        return package, None
    package['rule_id'] = candidate
    package['detection']['id'] = candidate
    if isinstance(package.get('response_proposal'), dict):
        package['response_proposal']['rule_id'] = candidate
        package['response_proposal'].pop('detection_sha256', None)
    pkg.bind_detection_digest(package)
    return package, 'renamed_from:' + str(rule_id)


def queue_package(store, package, *, authorized=False, reviewer='operator'):
    _authorized(authorized)
    _ensure_queue(store)
    package, note = give_unique_rule_id(store, package)
    if note == 'identical_rule_already_present':
        return {'queued': False, 'error': 'identical_rule_already_present'}
    errors = pkg.validate_package(package)
    if errors:
        return {'queued': False, 'errors': errors, 'status': 'validation_failed'}
    tests = pkg.test_package(package)
    if not tests['passed']:
        return {'queued': False, 'status': 'validation_failed', 'test_report': tests}
    from .smart_rules import SmartRuleEngine
    if package['rule_id'] in {r['_id'] for r in SmartRuleEngine().rules}:
        return {'queued': False, 'error': 'active_rule_id_collision'}
    _ensure_queue(store)
    try:
        with store.db:
            store.db.execute('INSERT INTO rule_adapter_queue(rule_id,rule_yaml,source,technique,status,created_at,package_json,content_hash,test_report) VALUES(?,?,?,?,?,?,?,?,?)',
                (package['rule_id'], yaml.safe_dump([package['detection']], allow_unicode=True), 'deepseek',
                 package['detection'].get('mitre', {}).get('technique'), 'pending_review', time.time(),
                 pkg.canonical(package).decode(), pkg.digest(package), json.dumps(tests)))
            _history(store, package['rule_id'], 'submit_validated_tested', 'generated', 'pending_review', reviewer, pkg.digest(package))
    except sqlite3.IntegrityError:
        # A rejected rule may come back with the same id (models reuse ids for the
        # same technique). Its history row stays; only a rejected row is replaced.
        # Reddedilen kural aynı kimlikle gelebilir; geçmiş kalır, yalnızca reddedilen kayıt değişir.
        with store.db:
            store.db.execute('BEGIN IMMEDIATE')
            row = store.db.execute('SELECT status FROM rule_adapter_queue WHERE rule_id=?', (package['rule_id'],)).fetchone()
            if not row or row[0] != 'rejected':
                return {'queued': False, 'error': 'duplicate_rule_id_history_preserved'}
            store.db.execute("UPDATE rule_adapter_queue SET rule_yaml=?,technique=?,status='pending_review',created_at=?,"
                             "reviewed_at=NULL,reviewer=NULL,package_json=?,content_hash=?,test_report=?,approved_payload=NULL,"
                             "signature=NULL,signature_fingerprint=NULL,last_error=NULL,activation=NULL,revision=revision+1 "
                             "WHERE rule_id=? AND status='rejected'",
                             (yaml.safe_dump([package['detection']], allow_unicode=True),
                              package['detection'].get('mitre', {}).get('technique'), time.time(),
                              pkg.canonical(package).decode(), pkg.digest(package), json.dumps(tests), package['rule_id']))
            _history(store, package['rule_id'], 'resubmit_after_reject', 'rejected', 'pending_review', reviewer, pkg.digest(package))
    result = {'queued': True, 'rule_id': package['rule_id'], 'status': 'pending_review', 'content_hash': pkg.digest(package)}
    if note:
        result.update(renamed=note, package=package)
    return result


def queue_rule(store, rule, source='deepseek', **kwargs):
    # Legacy API must not bypass the joint response schema or operator channel.
    if not isinstance(rule, dict) or 'detection' not in rule:
        return {'queued': False, 'errors': ['signed_joint_package_required']}
    return queue_package(store, rule, **kwargs)


def approve_rule(store, rule_id, output_dir=None, reviewer='operator', *, authorized=False):
    _authorized(authorized);_ensure_queue(store)
    try:
        store.db.execute('BEGIN IMMEDIATE')
        row = _row(store, rule_id)
        if row['status'] != 'pending_review':
            raise ValueError('invalid_state_transition')
        package = _checked_package(row)
        tests = pkg.test_package(package)
        if not tests['passed']:
            raise ValueError('functional_tests_failed')
        # The operator approval itself is signed together with the entire package.
        approval = {'operator_uid': int(reviewer), 'reviewed_at': time.time(), 'package_sha256': row['content_hash']}
        payload = pkg.canonical({'package': package, 'approval': approval}).decode()
        store.db.execute("UPDATE rule_adapter_queue SET status='approved_for_signing',reviewed_at=?,reviewer=?,approved_payload=?,revision=revision+1 WHERE rule_id=? AND status='pending_review'",
                         (approval['reviewed_at'], str(reviewer), payload, rule_id))
        _history(store, rule_id, 'approve', row['status'], 'approved_for_signing', reviewer, row['content_hash'])
        # 2.2.20: the authenticated approval is sealed locally, so no GPG step is
        # required. Without the local key the GPG path stays available.
        status = 'approved_for_signing'
        try:
            seal = rule_signing.seal_payload(payload.encode())
        except (OSError, ValueError):
            seal = None
        if seal is not None:
            store.db.execute("UPDATE rule_adapter_queue SET status='signed',signature=?,signature_fingerprint=?,last_error=NULL,revision=revision+1 WHERE rule_id=?",
                             (seal, 'satsuma-local-seal', rule_id))
            _history(store, rule_id, 'seal', 'approved_for_signing', 'signed', reviewer, row['content_hash'])
            status = 'signed'
        store.db.commit()
        return {'approved': True, 'activated': False, 'status': status, 'sealed': seal is not None, 'rule_id': rule_id,
                'signing_payload': payload, 'content_hash': row['content_hash']}
    except Exception:
        store.db.rollback()
        raise


def reject_rule(store, rule_id, reviewer='operator', *, authorized=False, reason=''):
    _authorized(authorized)
    if not isinstance(reason, str) or not 3 <= len(reason.strip()) <= 500:
        raise ValueError('rejection_reason_required')
    _ensure_queue(store)
    with store.db:
        store.db.execute('BEGIN IMMEDIATE')
        row = _row(store, rule_id)
        if row['status'] not in ('pending', 'pending_review', 'approved_for_signing', 'signing_failed'):
            raise ValueError('invalid_state_transition')
        store.db.execute("UPDATE rule_adapter_queue SET status='rejected',reviewed_at=?,reviewer=?,last_error=?,revision=revision+1 WHERE rule_id=?",
                         (time.time(), str(reviewer), 'operator_rejected', rule_id))
        _history(store, rule_id, 'reject', row['status'], 'rejected', reviewer, row.get('content_hash'), reason)
    return {'rejected': True, 'rule_id': rule_id, 'status': 'rejected'}


def verify_rule_signature(store, rule_id, signature=None, *, authorized=False, reviewer='operator'):
    _authorized(authorized);_ensure_queue(store)
    with store.db:
        store.db.execute('BEGIN IMMEDIATE')
        row = _row(store, rule_id); package = _checked_package(row)
        if row['status'] not in ('approved_for_signing', 'signing_failed', 'signed', 'activation_failed', 'activated'):
            raise ValueError('approval_required_before_signature')
        payload = row.get('approved_payload')
        if not payload or json.loads(payload)['package'] != package:
            raise ValueError('approved_content_changed')
        signature = signature if signature is not None else row.get('signature')
        result = rule_signing.verify_payload(payload.encode(), signature)
        if row['status']=='activated':
            _history(store, rule_id, 'verify_activated_signature', 'activated', 'activated', reviewer, row['content_hash'], result.get('error'))
            return {**result,'status':'activated','rule_id':rule_id,'activated':True}
        status = 'signed' if result['valid'] else 'signing_failed'
        store.db.execute('UPDATE rule_adapter_queue SET status=?,signature=?,signature_fingerprint=?,last_error=?,revision=revision+1 WHERE rule_id=?',
            (status, signature if result['valid'] else None, result.get('fingerprint'), result.get('error'), rule_id))
        _history(store, rule_id, 'verify_signature', row['status'], status, reviewer, row['content_hash'], result.get('error'))
    return {**result, 'status': status, 'rule_id': rule_id, 'activated': False}


def _secure_directory(path):
    path = Path(path).absolute()
    if path.resolve() != path:
        raise ValueError('symlink_directory_refused')
    path.mkdir(mode=0o700, parents=True, exist_ok=True)
    st = path.stat()
    if st.st_uid != rule_signing.TRUSTED_OWNER or st.st_mode & 0o022 or not stat.S_ISDIR(st.st_mode):
        raise ValueError('untrusted_directory')
    return path


def activate_rule(store, rule_id, *, authorized=False, reviewer='operator'):
    _authorized(authorized);_ensure_queue(store)
    published = None; staging = None
    try:
        store.db.execute('BEGIN IMMEDIATE')
        row = _row(store, rule_id)
        if row['status'] not in ('signed', 'activation_failed'):
            raise ValueError('signed_state_required')
        package = _checked_package(row)
        if json.loads(row['approved_payload'])['package'] != package:
            raise ValueError('approved_content_changed')
        verified = rule_signing.verify_payload(row['approved_payload'].encode(), row['signature'])
        if not verified['valid'] or not pkg.test_package(package)['passed']:
            raise ValueError('signature_or_functional_validation_failed')
        if not pkg.AI_ID.fullmatch(rule_id):
            raise ValueError('unsafe_rule_id')
        root = _secure_directory(ACTIVE_RULES_DIR)
        target = root / rule_id
        if os.path.lexists(target):
            raise ValueError('activation_target_exists')
        staging = Path(tempfile.mkdtemp(prefix='.staging-', dir=root))
        for name, data in (('rule.yaml', yaml.safe_dump([package['detection']], allow_unicode=True).encode()),
                           ('package.json', row['approved_payload'].encode()), ('signature.asc', row['signature'].encode())):
            fd = os.open(staging / name, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
            with os.fdopen(fd, 'wb') as stream:
                stream.write(data);stream.flush();os.fsync(stream.fileno())
        from .smart_rules import SmartRuleEngine
        engine = SmartRuleEngine(staging)
        if engine.load_errors or [r['_id'] for r in engine.rules] != [rule_id]:
            raise ValueError('actual_loader_rejected_package')
        fd = os.open(staging, os.O_RDONLY | os.O_DIRECTORY);os.fsync(fd);os.close(fd)
        os.rename(staging, target);staging = None;published = target
        fd = os.open(root, os.O_RDONLY | os.O_DIRECTORY);os.fsync(fd);os.close(fd)
        activation = {'file_written': True, 'loader_verified': True, 'runtime_loaded': False,
                      'runtime_state': 'awaiting_brain_acknowledgement', 'path': str(target), 'content_hash': row['content_hash']}
        store.db.execute("UPDATE rule_adapter_queue SET status='activated',activation=?,last_error=NULL,revision=revision+1 WHERE rule_id=?", (json.dumps(activation), rule_id))
        _history(store, rule_id, 'activate', row['status'], 'activated', reviewer, row['content_hash'])
        store.db.commit()
        return {'activated': True, 'rule_id': rule_id, 'status': 'activated', **activation}
    except Exception as exc:
        store.db.rollback()
        if published is not None:
            shutil.rmtree(published)
        if staging is not None:
            shutil.rmtree(staging)
        # Record failures only for a previously signed candidate, never mutate
        # rejected/legacy records merely because somebody retries activation.
        with store.db:
            current = _row(store, rule_id)
            if current['status'] in ('signed','activation_failed'):
                store.db.execute("UPDATE rule_adapter_queue SET status='activation_failed',last_error=?,revision=revision+1 WHERE rule_id=?", ('activation_preconditions_or_publication_failed', rule_id))
                _history(store, rule_id, 'activate', current['status'], 'activation_failed', reviewer, current.get('content_hash'), 'activation_preconditions_or_publication_failed')
        return {'activated': False, 'rule_id': rule_id, 'error': 'activation_preconditions_or_publication_failed'}


def activation_status(store, rule_id):
    row = _row(store, rule_id)
    status = json.loads(row.get('activation') or '{}')
    status['published_file_present']=False
    status['installed_integrity_valid']=False
    try:
        path=ACTIVE_RULES_DIR/rule_id/'rule.yaml'
        installed=yaml.safe_load(rule_signing.read_regular(path,65536))
        rule_signing.verify_installed_rule(path,installed)
        status['published_file_present']=True
        status['installed_integrity_valid']=True
    except Exception:
        pass
    runtime = store.get('deepseek_runtime', {}) or {}
    fresh = 0 <= time.time() - runtime.get('updated_at', 0) <= 60
    status['runtime_loaded'] = bool(fresh and runtime.get('loaded', {}).get(rule_id) == row.get('content_hash'))
    return {'rule_id': rule_id, 'status': row['status'], 'intervention_executed': False,
            'runtime_data_state': 'CURRENT' if fresh else 'UNKNOWN', **status}


def research_and_generate(store, technique, attack_type, config, *, confirmed=False):
    if config.get('rule_adapter_enabled') is not True:
        return {'enabled': False, 'error': 'rule_adapter_disabled'}
    raw = generate_rule(technique, attack_type, SCHEMA_HINT, config, confirmed=confirmed)
    completed = []
    _ensure_queue(store)
    if isinstance(raw, dict) and isinstance(raw.get('detection'), dict) and 'response_proposal' not in raw:
        raw['response_proposal'] = pkg.observe_only_proposal(raw)
        completed.append('response_proposal_missing_observe_only_added')
    # A model cannot reliably hash canonical bytes. Only this mechanical
    # binding may be supplied locally; no semantic match/action is repaired.
    pkg.bind_detection_digest(raw)
    raw, note = give_unique_rule_id(store, raw)
    if note:
        completed.append(note)
    errors = pkg.validate_package(raw)
    return {'enabled': True, 'generated_by': 'deepseek', 'package': raw, 'errors': errors, 'completed_locally': completed,
            'status': 'validation_failed' if errors else 'generated', 'queued': False}
