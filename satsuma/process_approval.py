"""Opt-in, fail-closed interactive process response for lab evaluation.

Only process termination is routed here.  This does not intercept kernel
fanotify permission events, network firewall decisions, or memory reads.
No password or authentication token is stored with a pending request.
"""
import copy
import json
import secrets
import threading
import time

_KEY = 'process_approval_requests'
_LOCK = threading.RLock()
TTL = 120
MAX_PENDING = 64



# Production uses SQLite rows, not read-modify-write state lists.  UPDATE
# ... WHERE state='pending' makes two separate service processes unable to
# consume one request twice, and avoids lost concurrent enqueues.
def _sql_db(store):
    # Installed with the existing Store schema.  Never commit an unrelated
    # caller's open transaction merely to check that the table exists.
    return store.db


def _sql_pending(store, now):
    db = _sql_db(store)
    rows = db.execute("SELECT payload FROM process_approvals WHERE state='pending' "
                      "AND created<=? AND expires>=? ORDER BY created, id LIMIT ?",
                      (now, now, MAX_PENDING)).fetchall()
    return [json.loads(row[0]) for row in rows]


def _sql_enqueue(store, finding, now, pid, start):
    db = _sql_db(store)
    request = {
        'id': secrets.token_hex(16), 'state': 'pending', 'created_at': now,
        'expires_at': now + TTL, 'pid': pid, 'starttime': str(start[0]),
        'rule_id': str(finding.get('rule_id') or '')[:120],
        'finding_id': str(finding.get('finding_id') or '')[:200],
        'engine': str(finding.get('team') or finding.get('source') or 'unknown')[:70],
        'finding': copy.deepcopy(finding),
    }
    serialized = json.dumps(request, ensure_ascii=True, allow_nan=False)
    if len(serialized) > 32768:
        return {'status': 'approval_evidence_too_large', 'signal_sent': False}
    with _LOCK:
        db.execute('BEGIN IMMEDIATE')
        try:
            db.execute("DELETE FROM process_approvals WHERE expires<? AND state='pending'", (now,))
            count = db.execute("SELECT COUNT(*) FROM process_approvals WHERE state='pending'").fetchone()[0]
            if count >= MAX_PENDING:
                db.rollback()
                return {'status': 'approval_queue_full', 'signal_sent': False}
            db.execute('INSERT INTO process_approvals VALUES (?,?,?,?,?)',
                       (request['id'], now, now+TTL, 'pending', serialized))
            db.commit()
        except BaseException:
            db.rollback()
            raise
    store.add('actions', {'timestamp': now, 'action': 'process.approval',
                          'status': 'approval_pending', 'request_id': request['id'],
                          'pid': pid, 'rule_id': request['rule_id'], 'signal_sent': False})
    return {'status': 'approval_pending', 'request_id': request['id'],
            'expires_at': now+TTL, 'signal_sent': False}


def _sql_decide(store, request_id, decision, uid, process_handler, now):
    db = _sql_db(store)
    # The claim must be committed BEFORE invoking the privileged executor.
    with _LOCK:
        db.execute('BEGIN IMMEDIATE')
        try:
            row = db.execute('SELECT payload,state,expires FROM process_approvals WHERE id=?',
                             (request_id,)).fetchone()
            if row is None or row[1] != 'pending':
                raise ValueError('Request not pending (missing or already processed)')
            if row[2] < now or json.loads(row[0])['created_at'] > now:
                db.execute("UPDATE process_approvals SET state='expired', payload='{}' WHERE id=?",(request_id,))
                db.commit()
                raise ValueError('Approval request expired; new detection required')
            request = json.loads(row[0])
            target_state = 'processing' if decision == 'apply' else 'rejected'
            changed = db.execute("UPDATE process_approvals SET state=?, payload='{}' "
                                 "WHERE id=? AND state='pending'", (target_state, request_id)).rowcount
            if changed != 1:
                raise ValueError('Request already consumed')
            db.commit()
        except BaseException:
            if db.in_transaction:
                db.rollback()
            raise
    result = {'ok': True, 'status': 'rejected', 'request_id': request_id,
              'signal_sent': False, 'operator_uid': uid}
    if decision == 'apply':
        if process_handler is None:
            result.update(ok=False, status='no_authenticated_executor')
        else:
            try:
                outcome = process_handler(copy.deepcopy(request['finding']), request_id)
                result.update(status='executed' if outcome.get('signal_sent') else 'not_executed',
                              signal_sent=bool(outcome.get('signal_sent')),
                              exit_verified=bool(outcome.get('exit_verified')),
                              execution_status=outcome.get('status'))
            except Exception as exc:
                result.update(ok=False, status='executor_failed', error_type=type(exc).__name__)
    db.execute('UPDATE process_approvals SET state=? WHERE id=?', (result['status'], request_id))
    db.commit()
    store.add('actions', {'timestamp': time.time(), 'action': 'process.approval_decision',
                          'status': result['status'], 'request_id': request_id,
                          'operator_uid': uid, 'signal_sent': result['signal_sent'],
                          'exit_verified': result.get('exit_verified', False)})
    return result

def pending(store, now=None):
    now = time.time() if now is None else now
    if getattr(store, "db", None) is not None:
        return _sql_pending(store, now)
    rows = store.get(_KEY, []) or []
    return [dict(r) for r in rows if r.get('state') == 'pending' and
            isinstance(r.get('created_at'), (int, float)) and
            0 <= now - r['created_at'] <= TTL]


def enqueue(store, finding, *, now=None):
    now = time.time() if now is None else now
    event = finding.get('event') or {}
    # An event without original process start identity cannot be authorized
    # through a delayed interactive approval.
    from .process_identity import evidence_pid, evidence_starttime
    pid = evidence_pid(event)
    start = evidence_starttime(event)
    if pid is None or start is None:
        return {'status': 'approval_unavailable', 'reason': 'missing_original_process_identity',
                'signal_sent': False}
    if getattr(store, "db", None) is not None:
        return _sql_enqueue(store, finding, now, pid, start)
    with _LOCK:
        rows = pending(store, now)
        # Bound storage and refuse overflow without killing anything.
        if len(rows) >= MAX_PENDING:
            return {'status': 'approval_queue_full', 'signal_sent': False}
        request = {
            'id': secrets.token_hex(16), 'state': 'pending', 'created_at': now,
            'expires_at': now + TTL, 'pid': pid, 'starttime': str(start[0]),
            'rule_id': str(finding.get('rule_id') or '')[:120],
            'finding_id': str(finding.get('finding_id') or '')[:200],
            'engine': str(finding.get('team') or finding.get('source') or 'unknown')[:70],
            # Existing authorized response path must receive the original
            # immutable detection evidence, never GUI-entered process fields.
            'finding': copy.deepcopy(finding),
        }
        rows.append(request)
        store.set(_KEY, rows)
        store.add('actions', {'timestamp': now, 'action': 'process.approval',
                              'status': 'approval_pending', 'request_id': request['id'],
                              'pid': pid, 'rule_id': request['rule_id'],
                              'signal_sent': False})
        return {'status': 'approval_pending', 'request_id': request['id'],
                'signal_sent': False, 'expires_at': request['expires_at']}


def cancel_all_pending(store, *, now=None):
    """Revoke unconsumed test approvals when disabling test mode.

    A completed/processing request is not rolled back.  The operator must
    explicitly review such actions in the audit log.  Neither raw finding
    payloads nor passwords are copied to the cancellation log.
    """
    now = time.time() if now is None else now
    db = getattr(store, 'db', None)
    if db is not None:
        with _LOCK:
            db.execute('BEGIN IMMEDIATE')
            try:
                count = db.execute(
                    "UPDATE process_approvals SET state='cancelled', payload='{}' "
                    "WHERE state='pending'"
                ).rowcount
                db.commit()
            except BaseException:
                if db.in_transaction:
                    db.rollback()
                raise
    else:
        with _LOCK:
            rows = store.get(_KEY, []) or []
            count = 0
            for row in rows:
                if row.get('state') == 'pending':
                    row['state'] = 'cancelled'
                    row.pop('finding', None)
                    count += 1
            store.set(_KEY, rows)
    store.add('actions', {'timestamp': now, 'action': 'process.approval_cancel_pending',
                          'cancelled_count': count, 'signal_sent': False})
    return count


def public_pending(store, now=None):
    return [{k: v for k, v in row.items() if k != 'finding'} for row in pending(store, now)]


def decide(store, request_id, decision, uid, *, process_handler=None, now=None):
    """Atomic consumption; caller MUST enforce fresh admin password.

    `process_handler` is injected by the privileged operator service and must
    re-run every live process identity/response policy check before signalling.
    """
    now = time.time() if now is None else now
    if decision not in ('apply', 'reject'):
        raise ValueError('Unsupported approval decision')
    if not isinstance(request_id, str) or len(request_id) != 32:
        raise ValueError('Invalid approval request ID')
    if getattr(store, 'db', None) is not None:
        return _sql_decide(store, request_id, decision, uid, process_handler, now)
    with _LOCK:
        rows = store.get(_KEY, []) or []
        target = next((r for r in rows if r.get('id') == request_id), None)
        if not target or target.get('state') != 'pending':
            raise ValueError('Request not pending (missing or already processed)')
        if not 0 <= now - target['created_at'] <= TTL:
            target['state'] = 'expired'
            store.set(_KEY, rows)
            raise ValueError('Approval request expired; new detection required')
        target['state'] = 'processing' if decision == 'apply' else 'rejected'
        store.set(_KEY, rows)  # consume before attempting any signal
        finding = copy.deepcopy(target['finding'])
    result = {'ok': True, 'status': 'rejected', 'request_id': request_id,
              'signal_sent': False, 'operator_uid': uid}
    if decision == 'apply':
        if process_handler is None:
            result.update(ok=False, status='no_authenticated_executor')
        else:
            try:
                outcome = process_handler(finding, request_id)
                result.update(status='executed' if outcome.get('signal_sent') else 'not_executed',
                              signal_sent=bool(outcome.get('signal_sent')),
                              exit_verified=bool(outcome.get('exit_verified')),
                              execution_status=outcome.get('status'))
            except Exception as exc:
                result.update(ok=False, status='executor_failed',
                              error_type=type(exc).__name__)
    with _LOCK:
        rows = store.get(_KEY, []) or []
        for row in rows:
            if row.get('id') == request_id:
                row['state'] = result['status']
                row.pop('finding', None)  # clear potentially sensitive evidence
                break
        store.set(_KEY, rows[-MAX_PENDING:])
    store.add('actions', {'timestamp': time.time(), 'action': 'process.approval_decision',
                          'status': result['status'], 'request_id': request_id,
                          'operator_uid': uid, 'signal_sent': result['signal_sent'],
                          'exit_verified': result.get('exit_verified', False)})
    return result
