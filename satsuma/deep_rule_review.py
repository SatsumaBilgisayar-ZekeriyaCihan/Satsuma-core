"""Authorized operator feedback for non-enforcing deep-engine test detections.

This is NOT a process termination approval queue. Applying a review means
confirming a detection label for supervised evaluation, never executing it.
No raw command lines, paths, tokens or secrets are stored in pending payloads.
"""
import json
import secrets
import time

TTL = 900
MAX_PENDING = 64
FIELDS = ('finding_id', 'rule_id', 'rule_title', 'severity', 'classification', 'confidence',
          'score', 'category', 'timestamp', 'event_source', 'event_kind', 'event_action',
          'event_fingerprint', 'process', 'file', 'network', 'matched_conditions', 'mitre',
          'window_events', 'evidence_type', 'authorization', 'test_rule', 'review_required')


def _db(store):
    db = store.db
    db.execute('CREATE TABLE IF NOT EXISTS deep_test_reviews ('
               'id TEXT PRIMARY KEY, created REAL NOT NULL, expires REAL NOT NULL,'
               'state TEXT NOT NULL, payload TEXT NOT NULL)')
    db.commit()
    return db


def enqueue(store, evidence, now=None):
    if evidence.get('test_rule') is not True or evidence.get('authorization') != 'none':
        raise ValueError('only non-authoritative lab evidence can be reviewed')
    if store.get('interactive_process_test_mode', False) is not True:
        return {'status': 'test_mode_disabled'}
    now = time.time() if now is None else now
    db = _db(store)
    record = {key: evidence[key] for key in FIELDS if key in evidence}
    encoded = json.dumps(record, ensure_ascii=False, separators=(',', ':'))
    if len(encoded.encode('utf-8')) > 6144:
        raise ValueError('review evidence exceeds size limit')
    record.update(id=secrets.token_hex(16), kind='deep_rule_review', status='pending',
                  created_at=now, expires_at=now + TTL, signal_sent=False)
    db.execute('BEGIN IMMEDIATE')
    try:
        db.execute("UPDATE deep_test_reviews SET state='expired',payload='{}' "
                   "WHERE state='pending' AND expires<?", (now,))
        count = db.execute("SELECT COUNT(*) FROM deep_test_reviews WHERE state='pending'").fetchone()[0]
        if count >= MAX_PENDING:
            db.rollback()
            return {'status': 'review_queue_full'}
        # Only a compact, validated, non-executable record enters the queue.
        db.execute('INSERT INTO deep_test_reviews VALUES(?,?,?,?,?)',
                   (record['id'], now, now + TTL, 'pending', json.dumps(record)))
        db.commit()
    except BaseException:
        if db.in_transaction: db.rollback()
        raise
    store.add('deep_rule_review_events', {'status': 'pending', **record})
    return {'status': 'pending', 'id': record['id']}


def pending(store, now=None):
    now = time.time() if now is None else now
    if store.get('interactive_process_test_mode', False) is not True:
        return []
    db = _db(store)
    rows = db.execute("SELECT payload FROM deep_test_reviews WHERE state='pending' "
                      "AND created<=? AND expires>=? ORDER BY created LIMIT ?",
                      (now, now, MAX_PENDING)).fetchall()
    return [json.loads(row[0]) for row in rows]


def decide(store, request_id, decision, operator_uid, now=None):
    """Apply=label detection correct; reject=label incorrect. No OS actions."""
    if decision not in ('apply', 'reject'):
        raise ValueError('invalid review decision')
    if not isinstance(request_id, str) or len(request_id) != 32:
        raise ValueError('invalid review id')
    if store.get('interactive_process_test_mode', False) is not True:
        raise PermissionError('test mode disabled')
    now = time.time() if now is None else now
    db = _db(store)
    db.execute('BEGIN IMMEDIATE')
    try:
        row = db.execute('SELECT state,expires,payload FROM deep_test_reviews WHERE id=?',
                         (request_id,)).fetchone()
        if row is None or row[0] != 'pending':
            raise ValueError('request already processed or absent')
        if row[1] < now:
            db.execute("UPDATE deep_test_reviews SET state='expired',payload='{}' WHERE id=?", (request_id,))
            db.commit()
            raise ValueError('request expired')
        evidence = json.loads(row[2])
        state = 'operator_label_accepted' if decision == 'apply' else 'operator_label_rejected'
        updated = db.execute("UPDATE deep_test_reviews SET state=?,payload='{}' "
                             "WHERE id=? AND state='pending'", (state, request_id)).rowcount
        if updated != 1: raise ValueError('request already processed')
        db.commit()
    except BaseException:
        if db.in_transaction: db.rollback()
        raise
    result = {'ok': True, 'status': state, 'id': request_id,
              'rule_id': evidence.get('rule_id'), 'signal_sent': False,
              'enforcement': 'none', 'operator_uid': operator_uid,
              'review_evidence': evidence,
              'label': 'true_positive' if decision == 'apply' else 'false_positive'}
    store.add('deep_rule_review_events', result)
    return result


def cancel_all(store, now=None):
    db = _db(store)
    db.execute('BEGIN IMMEDIATE')
    try:
        count = db.execute("UPDATE deep_test_reviews SET state='cancelled',payload='{}' "
                           "WHERE state='pending'").rowcount
        db.commit()
    except BaseException:
        if db.in_transaction: db.rollback()
        raise
    if count: store.add('deep_rule_review_events', {'status': 'cancelled', 'count': count,
                  'signal_sent': False, 'timestamp': time.time()})
    return count
