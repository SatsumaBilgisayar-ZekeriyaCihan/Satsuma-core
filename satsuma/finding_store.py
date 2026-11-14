"""Finding event yazımı için ortak dedup katmanı."""
from __future__ import annotations

import hashlib
import json
import time


def _fingerprint(finding, module):
    explicit = finding.get('finding_id')
    if explicit:
        seed = f"{module}|{explicit}"
    else:
        event_ids = []
        for event in finding.get('events', []) or []:
            event_ids.append(str(event.get('id') or event.get('raw_id') or event.get('timestamp') or event.get('pid') or ''))
        seed = json.dumps([
            module,
            finding.get('type'),
            finding.get('rule_id'),
            finding.get('summary'),
            event_ids,
        ], ensure_ascii=False, sort_keys=True)
    return hashlib.sha256(seed.encode('utf-8', errors='replace')).hexdigest()


def _ensure_table(store):
    store.db.execute('''
        CREATE TABLE IF NOT EXISTS finding_dedup (
            fingerprint TEXT PRIMARY KEY,
            finding_id TEXT,
            module TEXT,
            first_seen REAL NOT NULL,
            last_seen REAL NOT NULL,
            occurrences INTEGER NOT NULL DEFAULT 1
        )
    ''')
    store.db.execute('CREATE INDEX IF NOT EXISTS finding_dedup_last_seen ON finding_dedup(last_seen)')
    store.db.commit()


def record_finding(store, finding, module, *, dedup_seconds=86400):
    """Finding'i event havuzuna en fazla bir kez yaz.

    Aynı finding tekrar görülürse event çoğaltılmaz; occurrence sayısı artar.
    Returns: {'written': bool, 'fingerprint': ..., 'occurrences': n}
    """
    _ensure_table(store)
    now = time.time()
    fp = _fingerprint(finding, module)
    row = store.db.execute(
        'SELECT last_seen, occurrences FROM finding_dedup WHERE fingerprint=?',
        (fp,),
    ).fetchone()

    if row and now - float(row[0]) <= dedup_seconds:
        occurrences = int(row[1]) + 1
        store.db.execute(
            'UPDATE finding_dedup SET last_seen=?, occurrences=? WHERE fingerprint=?',
            (now, occurrences, fp),
        )
        store.db.commit()
        return {'written': False, 'fingerprint': fp, 'occurrences': occurrences}

    event_body = {
        'event': {
            'timestamp': finding.get('timestamp', int(now)),
            'category': 'finding',
            'action': finding.get('rule_id') or finding.get('type', 'unknown'),
            'outcome': 'alarm',
            'severity': finding.get('severity', 'info'),
            'classification': finding.get('classification', 'suspicious'),
        },
        'source': {'type': 'satsuma-core', 'module': module},
        'metadata': {'finding': finding, 'dedup_fingerprint': fp},
    }
    store.add('events', event_body)
    store.db.execute(
        'INSERT OR REPLACE INTO finding_dedup(fingerprint,finding_id,module,first_seen,last_seen,occurrences) '
        'VALUES(?,?,?,?,?,?)',
        (fp, finding.get('finding_id'), module, now, now, 1),
    )
    # Bounded retention.
    store.db.execute('DELETE FROM finding_dedup WHERE last_seen < ?', (now - max(dedup_seconds * 7, 86400),))
    store.db.commit()
    return {'written': True, 'fingerprint': fp, 'occurrences': 1}
