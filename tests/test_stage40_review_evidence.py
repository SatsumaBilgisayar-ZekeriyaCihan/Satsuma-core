"""Stage 40: operator review carries useful, bounded, redacted evidence only."""
import json

from satsuma_engine.review_evidence import build_review_evidence
from satsuma.deep_rule_review import enqueue, pending
from satsuma.store import Store


def sample_finding():
    return {
        'finding_id': 'F-0123456789abcdef', 'rule_id': 'SATSUMA-C2-004',
        'rule_title': 'Suspicious command-and-control behavior', 'severity': 'high',
        'classification': 'suspicious', 'confidence': 'medium', 'score': 72,
        'category': 'command-control', 'timestamp': '2026-11-14T18:00:00Z',
        'event_fingerprint': 'abc123',
        'evidence': [
            {'type': 'field', 'field': 'event.cmd',
             'value': 'python3 -c "token=supersecret123; connect()"'},
            {'type': 'event', 'event_fingerprint': 'abc123'},
        ],
        'mitre': [{'technique': 'T1059', 'tactic': 'execution'}],
        'source': {'raw_event': {'id': 'evt-1', 'source': 'sys_proc', 'timestamp': '2026-11-14T18:00:00Z',
            'event': {'id': 'evt-1', 'source': 'sys_proc', 'kind': 'process', 'action': 'exec',
                      'pid': 410, 'starttime': 991, 'boot_id': 'boot-a', 'uid': 1000,
                      'exe': '/usr/bin/python3', 'cmd': 'python3 -c "password=hunter2; token=supersecret123"',
                      'file_path': '/home/test/sample.py', 'dest_ip': '203.0.113.8', 'dest_port': 443,
                      'proto': 'tcp', 'api_key': 'do-not-copy'}}}
    }


def test_review_evidence_has_context_but_no_raw_event_or_common_secrets():
    result = build_review_evidence(sample_finding(), window_events=4)
    assert result['rule_id'] == 'SATSUMA-C2-004'
    assert result['process']['pid'] == 410
    assert result['process']['starttime'] == 991
    assert result['file']['file_path'] == '/home/test/sample.py'
    assert result['network']['dest_ip'] == '203.0.113.8'
    serialized = json.dumps(result)
    assert 'hunter2' not in serialized
    assert 'supersecret123' not in serialized
    assert 'do-not-copy' not in serialized
    assert 'raw_event' not in serialized
    assert 'actions' not in result


def test_enqueued_review_preserves_sanitized_context(tmp_path):
    store = Store(str(tmp_path), test=True)
    try:
        store.set('interactive_process_test_mode', True)
        evidence = build_review_evidence(sample_finding(), window_events=4)
        result = enqueue(store, evidence, now=1000)
        assert result['status'] == 'pending'
        record = pending(store, now=1001)[0]
        assert record['process']['pid'] == 410
        assert record['file']['file_path'] == '/home/test/sample.py'
        assert record['authorization'] == 'none'
        assert record['test_rule'] is True
        assert record['process']['cmd'].find('[REDACTED]') >= 0
    finally:
        store.close()


def test_review_queue_rejects_oversized_nested_evidence(tmp_path):
    store = Store(str(tmp_path), test=True)
    try:
        store.set('interactive_process_test_mode', True)
        evidence = build_review_evidence(sample_finding(), window_events=4)
        evidence['matched_conditions'] = [{'field': 'x', 'value': 'x' * 7000}]
        import pytest
        with pytest.raises(ValueError, match='size limit'):
            enqueue(store, evidence, now=1000)
    finally:
        store.close()


def test_operator_label_audit_retains_sanitized_evidence(tmp_path):
    from satsuma.deep_rule_review import decide
    store = Store(str(tmp_path), test=True)
    try:
        store.set('interactive_process_test_mode', True)
        evidence = build_review_evidence(sample_finding(), window_events=4)
        request = enqueue(store, evidence, now=1000)
        result = decide(store, request['id'], 'reject', 1000, now=1001)
        assert result['label'] == 'false_positive'
        assert result['enforcement'] == 'none'
        records = store.recent('deep_rule_review_events', limit=5)
        decided = next(item for item in records if item.get('id') == request['id'])
        assert decided['label'] == 'false_positive'
        assert decided['review_evidence']['process']['pid'] == 410
        assert 'hunter2' not in json.dumps(decided)
    finally:
        store.close()
