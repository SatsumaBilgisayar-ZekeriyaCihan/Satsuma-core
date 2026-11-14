"""Fail-closed notification and revocation regression tests."""
import sqlite3
import time
import pytest
from satsuma.process_approval import enqueue, cancel_all_pending, pending, decide
from satsuma import dashboard_api


class MemoryStore:
    def __init__(self):
        self.data = {}
        self.logs = []
    def get(self, key, default=None):
        return self.data.get(key, default)
    def set(self, key, value):
        self.data[key] = value
    def add(self, key, value):
        self.logs.append((key, value))


def _finding(pid=1234):
    return {'finding_id': 'one', 'rule_id': 'RULE', 'event': {
        'pid': pid, 'starttime': 10042, 'timestamp': time.time()}}


def test_memory_revocation_cannot_replay_after_mode_toggle():
    store = MemoryStore()
    a = enqueue(store, _finding())['request_id']
    assert cancel_all_pending(store) == 1
    assert not pending(store)
    assert cancel_all_pending(store) == 0
    with pytest.raises(ValueError, match='not pending'):
        decide(store, a, 'apply', 1000, process_handler=lambda *_: pytest.fail('must not execute'))
    assert 'finding' not in store.get('process_approval_requests')[0]


def test_database_revocation_two_connections(tmp_path):
    from satsuma.store import Store
    file = str(tmp_path / 'database')
    one, two = Store(file, test=True), Store(file, test=True)
    try:
        a = enqueue(one, _finding())['request_id']
        assert cancel_all_pending(two) == 1
        assert pending(one) == []
        with pytest.raises(ValueError, match='not pending'):
            decide(one, a, 'apply', 1000, process_handler=lambda *_: pytest.fail('must not execute'))
        assert one.db.execute('SELECT payload FROM process_approvals WHERE id=?', (a,)).fetchone()[0] == '{}'
    finally:
        one.close()
        two.close()


def _reader_db(tmp_path, enabled=True):
    file = str(tmp_path / 'reader.sqlite')
    db = sqlite3.connect(file)
    db.execute('CREATE TABLE state(key TEXT PRIMARY KEY, body TEXT)')
    db.execute('CREATE TABLE process_approvals(id TEXT PRIMARY KEY, created REAL, expires REAL, state TEXT, payload TEXT)')
    db.execute('INSERT INTO state VALUES (?,?)', ('interactive_process_test_mode', 'true' if enabled else 'false'))
    now=time.time()
    db.execute('INSERT INTO process_approvals VALUES (?,?,?,?,?)', ('secret-1', now-1, now+60, 'pending', '{"finding":"secret"}'))
    db.execute('INSERT INTO process_approvals VALUES (?,?,?,?,?)', ('secret-2', now-300, now-20, 'pending', '{}'))
    db.commit(); db.close()
    return file


def test_reader_notice_only_count_no_process_evidence(tmp_path, monkeypatch):
    file = _reader_db(tmp_path)
    monkeypatch.setattr(dashboard_api, 'DB_PATH', file)
    result = dashboard_api.METHODS['process_approval_notice']({})
    assert result == {'status': 'OK', 'enabled': True, 'pending_count': 1}
    assert 'secret' not in repr(result)


def test_reader_notice_disabled_hides_pending(tmp_path, monkeypatch):
    file = _reader_db(tmp_path, enabled=False)
    monkeypatch.setattr(dashboard_api, 'DB_PATH', file)
    assert dashboard_api.m_process_approval_notice() == {
        'status': 'DISABLED', 'enabled': False, 'pending_count': 0}


def test_reader_notice_missing_db_is_not_success(tmp_path, monkeypatch):
    monkeypatch.setattr(dashboard_api, 'DB_PATH', str(tmp_path / 'missing.db'))
    assert dashboard_api.m_process_approval_notice()['status'] == 'UNAVAILABLE'
