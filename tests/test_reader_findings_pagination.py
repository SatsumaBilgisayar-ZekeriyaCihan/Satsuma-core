"""Real SQLite regressions for historical Reader visibility (no host services)."""
import json
import sqlite3

import pytest
from satsuma import dashboard_api as api


@pytest.fixture
def databases(tmp_path, monkeypatch):
    core, host = tmp_path / 'core.db', tmp_path / 'host.db'
    with sqlite3.connect(core) as db:
        db.execute('CREATE TABLE records(id INTEGER PRIMARY KEY, kind TEXT, created REAL, body TEXT)')
        db.execute('CREATE INDEX records_kind ON records(kind, id)')
        db.execute('INSERT INTO records VALUES(1,?,?,?)', ('events', 1, json.dumps({
            'event': {'category': 'finding'}, 'metadata': {'finding': {
                'finding_id': 'old-core-event', 'rule_id': 'OLD', 'severity': 'high'}}})))
        db.executemany('INSERT INTO records(kind,created,body) VALUES(?,?,?)',
                       [('events', 2, '{"event":{"category":"activity"}}')] * 6000)
        db.executemany('INSERT INTO records(kind,created,body) VALUES(?,?,?)',
                       [('findings', i, json.dumps({'finding_id': f'core-{i}', 'rule_id': 'OLD' if i == 0 else 'NEW'}))
                        for i in range(2100)])
    with sqlite3.connect(host) as db:
        db.execute('CREATE TABLE findings(finding_id TEXT PRIMARY KEY, last_seen REAL, body TEXT)')
        db.executemany('INSERT INTO findings VALUES(?,?,?)', [
            (f'host-{i:05}', i, json.dumps({'last_seen': i, 'rule_id': 'OLD' if i == 0 else 'NEW',
                                         'classification': 'confirmed', 'severity': 'high',
                                         'summary': 'old needle' if i == 0 else 'recent'}))
            for i in range(12903)])
    monkeypatch.setattr(api, 'DB_PATH', str(core))
    monkeypatch.setattr(api, 'HOST_DB_PATH', str(host))
    return core, host


def test_old_findings_are_filterable_before_limit(databases):
    result = api.m_findings(rule_id='OLD', limit=10)
    assert {r['finding_id'] for r in result['items']} == {'old-core-event', 'core-0', 'host-00000'}
    assert result['total_count'] == result['counts']['total'] == 15004
    assert result['filtered_count'] == result['shown_count'] == 3
    assert result['data_state'] == 'OK'
    assert not result['has_more']
    assert api.m_finding('host-00000')['available']
    assert api.m_finding('old-core-event')['raw']['finding_id'] == 'old-core-event'


def test_stable_pages_and_unique_source_identity(databases):
    first = api.m_findings(rule_id='NEW', limit=7)
    second = api.m_findings(rule_id='NEW', limit=7, offset=7)
    combined = api.m_findings(rule_id='NEW', limit=14)
    assert first['items'] + second['items'] == combined['items']
    assert len({r['record_key'] for r in combined['items']}) == 14
    assert first['filtered_count'] == 15001
    assert first['has_more']
    for item in first['items'][:1]:
        detail = api.m_finding(item['finding_id'], item['record_key'])
        assert detail['record_key'] == item['record_key']


def test_filters_empty_pages_and_epoch_zero(databases):
    result = api.m_findings(source='core', text='OLD NEEDLE', date_from=0, date_to=0)
    assert [r['finding_id'] for r in result['items']] == ['host-00000']
    empty = api.m_findings(rule_id='missing')
    assert empty['filtered_count'] == empty['shown_count'] == 0
    assert empty['total_count'] == 15004
    assert empty['data_state'] == 'OK'


def test_source_failure_is_explicit_and_does_not_hide_other_source(databases):
    core, host = databases
    host.unlink()
    result = api.m_findings(rule_id='OLD')
    assert result['data_state'] == 'PARTIAL'
    assert result['sources']['host']['data_state'] == 'UNKNOWN'
    assert {r['finding_id'] for r in result['items']} == {'old-core-event', 'core-0'}
    core.unlink()
    assert api.m_findings()['data_state'] == 'UNKNOWN'


def test_reader_leaves_sources_unchanged(databases):
    before = [p.read_bytes() for p in databases]
    api.m_findings(text="' OR 1=1 --")
    assert [p.read_bytes() for p in databases] == before
    with api._connect() as db:
        with pytest.raises(sqlite3.OperationalError, match='readonly'):
            db.execute('DELETE FROM records')


def test_source_keys_disambiguate_colliding_ids_and_tied_times(databases):
    core, host = databases
    with sqlite3.connect(core) as db:
        db.execute('INSERT INTO records(kind,created,body) VALUES(?,?,?)',
                   ('findings', 99999, json.dumps({'finding_id': 'host-00000', 'severity': 'high',
                                                'classification': 'confirmed', 'title': 'core collision'})))
    rows = api.m_findings(text='host-00000')['items']
    assert len(rows) == 2
    for item in rows:
        detail = api.m_finding(item['finding_id'], item['record_key'])
        assert detail['origin'] == item['origin']
        assert detail['record_key'] == item['record_key']
    with sqlite3.connect(host) as db:
        for fid in ('tie-b', 'tie-a'):
            db.execute('INSERT INTO findings VALUES(?,?,?)',
                       (fid, 10, json.dumps({'last_seen': 10, 'rule_id': 'TIED'})))
    assert [r['finding_id'] for r in api.m_findings(rule_id='TIED')['items']] == ['tie-a', 'tie-b']


def test_status_unicode_filter_and_missing_detail(databases):
    _, host = databases
    with sqlite3.connect(host) as db:
        db.execute('INSERT INTO findings VALUES(?,?,?)',
                   ('unicode', 1, json.dumps({'last_seen': 1, 'status': 'CLOSED', 'title': 'ÖNEMLİ'})))
    result = api.METHODS['findings']({'text': 'önemli̇', 'status': 'closed'})
    assert [r['finding_id'] for r in result['items']] == ['unicode']
    assert not api.m_finding(None)['available']
    assert not api.m_finding('HOST-00000')['available']
    assert not api.m_finding('host-00000', record_key='invalid')['available']
