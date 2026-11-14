"""Test process results and paginated SQLite/Qt views without real signals.

Gerçek sinyal olmadan süreç sonuçlarını ve sayfalı SQLite/Qt ekranlarını test et.
"""
import json
import sqlite3
import time
from types import SimpleNamespace
from unittest.mock import Mock

import pytest
from satsuma import auto_process, database_view, dashboard_api
from satsuma.store import Store


@pytest.fixture
def store(tmp_path):
    value = Store(tmp_path / 'data', test=True)
    yield value
    value.close()


@pytest.mark.parametrize('status,sent,exited,expected', [
    ('terminated', True, True, 'process_terminated'),
    ('termination_pending', True, False, 'process_termination_unverified'),
    ('identity_recheck_failed', True, False, 'process_termination_unverified'),
    ('termination_failed', False, False, None),
])
def test_findings_do_not_invent_verified_process_exits(store, monkeypatch, status, sent, exited, expected):
    monkeypatch.setattr(auto_process, 'authorize_destructive', lambda *a, **k: SimpleNamespace(allowed=True, reasons=()))
    finding = {'rule_id': 'SATSUMA-EXEC-001', 'finding_id': 'fake-detection',
               'event': {'pid': 424242, 'starttime': 123, 'exe': '/fixture/bash', 'timestamp': time.time()}}
    executor = Mock()
    executor.terminate_process.return_value = {'status': status, 'signal_sent': sent, 'exit_verified': exited}
    result = auto_process.respond(store, {'auto_action_process_enabled': True}, finding, executor)
    executor.terminate_process.assert_called_once()
    assert result['signal_sent'] is sent
    rows = [json.loads(r[0]) for r in store.db.execute("SELECT body FROM records WHERE kind='findings'")]
    assert [r['automatic_action'] for r in rows] == ([] if expected is None else [expected])
    if sent and not exited:
        assert 'durdurdu' not in rows[0]['title']
    assert database_view.stopped(store.db)['count'] == int(sent and exited and status == 'terminated')


def test_stopped_view_excludes_authorization_and_unverified_and_deduplicates(store):
    for status,sent,exited in [('process_termination_authorized',False,False),
                              ('termination_pending',True,False),('terminated',True,True),('terminated',True,True)]:
        store.add('actions', {'action':'process.terminate','finding_id':'one','pid':444,
                             'status':status,'signal_sent':sent,'exit_verified':exited})
    store.add('actions', {'action':'network.block','status':'terminated','signal_sent':True,'exit_verified':True})
    assert database_view.stopped(store.db)['count'] == 1


def test_database_inventory_pagination_and_secrets(store):
    store.db.execute('CREATE TABLE credentials (id INTEGER PRIMARY KEY, password TEXT)')
    store.db.execute("INSERT INTO credentials VALUES(1,'private-value')")
    for index in range(103):
        store.add('events', {'index':index,'api_key':'private-value','nested':{'token':'secret'}})
    inventory = database_view.catalog(store.db)
    assert next(t for t in inventory if t['table']=='credentials')['access'] == 'metadata_only'
    with pytest.raises(PermissionError):database_view.page(store.db,'credentials')
    pages = [database_view.page(store.db,'records',kind='events',offset=o,limit=50) for o in (0,50,100)]
    assert [len(p['items']) for p in pages] == [50,50,3]
    assert len({r['id'] for p in pages for r in p['items']}) == 103
    assert 'private-value' not in json.dumps(pages)
    assert 'secret"' not in json.dumps(pages)
    with pytest.raises(ValueError):database_view.page(store.db,'records; DELETE FROM records')


def test_secret_state_value_is_hidden(store):
    store.set('otx_api_key', 'hidden-value')
    page = database_view.page(store.db,'state')
    assert 'hidden-value' not in json.dumps(page)


def test_reader_views_retain_read_only_connections(store, monkeypatch):
    db_path = store.db.execute('PRAGMA database_list').fetchone()[2]
    monkeypatch.setattr(dashboard_api,'_connect',lambda:dashboard_api._connect_at(db_path))
    monkeypatch.setattr(dashboard_api,'_connect_host',lambda:dashboard_api._connect_at(db_path))
    assert set(dashboard_api.m_database_catalog()['databases']) == {'core','host'}
    assert dashboard_api.m_stopped_processes({})['count'] == 0
    assert dashboard_api.m_database_page({'table':'state'})['redacted']
    with dashboard_api._connect() as connection:
        with pytest.raises(sqlite3.OperationalError):connection.execute('DELETE FROM state')


def test_new_qt_panels_and_paging(store):
    from PyQt6.QtWidgets import QApplication
    from satsuma.dashboard_qt.panels.process_history import DatabasePanel, StoppedProcessesPanel
    app = QApplication.instance() or QApplication([])
    class Backend:
        def call(self,method,**params):
            if method=='database_catalog':return {'databases':{'core':database_view.catalog(store.db)}}
            if method=='database_page':return database_view.page(store.db,params['table'],kind=params.get('kind'),offset=params['offset'],limit=params['limit'])
            return database_view.stopped(store.db,offset=params['offset'],limit=params['limit'])
    for index in range(51):
        store.add('actions', {'action':'process.terminate','finding_id':str(index),'pid':10000+index,
                             'status':'terminated','signal_sent':True,'exit_verified':True})
    stopped = StoppedProcessesPanel(Backend());stopped.refresh()
    assert stopped.table.rowCount()==50 and stopped.next_page.isEnabled()
    stopped.next_page.click()
    assert stopped.table.rowCount()==1 and not stopped.next_page.isEnabled()
    db = DatabasePanel(Backend());db.refresh()
    index = next(i for i in range(db.sources.count()) if db.sources.itemData(i).get('kind') == 'actions')
    db.sources.setCurrentIndex(index)
    assert db.sources.count()>0 and db.table.rowCount()>0
    stopped.close();db.close()
