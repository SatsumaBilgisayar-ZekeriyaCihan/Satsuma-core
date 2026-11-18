"""2.2.47: Kayıtlar → Tüm kayıtlar shows every log as one readable list.

Owner request 2026-11-18: technical logs should be meaningful and all logs
should be in a separate, easily readable section.
"""
import json
import os
import sqlite3
import sys
from contextlib import contextmanager
from pathlib import Path

import pytest

from satsuma import record_catalog as catalog

sys.path.insert(0, str(Path(__file__).parents[1] / 'tools'))
NOW = 1_800_000_000.0


def database(rows):
    db = sqlite3.connect(':memory:')
    db.execute('CREATE TABLE records (id INTEGER PRIMARY KEY, created REAL, kind TEXT, body TEXT)')
    for created, kind, body in rows:
        db.execute('INSERT INTO records(created,kind,body) VALUES(?,?,?)', (created, kind, json.dumps(body)))

    @contextmanager
    def connect():
        yield db
    return connect


ROWS = [(NOW - 50, 'events', {'source': 'sys_proc', 'action': 'exec', 'exe': '/usr/bin/ls'}),
        (NOW - 40, 'findings', {'rule_name': 'Şüpheli program', 'rule_id': 'R1', 'severity': 'high', 'token': 'gizli-değer'}),
        (NOW - 30, 'findings', {'rule_name': 'Şüpheli program', 'rule_id': 'R1', 'severity': 'high'}),
        (NOW - 20, 'errors', {'component': 'DNS filtresi', 'error': 'yanıt yok'}),
        (NOW - 10, 'actions', {'action': 'process.terminate', 'status': 'terminated', 'exit_verified': True, 'pid': 42})]


def test_important_view_is_readable_newest_first_and_folds_repeats():
    result = catalog.timeline((('core', database(ROWS)),), now=NOW)
    texts = [(i['level'], i['text']) for i in result['items']]
    assert texts[0][1].startswith('Süreç durdurma') and texts[0][0] == 'Başarılı'
    assert ('Hata', 'DNS filtresi') in texts
    assert ('Önemli', 'Şüpheli program (×2)') in texts
    assert not any(i['kind'] == 'events' for i in result['items'])       # raw telemetry left out
    finding = next(i for i in result['items'] if i['kind'] == 'findings')
    assert finding['kind_name'] == 'Bulgular' and finding['kind_why'] and finding['repeat'] == 2
    assert 'gizli-değer' not in json.dumps(result, ensure_ascii=False)   # masked like everywhere else


def test_views_search_and_paging():
    connect = database(ROWS)
    raw = catalog.timeline((('core', connect),), view='raw', now=NOW)
    assert [i['kind'] for i in raw['items']] == ['events']
    problems = catalog.timeline((('core', connect),), view='problems', now=NOW)
    assert {i['level'] for i in problems['items']} <= {'Hata', 'Önemli', 'Uyarı'}
    assert [i['text'] for i in catalog.timeline((('core', connect),), search='DNS', now=NOW)['items']] == ['DNS filtresi']
    first = catalog.timeline((('core', connect),), limit=1, now=NOW)
    assert first['has_more'] and len(first['items']) == 1
    older = catalog.timeline((('core', connect),), before=first['oldest'], now=NOW)
    assert first['items'][0]['id'] not in {i['id'] for i in older['items']} and older['items']


def test_an_unreadable_database_is_named_not_hidden():
    @contextmanager
    def broken():
        raise sqlite3.OperationalError('disk I/O error')
        yield
    result = catalog.timeline((('core', database(ROWS)), ('host', broken)), now=NOW)
    assert result['errors'] == {'host': 'disk I/O error'} and result['data_state'] == 'DEGRADED' and result['items']


def test_reader_offers_the_log():
    from satsuma import dashboard_api
    assert 'logbook' in dashboard_api.METHODS


def test_navigation_gives_each_area_its_own_section():
    pytest.importorskip('PyQt6.QtWidgets')
    from satsuma.dashboard_qt.windows.nav import SECTION_OF, resolve
    assert SECTION_OF['scanners'] == 'antivirus'
    assert SECTION_OF['blocks'] == SECTION_OF['firewall_settings'] == SECTION_OF['otx'] == 'firewall'
    assert SECTION_OF['apps'] == SECTION_OF['process_approvals'] == 'apps'
    assert {SECTION_OF[t] for t in ('logbook', 'records', 'events', 'errors', 'audit', 'database')} == {'logs'}
    assert resolve('network') == ('firewall', 'firewall_settings') and resolve('logs') == ('logs', 'logbook')


def test_logbook_page_lists_colours_and_explains_the_selected_record():
    os.environ.setdefault('QT_QPA_PLATFORM', 'offscreen')
    pytest.importorskip('PyQt6.QtWidgets')
    from PyQt6.QtWidgets import QApplication
    from dashboard_fixture import FakeBackend
    from satsuma.dashboard_qt.panels.logbook import LogbookPanel
    app = QApplication.instance() or QApplication([])  # kept alive for the whole test
    panel = LogbookPanel(FakeBackend())
    try:
        panel.refresh()
        assert panel.table.rowCount() >= 5 and '×11' in panel.table.item(0, 3).text()
        panel.table.selectRow(0)
        text = panel.detail_view.text()
        assert 'Neden önemli' in text and '11 kez' in text
        panel.view.setCurrentIndex(panel.view.findData('raw'))
        assert panel.table.rowCount() == 1
        panel.view.setCurrentIndex(0)
        panel.search.setText('kworkerd')
        panel._restart()
        assert panel.table.rowCount() == 1
    finally:
        panel.close()


def test_firewall_and_protection_pages_split_the_cards():
    os.environ.setdefault('QT_QPA_PLATFORM', 'offscreen')
    pytest.importorskip('PyQt6.QtWidgets')
    from PyQt6.QtWidgets import QApplication
    from dashboard_fixture import FakeBackend
    from satsuma.dashboard_qt.panels.protection import ProtectionPanel, FirewallSettingsPanel
    app = QApplication.instance() or QApplication([])  # kept alive for the whole test
    protection, firewall = ProtectionPanel(FakeBackend()), FirewallSettingsPanel(FakeBackend())
    try:
        protection.reload(); firewall.reload()
        assert set(protection.cards) == {'process', 'files'} and 'application_control' not in protection.switches
        assert set(firewall.cards) == {'network', 'dns', 'intel'}
        assert firewall.switches['lan_access'].switch.known and firewall.egress_boxes
    finally:
        protection.close(); firewall.close()
