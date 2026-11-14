"""Exercise the actual read-only socket protocol used by the desktop GUI."""
import json
import sqlite3
import threading
from pathlib import Path
from unittest.mock import patch

import pytest

from satsuma import dashboard_api as api
from satsuma.dashboard_api_client import ReaderClient, SOCKET_PATH
from satsuma.store import Store

ROOT = Path(__file__).resolve().parents[1]


def test_reader_runtime_directory_and_client_share_socket():
    unit = (ROOT / 'systemd/satsuma-reader.service').read_text()
    assert 'ProtectSystem=strict' in unit
    assert 'RuntimeDirectory=satsuma-reader\n' in unit
    assert 'RuntimeDirectoryMode=0750' in unit
    assert 'Group=satsuma-reader' in unit
    assert SOCKET_PATH == api.SOCKET_PATH == '/run/satsuma-reader/reader.sock'


def test_desktop_reads_real_records_over_read_only_channel(tmp_path):
    store = Store(tmp_path / 'data', test=True)
    store.set('health', {'status': 'running'})
    store.add('events', {'summary': 'real event'})
    dbpath = tmp_path / 'data' / 'core.db'
    store.close()
    socket_path = str(tmp_path / 'reader.sock')
    with patch.object(api, 'DB_PATH', str(dbpath)):
        server = api.Server(socket_path, api.Handler)
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        try:
            client = ReaderClient(socket_path)
            assert client.ping()
            assert client.call('health')['status'] == 'running'
            rows = client.call('rows', kind='events', limit=10)
            assert len(rows) == 1
            assert rows[0]['summary'] == 'real event'
            assert client.call('state', key='health')['status'] == 'running'
            with pytest.raises(RuntimeError, match='bilinmeyen metod'):
                client.call('execute', sql='DELETE FROM records')
            with api._connect() as db:
                with pytest.raises(sqlite3.OperationalError, match='readonly'):
                    db.execute('DELETE FROM records')
            with sqlite3.connect(dbpath) as db:
                assert db.execute('SELECT count(*) FROM records').fetchone()[0] == 1
        finally:
            server.shutdown()
            server.server_close()
            thread.join(timeout=2)


def test_reader_with_block_closes_connection_without_gc(tmp_path):
    # Field log 2026-10-25: satsuma-reader held 507 core.db descriptors and hit
    # EMFILE, because sqlite3's ``with`` does not close and GC rarely ran.
    import gc, os
    path = tmp_path / 'core.db'
    db = sqlite3.connect(path); db.execute('CREATE TABLE state(key, body)'); db.commit(); db.close()
    count = lambda: len(os.listdir('/proc/self/fd'))
    enabled = gc.isenabled(); gc.disable()
    try:
        before = count()
        for _ in range(50):
            with api._connect_at(path) as conn:
                conn.execute('SELECT 1').fetchall()
        assert count() - before <= 2
        with pytest.raises(sqlite3.ProgrammingError):
            conn.execute('SELECT 1')
    finally:
        if enabled: gc.enable()


def test_ticket_enrichment_runs_while_connection_is_open(tmp_path, monkeypatch):
    path = tmp_path / 'core.db'
    db = sqlite3.connect(path)
    db.execute('CREATE TABLE tickets(finding_id, status, ticket_level, evidence)')
    db.execute('CREATE TABLE records(kind, body)')
    db.execute("INSERT INTO tickets VALUES ('f1', 'open', 'high', '{}')")
    db.execute("INSERT INTO records VALUES ('events', ?)", (json.dumps(
        {'metadata': {'finding': {'finding_id': 'f1', 'rule_id': 'R-1'}}}),))
    db.commit(); db.close()
    monkeypatch.setattr(api, 'DB_PATH', str(path))
    [ticket] = api.m_tickets()
    assert ticket['related_finding'] == 'f1' and ticket['related_rule'] == 'R-1'


def test_ticket_enrichment_runs_while_connection_is_open(tmp_path, monkeypatch):
    path = tmp_path / 'core.db'
    db = sqlite3.connect(path)
    db.execute('CREATE TABLE tickets(finding_id, status, ticket_level, evidence)')
    db.execute('CREATE TABLE records(kind, body)')
    db.execute("INSERT INTO tickets VALUES ('f1', 'open', 'high', '{}')")
    db.execute("INSERT INTO records VALUES ('events', ?)", (json.dumps(
        {'metadata': {'finding': {'finding_id': 'f1', 'rule_id': 'R-1'}}}),))
    db.commit(); db.close()
    monkeypatch.setattr(api, 'DB_PATH', str(path))
    [ticket] = api.m_tickets()
    assert ticket['related_finding'] == 'f1' and ticket['related_rule'] == 'R-1'
