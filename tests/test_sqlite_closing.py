"""No service leaks SQLite descriptors (field log 2026-10-25: reader EMFILE, operator 240 core.db fds).

Hiçbir servis SQLite tanıtıcısı sızdırmaz.
"""
import os
import re
import sqlite3
from pathlib import Path

import pytest

from satsuma.sqlite_closing import ClosingConnection

ROOT = Path(__file__).parents[1]


def open_fds():
    return len(os.listdir('/proc/self/fd'))


def test_with_block_closes_the_connection(tmp_path):
    path = tmp_path / 'x.db'
    with sqlite3.connect(path, factory=ClosingConnection) as db:
        db.execute('CREATE TABLE t(a)')
    with pytest.raises(sqlite3.ProgrammingError):
        db.execute('SELECT 1')
    with sqlite3.connect(path, factory=ClosingConnection) as db:
        assert db.execute('SELECT count(*) FROM t').fetchone() == (0,)  # the CREATE was committed


def test_a_loop_of_with_blocks_does_not_grow_descriptors(tmp_path):
    path = tmp_path / 'x.db'
    sqlite3.connect(path).execute('PRAGMA journal_mode=WAL').close()
    before = open_fds()
    for _ in range(200):
        with sqlite3.connect(path, factory=ClosingConnection) as db:
            db.execute('SELECT 1').fetchone()
    assert open_fds() - before < 5


def test_no_product_code_uses_the_leaking_pattern():
    leak = re.compile(r'with\s+sqlite3\.connect\((?![^\n]*factory=)')
    offenders = []
    for path in [*ROOT.glob('satsuma/**/*.py'), *ROOT.glob('integrations/*.py'), *ROOT.glob('workers/**/*.py'),
                 *ROOT.glob('installer/*.py'), ROOT / 'run_satsuma_teams.py']:
        for number, line in enumerate(path.read_text().splitlines(), 1):
            if leak.search(line):
                offenders.append(f'{path.relative_to(ROOT)}:{number}')
    assert not offenders


def test_operator_status_summary_does_not_leak_core_db(tmp_path, monkeypatch):
    from satsuma import dashboard_api
    db = tmp_path / 'core.db'
    conn = sqlite3.connect(db)
    conn.execute('PRAGMA journal_mode=WAL')
    conn.execute('CREATE TABLE records(id INTEGER PRIMARY KEY, kind TEXT, body TEXT, ts REAL)')
    conn.execute('CREATE TABLE state(key TEXT PRIMARY KEY, body TEXT)')
    conn.commit(); conn.close()
    monkeypatch.setattr(dashboard_api, 'DB_PATH', db)
    for _ in range(3):
        dashboard_api.m_health_summary()
    before = open_fds()
    for _ in range(60):
        dashboard_api.m_health_summary()
    assert open_fds() - before < 5
