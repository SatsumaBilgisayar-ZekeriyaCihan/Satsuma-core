"""The brain reads only the recent window of normalized events.

Field log 2026-10-25: each satsuma-teams cycle took ~22 s and ~74% of a core
because every team re-read and parsed the whole normalized history.

Beyin yalnızca normalize olayların yakın penceresini okur.

Saha kaydı 2026-10-25: her takım geçmişin tamamını yeniden okuyup
ayrıştırdığı için her satsuma-teams turu ~22 sn ve bir çekirdeğin ~%74'ünü
alıyordu.
"""
import json
import time

from satsuma.store import Store
from satsuma.normalized_window import recent_rows
from satsuma.teams.base import BaseTeamLead
from satsuma.correlation_engine import CorrelationEngine


def _event(ts):
    return {'event': {'event': {'timestamp': ts, 'category': 'process', 'action': 'exec'}}}


def _fill(store, old, recent, now):
    rows = [('normalized', now - 86400 - i, json.dumps(_event(now - 86400 - i))) for i in range(old)]
    store.db.executemany('INSERT INTO records(kind,created,body) VALUES(?,?,?)', rows[::-1])
    for i in range(recent):
        store.db.execute('INSERT INTO records(kind,created,body) VALUES(?,?,?)',
                         ('normalized', now - 10 + i, json.dumps(_event(int(now) - 10 + i))))
    store.db.commit()


def test_walk_stops_at_the_first_row_inserted_before_the_window(tmp_path):
    store = Store(tmp_path, test=True)
    try:
        now = time.time()
        _fill(store, 50000, 5, now)
        seen = []
        for row in recent_rows(store.db, int(now) - 300):
            seen.append(row[0])
        assert len(seen) == 5
    finally:
        store.close()


def test_late_inserted_event_inside_the_window_is_kept(tmp_path):
    store = Store(tmp_path, test=True)
    try:
        now = time.time()
        _fill(store, 10, 0, now)
        # Happened 200 s ago, stored just now (delayed audit read).
        store.add('normalized', _event(int(now) - 200))
        # Happened an hour ago, stored now: outside the window, filtered by timestamp.
        store.add('normalized', _event(int(now) - 3600))
        team = BaseTeamLead(store, {})
        assert [e['timestamp'] for e in team._read_normalized(int(now) - 300)] == [int(now) - 200]
        assert [e['timestamp'] for e in CorrelationEngine(store, {})._read_normalized(int(now) - 300)] == [int(now) - 200]
    finally:
        store.close()


def test_large_history_does_not_slow_a_cycle(tmp_path):
    store = Store(tmp_path, test=True)
    try:
        now = time.time()
        _fill(store, 200000, 200, now)
        started = time.monotonic()
        for _ in range(5):  # four teams and the correlation engine
            assert len(BaseTeamLead(store, {})._read_normalized(int(now) - 300)) == 200
        assert time.monotonic() - started < 1.0
    finally:
        store.close()
