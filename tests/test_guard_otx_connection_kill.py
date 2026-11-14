"""OTX-confirmed peers lose exactly the connection that reaches them.
No live OTX, nft or ss calls: the OTX answer and the killer are injected.

OTX'in doğruladığı uzak uçlar yalnızca kendilerine ulaşan bağlantıyı yitirir.
Canlı OTX, nft veya ss çağrısı yok: OTX yanıtı ve kesici dışarıdan verilir.
"""
import importlib.util
import sqlite3
import time
from pathlib import Path
from unittest.mock import Mock

spec = importlib.util.spec_from_file_location(
    'otx_conn_guard', Path(__file__).resolve().parents[1] / 'integrations/satsuma_guard.py')
guard = importlib.util.module_from_spec(spec)
spec.loader.exec_module(guard)

BAD, GOOD = '203.0.113.5', '198.51.100.7'
LOCAL = '10.20.30.2'


def service(mode='block', unlocked=True, **cfg):
    svc = object.__new__(guard.Guard)
    svc.cfg = {**guard.DEFAULT, 'mode': mode, **cfg}
    svc.api_key = 'key'
    svc.core_store = None
    svc.own_ips = {LOCAL}
    svc.boot_provider = lambda: {'response_unlocked': unlocked}
    svc.eligible = lambda src, dst: src != '192.0.2.99'
    svc.db = sqlite3.connect(':memory:')
    svc.db.execute('CREATE TABLE otx_cache(ip TEXT PRIMARY KEY, ts REAL, pulses INTEGER, reputation REAL, verdict TEXT)')
    svc.write = Mock()
    svc.otx_check = Mock(side_effect=lambda ip: ip == BAD)
    return svc


def killer(report=None):
    return Mock(return_value=report or {'terminated': True, 'verified': True, 'reason': None})


def test_only_connections_to_the_confirmed_peer_are_destroyed():
    svc, kill = service(), killer()
    peers = {BAD: [(LOCAL, 40000, 443), (LOCAL, 40001, 8443)], GOOD: [(LOCAL, 40002, 443)]}
    results = svc.check_otx_connections(peers, kill)
    assert len(results) == 2
    assert [c.args[:4] for c in kill.call_args_list] == [
        (LOCAL, 40000, BAD, 443), (LOCAL, 40001, BAD, 8443)]
    events = [c for c in svc.write.call_args_list if c.args[0] == 'otx_connection_kill']
    assert len(events) == 2 and all(e.kwargs['terminated'] and e.kwargs['verified'] for e in events)


def test_failed_destroy_is_recorded_as_failed_not_success():
    svc = service()
    kill = killer({'terminated': False, 'verified': False, 'reason': 'ss_unavailable'})
    svc.check_otx_connections({BAD: [(LOCAL, 40000, 443)]}, kill)
    event = [c for c in svc.write.call_args_list if c.args[0] == 'otx_connection_kill'][0]
    assert event.kwargs['terminated'] is False and event.kwargs['reason'] == 'ss_unavailable'


def test_observe_mode_or_locked_integrity_never_destroys():
    for svc in (service(mode='observe'), service(mode='block', unlocked=False)):
        kill = killer()
        assert svc.check_otx_connections({BAD: [(LOCAL, 40000, 443)]}, kill) == []
        kill.assert_not_called()
        assert svc.write.call_args.args[0] == 'would_block'


def test_switch_off_or_missing_key_does_nothing():
    for svc in (service(otx_connection_kill=False), service(otx_enabled=False)):
        kill = killer()
        assert svc.check_otx_connections({BAD: [(LOCAL, 40000, 443)]}, kill) == []
        svc.otx_check.assert_not_called()
    svc = service()
    svc.api_key = None
    assert svc.check_otx_connections({BAD: [(LOCAL, 40000, 443)]}, killer()) == []


def test_ineligible_peers_are_never_looked_up_or_destroyed():
    svc, kill = service(), killer()
    svc.check_otx_connections({'192.0.2.99': [(LOCAL, 40000, 443)]}, kill)
    svc.otx_check.assert_not_called()
    kill.assert_not_called()


def test_unhealthy_integrity_stops_it():
    for state in ({'integrity_runtime': {'status': 'DEGRADED'}},):
        svc, kill = service(), killer()
        svc.core_store = Mock()
        svc.core_store.get = lambda key, default=None, _s=state: _s.get(key, default)
        assert svc.check_otx_connections({BAD: [(LOCAL, 40000, 443)]}, kill) == []
        kill.assert_not_called()


def test_new_lookups_per_poll_are_limited_and_cached_ones_are_free():
    svc = service(otx_lookups_per_poll=2)
    svc.otx_check = Mock(return_value=False)
    ips = [f'203.0.113.{n}' for n in range(10, 16)]
    svc.db.execute('INSERT INTO otx_cache VALUES(?,?,?,?,?)', (ips[5], time.time(), 0, 0, 'not_confirmed'))
    svc.check_otx_connections({ip: [(LOCAL, 40000 + i, 443)] for i, ip in enumerate(ips)}, killer())
    asked = [c.args[0] for c in svc.otx_check.call_args_list]
    assert len(asked) == 3 and ips[5] in asked  # two new lookups plus the cached peer


def test_new_config_keys_validate(tmp_path):
    import json, os
    path = tmp_path / 'guard.json'
    for bad in ({'otx_connection_kill': 'yes'}, {'otx_lookups_per_poll': 0}, {'otx_lookups_per_poll': 51}):
        path.write_text(json.dumps(bad))
        os.chmod(path, 0o600)
        try:
            guard.get_config(str(path))
        except (ValueError, PermissionError):
            continue
        raise AssertionError(bad)
    path.write_text(json.dumps({'otx_connection_kill': False, 'otx_lookups_per_poll': 3}))
    os.chmod(path, 0o600)
    cfg = guard.get_config(str(path))
    assert cfg['otx_connection_kill'] is False and cfg['otx_lookups_per_poll'] == 3
