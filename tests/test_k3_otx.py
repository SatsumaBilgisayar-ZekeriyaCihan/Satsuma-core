"""Audit K3: one OTX pulse, which anyone can publish, never blocks an address.

Denetim K3: herkesin yayınlayabildiği tek bir OTX kaydı hiçbir adresi engellemez.
"""
import importlib.util
import io
import json
import os
from pathlib import Path

import pytest

from satsuma import config as core_config
from satsuma import otx

ROOT = Path(__file__).parents[1]
spec = importlib.util.spec_from_file_location('k3_guard', ROOT / 'integrations/satsuma_guard.py')
guard = importlib.util.module_from_spec(spec)
spec.loader.exec_module(guard)


def guard_config(tmp_path, **custom):
    path = tmp_path / 'guard.json'
    path.write_text(json.dumps(custom))
    os.chmod(path, 0o600)
    return guard.get_config(str(path))


def test_guard_defaults_to_threshold():
    assert guard.DEFAULT['otx_match_mode'] == 'threshold'


def test_old_any_pulse_guard_setting_is_read_as_threshold_and_floors_hold(tmp_path):
    cfg = guard_config(tmp_path, otx_match_mode='any_pulse', otx_min_pulses=1, otx_min_reputation=0)
    assert cfg['otx_match_mode'] == 'threshold'
    assert cfg['otx_min_pulses'] == 2 and cfg['otx_min_reputation'] == 1


class Response(io.BytesIO):
    def __enter__(self):
        return self

    def __exit__(self, *exc):
        return False


@pytest.mark.parametrize('pulses,reputation,expected', [
    (1, 5, False),    # one pulse: what an attacker can publish alone
    (2, 0, False),    # no positive reputation
    (2, 1, True),
    (36, 3, True),
])
def test_guard_otx_needs_two_pulses_and_positive_reputation(tmp_path, monkeypatch, pulses, reputation, expected):
    monkeypatch.setattr(guard, 'local_ips', lambda: set())
    cfg = dict(guard.DEFAULT, mode='observe', state_dir=str(tmp_path), otx_enabled=False)
    svc = guard.Guard(cfg, boot_provider=lambda: {'response_unlocked': True})
    try:
        svc.api_key = 'fixture'
        body = json.dumps({'pulse_info': {'count': pulses}, 'reputation': reputation}).encode()
        monkeypatch.setattr(guard.urllib.request, 'urlopen', lambda *a, **k: Response(body))
        assert svc.otx_check('45.33.32.10') is expected
        # The cached verdict is judged by the same rule.
        monkeypatch.setattr(guard.urllib.request, 'urlopen', lambda *a, **k: pytest.fail('cache not used'))
        assert svc.otx_check('45.33.32.10') is expected
    finally:
        svc.db.close()


def test_guard_one_pulse_in_cache_from_the_old_policy_no_longer_blocks(tmp_path, monkeypatch):
    monkeypatch.setattr(guard, 'local_ips', lambda: set())
    cfg = dict(guard.DEFAULT, mode='observe', state_dir=str(tmp_path), otx_enabled=False)
    svc = guard.Guard(cfg, boot_provider=lambda: {'response_unlocked': True})
    try:
        svc.api_key = 'fixture'
        import time
        svc.db.execute('INSERT INTO otx_cache VALUES(?,?,?,?,?)', ('45.33.32.10', time.time(), 1, 9, 'confirmed'))
        assert svc.otx_check('45.33.32.10') is False
    finally:
        svc.db.close()


@pytest.mark.parametrize('mode', ['any_pulse', 'threshold', None])
def test_worker_never_blocks_on_one_pulse_whatever_mode_is_stored(mode):
    cfg = {'require_tls': True, 'pulse_threshold': 1, 'recent_pulse_days': 14, 'match_mode': mode}
    one = {'tls': {'verified': True}, 'pulse_count': 1, 'latest_pulse_age_days': 0}
    assert otx._should_block(one, cfg) == (False, 'below_pulse_threshold')
    assert otx._should_block({**one, 'pulse_count': 2}, cfg)[0]


def test_unknown_mode_is_refused():
    item = {'tls': {'verified': True}, 'pulse_count': 50, 'latest_pulse_age_days': 0}
    assert otx._should_block(item, {'require_tls': True, 'pulse_threshold': 2, 'recent_pulse_days': 14,
                                    'match_mode': 'unsafe'}) == (False, 'invalid_match_mode')


def test_key_setup_replaces_a_stored_any_pulse(tmp_path, monkeypatch):
    from types import SimpleNamespace
    from satsuma.store import Store
    store = Store(tmp_path / 'data', test=True)
    monkeypatch.setattr(otx, 'save_key', lambda *a, **k: None)
    try:
        store.set('operator_otx_policy', {'match_mode': 'any_pulse'})
        otx.configure_key('fixture', store=store, runner=lambda *a, **k: SimpleNamespace(returncode=0))
        assert store.get('operator_otx_policy')['match_mode'] == 'threshold'
    finally:
        store.close()


def test_core_config_reads_any_pulse_as_threshold():
    assert core_config.validate({'otx_match_mode': 'any_pulse'})['otx_match_mode'] == 'threshold'
    with pytest.raises(ValueError):
        core_config.validate({'otx_match_mode': 'unsafe'})


def test_shipped_examples_do_not_select_one_pulse_blocking():
    for name in ('policy.json', 'config.json', 'suricata-otx-guard.json'):
        assert 'any_pulse' not in (ROOT / 'config_examples' / name).read_text()
