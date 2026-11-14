"""Both subnet protections ship active (operator decision, 2026-11-03).

İki subnet koruması da etkin gelir (operatör kararı, 2026-11-03).
"""
import importlib.util
import json
from pathlib import Path

from satsuma.config import DEFAULT
from satsuma.store import Store
from satsuma.subnet_protection import evaluate

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location('subnet_default_guard', ROOT / 'integrations/satsuma_guard.py')
guard = importlib.util.module_from_spec(spec)
spec.loader.exec_module(guard)


def test_guard_subnet_protection_is_on_in_code_and_in_the_shipped_config():
    shipped = json.loads((ROOT / 'config_examples/suricata-otx-guard.json').read_text())
    assert guard.DEFAULT['subnet_enabled'] is True
    assert shipped['subnet_enabled'] is True
    assert (shipped['subnet_prefix'], shipped['subnet_threshold']) == (24, 10)


def _find(data, key):
    if isinstance(data, dict):
        if key in data:
            yield data[key]
        for value in data.values():
            yield from _find(value, key)
    elif isinstance(data, list):
        for value in data:
            yield from _find(value, key)


def test_subnet_worker_policy_is_on_in_every_shipped_default():
    assert DEFAULT['subnet_protection_enabled'] is True
    for name in ('policy.json', 'config.json'):
        values = list(_find(json.loads((ROOT / 'config_examples' / name).read_text()), 'subnet_protection_enabled'))
        assert values == [True], name


def test_worker_blocks_with_no_stored_policy_at_all(tmp_path):
    store = Store(tmp_path / 'data', test=True)
    calls = []
    fake = type('R', (), {'block_ip': lambda self, ip, reason: calls.append(ip) or {'status': 'set_membership_confirmed'}})()
    try:
        ten = {f'203.0.113.{n}': 1 for n in range(1, 11)}
        out = evaluate(store, ten, {}, fake, now=100, boot_provider=lambda: {'response_unlocked': True})
        assert len(out) == 10 and len(calls) == 10
    finally:
        store.close()
