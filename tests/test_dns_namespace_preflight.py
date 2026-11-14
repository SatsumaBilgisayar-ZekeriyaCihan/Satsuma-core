import importlib.util
from pathlib import Path

ROOT = Path(__file__).parents[1]
spec = importlib.util.spec_from_file_location('dns_namespace_preflight', ROOT / 'tools/dns_namespace_preflight.py')
mod = importlib.util.module_from_spec(spec)
spec.loader.exec_module(mod)


def test_current_source_is_blocked_without_mutation():
    result = mod.assess(ROOT)
    assert result['status'] == 'BLOCKED'
    assert any('loopback' in blocker for blocker in result['blockers'])
    assert any('NamespacePath' in blocker for blocker in result['blockers'])
    assert any('public resolver' in blocker for blocker in result['blockers'])


def test_missing_sources_fail_closed(tmp_path):
    result = mod.assess(tmp_path)
    assert result['status'] == 'BLOCKED'
    assert any('Missing' in blocker for blocker in result['blockers'])
