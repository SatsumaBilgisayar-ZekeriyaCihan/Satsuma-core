"""Regression: retired runtime web research cannot be re-enabled by old configuration."""
import importlib.util
from satsuma import config, investigation, full_protection


def test_old_web_options_are_migrated_out():
    state = config.validate({'investigation_web_enabled': True,
                             'investigation_trusted_sources': ['mitre_attack']})
    assert 'investigation_web_enabled' not in state
    assert 'investigation_trusted_sources' not in state
    assert 'investigation_web_enabled' not in full_protection.FULL_PROTECTION


def test_runtime_web_module_absent():
    assert importlib.util.find_spec('satsuma.web_research') is None


def test_local_investigation_has_no_web_result():
    finding = {'type': 'unknown-attack', 'severity': 'info', 'pid': 0}
    result = investigation.investigate(None, finding,
                 {'investigation_web_enabled': True})
    assert 'web_research' not in result
    assert 'warning' in result
