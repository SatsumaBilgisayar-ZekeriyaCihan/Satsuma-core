"""Retired RAM signatures must never authorize a process signal."""
from satsuma.response import ResponseWorker
from satsuma.enforcement import ATTACK_INDICATORS

class FakeStore:
    def get(self, key, default=None):
        return default


def test_retired_rules_are_not_live_attack_indicators():
    assert 'SATSUMA-RAM-107' not in ATTACK_INDICATORS
    assert 'SATSUMA-RAM-001' in ATTACK_INDICATORS
    assert 'SATSUMA-RAM-009' in ATTACK_INDICATORS


def test_retired_findings_denied_before_privileged_backend():
    worker = ResponseWorker(FakeStore(), {})
    def forbidden(*args, **kwargs):
        raise AssertionError('privileged backend called')
    worker._privd = forbidden
    for rule in ('SATSUMA-RAM-106', 'SATSUMA-RAM-107'):
        outcome = worker.terminate_process(12345, 'legacy',
            evidence={'source':'memory', 'action':'unrelated'},context={'rule_id':rule})
        assert outcome['status'] == 'policy_denied'
        assert outcome['signal_sent'] is False
        assert 'ram_clamav_retired' in outcome['reasons']
    for action in ('ram_signature_match_v2', 'ram_review_v2'):
        result = worker.terminate_process(12345, 'legacy', evidence={'action':action})
        assert result['status'] == 'policy_denied'
    result = worker.terminate_process(12345, 'legacy', context={'ram_v2_required':True})
    assert result['status'] == 'policy_denied'


def test_legacy_unit_is_only_stopped_not_reenabled_by_rpm():
    from pathlib import Path
    spec = (Path(__file__).resolve().parents[1] / 'packaging/satsuma-core.spec').read_text()
    assert 'systemctl disable --now satsuma-ram-clamd.service' in spec
    assert 'systemctl enable satsuma-ram-clamd.service' not in spec
    assert 'systemctl start satsuma-ram-clamd.service' not in spec
    assert 'systemctl enable clamd@scan.service satsuma-clamonacc.service' in spec
