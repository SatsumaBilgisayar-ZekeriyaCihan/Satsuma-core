"""Keep tests independent of the host's own gateway and DNS servers.

satsuma.full_protection never blocks this machine's gateway or resolvers; it
reads them from /proc and /etc/resolv.conf. Tests run on many machines (the
cloud runner uses 8.8.8.8 as its resolver), so they see an empty set unless a
test sets one explicitly.

Testleri makinenin kendi ağ geçidi ve DNS sunucularından bağımsız tutar.
"""
import pytest


@pytest.fixture(autouse=True)
def _no_host_gateway_or_dns(monkeypatch):
    from satsuma import full_protection
    monkeypatch.setattr(full_protection, 'protected_local_targets', lambda: set())


# Tests that exercise the intervention lock itself use the real decision.
# Bu dosyalar müdahale kilidinin kendisini sınar; gerçek karar kullanılır.
REAL_INTERVENTION_GUARD = {'test_ram_v2_trust.py'}


@pytest.fixture(autouse=True)
def _trusted_runtime_for_response_tests(request, monkeypatch):
    """Response tests run as on a verified host; the lock has its own tests.

    Müdahale testleri doğrulanmış bir makinedeymiş gibi çalışır; kilidin
    kendi testleri ayrıdır (test_ram_v2_trust.py).
    """
    if request.node.path.name in REAL_INTERVENTION_GUARD or request.node.get_closest_marker('real_intervention_guard'):
        return
    from satsuma import intervention_guard
    monkeypatch.setattr(intervention_guard, 'evaluate', lambda store, verdict_reader=None: {
        'allowed': True, 'status': 'READY', 'reasons': [], 'runtime_status': 'HEALTHY',
        'verdict_state': 'FULL_CHECKED', 'observation_policy_unchanged': True})
