"""A second Suricata service on queue 100 is reported, never silently ignored.

Kuyruk 100'deki ikinci bir Suricata servisi bildirilir, sessizce geçilmez.
"""
import pytest

from satsuma.self_health import competing_ips


@pytest.mark.parametrize('state,ok,label', [
    ({'LoadState': 'not-found', 'ActiveState': 'inactive', 'UnitFileState': ''}, True, 'NOT_INSTALLED'),
    ({'LoadState': 'loaded', 'ActiveState': 'inactive', 'UnitFileState': 'disabled'}, True, 'DISABLED'),
    ({'LoadState': 'loaded', 'ActiveState': 'inactive', 'UnitFileState': 'masked'}, True, 'DISABLED'),
    # Field log: inactive but enabled, so the fight starts again at boot.
    ({'LoadState': 'loaded', 'ActiveState': 'inactive', 'UnitFileState': 'enabled'}, False, 'ENABLED'),
    ({'LoadState': 'loaded', 'ActiveState': 'active', 'UnitFileState': 'disabled'}, False, 'ACTIVE'),
])
def test_competing_suricata_states(state, ok, label):
    result = competing_ips(state)
    assert result['ok'] is ok and result['state'] == label
    if not ok:
        assert 'kuyruk 100' in result['error'] and 'systemctl disable --now suricata.service' in result['error']
