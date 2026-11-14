"""RAM v2 health ignores normal process churn (2.2.27).

Field 2026-11-04: ram_v2 showed "Sorunlu çalışıyor" because one process in
the last 128 exited or changed while being read.

RAM v2 sağlığı olağan süreç değişimini sorun saymaz.
"""
from satsuma.ram.coordinator import MemoryMonitor


def status(reports):
    m = MemoryMonitor(autostart=False)
    m.ready = [{'observed_at': i, 'pid': i + 1, **r} for i, r in enumerate(reports)]
    return m.health()


def test_vanished_or_changed_process_is_coverage_not_degraded():
    h = status([{'status': 'PARTIAL'}] * 8 + [{'status': 'PROCESS_UNAVAILABLE', 'error': 'ProcessLookupError'},
                                             {'status': 'PROCESS_CHANGED'}])
    assert h['status'] == 'OBSERVING'
    assert h['coverage_state'] == 'INCOMPLETE'


def test_capacity_exclusion_is_coverage_not_degraded():
    m = MemoryMonitor(autostart=False)
    m.capacity_excluded = 3
    m.ready = [{'pid': 1, 'status': 'PARTIAL', 'observed_at': 1}]
    assert m.health()['status'] == 'OBSERVING'
    assert m.health()['coverage_state'] == 'INCOMPLETE'


def test_mostly_denied_is_degraded():
    h = status([{'status': 'PROCESS_UNAVAILABLE', 'error': 'PermissionError'}] * 6 + [{'status': 'PARTIAL'}] * 4)
    assert h['status'] == 'DEGRADED'


def test_scanner_unavailable_is_degraded():
    assert status([{'status': 'SCANNER_UNAVAILABLE'}])['status'] == 'DEGRADED'
