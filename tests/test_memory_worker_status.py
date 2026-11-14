"""The memory worker's status reflects the check, coverage is separate.

Field photo 2026-10-25: "memory — Sorunlu çalışıyor" stayed on because one
process that could not be fully compared turned the worker DEGRADED.

Bellek işçisinin durumu denetimi yansıtır; kapsam ayrıca bildirilir.
"""
import pytest

from satsuma import worker_memory
from satsuma.worker_memory import WorkerMemory


class Store:
    def __init__(self): self.data = {}
    def get(self, key, default=None): return self.data.get(key, default)
    def set(self, key, value): self.data[key] = value
    def add(self, *args): pass


class Pipeline:
    def __init__(self): self.events = []
    def ingest_host(self, event): self.events.append(event)


def run(tmp_path, monkeypatch, outcomes):
    for pid in range(1, len(outcomes) + 1):
        d = tmp_path / str(pid)
        d.mkdir()
        (d / 'stat').write_text(f'{pid} (p) ' + ' '.join(['0'] * 19 + ['100']))
        (d / 'exe').symlink_to('/usr/bin/fixture')
        (d / 'maps').write_text('')
    results = iter(outcomes)
    monkeypatch.setattr(worker_memory, 'validate_executable', lambda path: next(results))
    store, pipeline = Store(), Pipeline()
    WorkerMemory(store, proc_root=tmp_path).tick(pipeline)
    return store.data['worker.memory.health'], pipeline.events


MATCH = {'status': 'CODE_MATCH', 'complete': True}


def test_one_unverifiable_process_does_not_make_the_worker_faulty(tmp_path, monkeypatch):
    health, _ = run(tmp_path, monkeypatch, [MATCH] * 8 + [{'status': 'UNVERIFIED', 'reason': 'mapping_changed'},
                                                         {'status': 'CODE_MATCH', 'complete': False}])
    assert health['status'] == 'RUNNING'
    assert health['coverage'] == 'PARTIAL'  # never reported as fully clean
    assert health['incomplete_reasons'] == {'mapping_changed': 1, 'code_over_check_budget': 1}
    assert 'saldırı göstergesi değildir' in health['coverage_note']


def test_full_comparison_is_complete(tmp_path, monkeypatch):
    health, _ = run(tmp_path, monkeypatch, [MATCH] * 3)
    assert (health['status'], health['coverage'], health['coverage_note']) == ('RUNNING', 'COMPLETE', None)


def test_mostly_denied_access_is_a_real_fault(tmp_path, monkeypatch):
    health, _ = run(tmp_path, monkeypatch, [{'status': 'ACCESS_DENIED', 'reason': 'process_memory_access_denied'}] * 3 + [MATCH])
    assert health['status'] == 'DEGRADED' and 'erişim reddedildi' in health['degraded_reason']


def test_code_difference_is_still_an_event(tmp_path, monkeypatch):
    health, events = run(tmp_path, monkeypatch, [MATCH, {'status': 'CODE_MISMATCH', 'complete': True}])
    assert health['status'] == 'RUNNING'
    assert [e['action'] for e in events] == ['executable_code_mismatch']
