"""Kernel threads are neither vanished processes nor RAM scan coverage gaps.

Çekirdek iş parçacıkları kaybolan süreç ya da RAM taraması kapsam açığı değildir.
"""
import os
import time

from satsuma import worker_memory
from satsuma.ram.coordinator import MemoryMonitor
from satsuma.ram.proc import kernel_thread
from satsuma.worker_memory import WorkerMemory


def stat_line(pid, flags):
    tail = ['S', '0', '0', '0', '0', '0', str(flags)] + ['0'] * 12 + ['100']
    return f'{pid} (kworker/0:1) ' + ' '.join(tail)


def test_flag_parsing():
    assert kernel_thread(stat_line(2, 0x00208040))
    assert not kernel_thread(stat_line(900, 0x00400100))
    assert kernel_thread('7 (a) b) c) ' + ' '.join(['S', '0', '0', '0', '0', '0', '2097152'] + ['0'] * 13))


class Store:
    def __init__(self): self.data = {}
    def get(self, key, default=None): return self.data.get(key, default)
    def set(self, key, value): self.data[key] = value
    def add(self, *args): pass


class Pipeline:
    def ingest_host(self, event): pass


class Monitor:
    def drain(self): return []
    def health(self): return {}
    def ack(self): pass


def test_worker_counts_kernel_threads_apart(tmp_path, monkeypatch):
    for pid in (2, 3):
        (tmp_path / str(pid)).mkdir()
        (tmp_path / str(pid) / 'stat').write_text(stat_line(pid, 0x00208040))
    user = tmp_path / '500'
    user.mkdir()
    (user / 'stat').write_text(stat_line(500, 0x00400100))
    (user / 'exe').symlink_to('/usr/bin/fixture')
    (user / 'maps').write_text('')
    monkeypatch.setattr(worker_memory, 'validate_executable',
                        lambda path: {'status': 'CODE_MATCH', 'complete': True})
    worker = WorkerMemory(Store(), proc_root=tmp_path)
    worker.ram_v2 = Monitor()
    worker.tick(Pipeline())
    health = worker.store.data['worker.memory.health']
    assert (health['kernel_threads'], health['vanished'], health['inspected']) == (2, 0, 1)
    assert health['status'] == 'RUNNING'


def test_a_batch_of_only_kernel_threads_is_not_a_fault(tmp_path):
    (tmp_path / '2').mkdir()
    (tmp_path / '2' / 'stat').write_text(stat_line(2, 0x00208040))
    worker = WorkerMemory(Store(), proc_root=tmp_path)
    worker.ram_v2 = Monitor()
    worker.tick(Pipeline())
    assert worker.store.data['worker.memory.health']['status'] == 'RUNNING'


def test_ram_v2_skips_kernel_threads_without_a_report(tmp_path):
    for pid in (2, 3):
        (tmp_path / str(pid)).mkdir()
        (tmp_path / str(pid) / 'stat').write_text(stat_line(pid, 0x00208040))
    monitor = MemoryMonitor(tmp_path, autostart=False)
    monitor.thread.start()
    try:
        deadline = time.monotonic() + 3
        while time.monotonic() < deadline and len(monitor.kernel_threads) < 2:
            time.sleep(.01)
    finally:
        monitor.close()
    assert monitor.kernel_threads == {2, 3}
    assert monitor.results.empty()
    health = monitor.health()
    assert health['kernel_threads'] == 2 and health['coverage_state'] != 'INCOMPLETE'


def test_no_process_at_all_is_still_a_fault(tmp_path):
    worker = WorkerMemory(Store(), proc_root=tmp_path)
    worker.ram_v2 = Monitor()
    worker.tick(Pipeline())
    assert worker.store.data['worker.memory.health']['status'] == 'DEGRADED'
