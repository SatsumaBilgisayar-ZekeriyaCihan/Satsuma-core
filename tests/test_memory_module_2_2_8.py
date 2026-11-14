"""Memory module hardening from the 2026-10-26 review.

Signals go only to disposable child processes.

2026-10-26 incelemesinden gelen bellek modülü sağlamlaştırması. Sinyaller
yalnızca atılabilir alt işlemlere gider.
"""
import os
import subprocess
import sys
import time

import pytest

from satsuma import memory_validation, process_identity, worker_memory
from satsuma.anonymous_exec import classify, inventory
from satsuma.memory_validation import validate_executable
from satsuma.presentation import action_outcome
from satsuma.process_identity import capture_process_identity, read_tracer_pid
from satsuma.response import ResponseWorker
from satsuma.store import Store


@pytest.fixture
def store(tmp_path):
    s = Store(tmp_path / 'data', test=True)
    yield s
    s.close()


@pytest.fixture
def child():
    p = subprocess.Popen(['sleep', '60'])
    yield p
    if p.poll() is None:
        p.kill()
    p.wait(timeout=5)


def memory_stop(store, pid, monkeypatch=None):
    evidence = {**capture_process_identity(pid), 'timestamp': time.time(), 'source': 'memory',
                'action': 'executable_code_mismatch'}
    return ResponseWorker(store, {'response_enabled': True}).terminate_process(
        pid, 'test', evidence=evidence, context={'rule_id': 'SATSUMA-RAM-005', 'memory_validation_required': True})


def test_scan_is_deterministic_and_reports_its_coverage():
    result = validate_executable('/proc/' + str(os.getpid()), byte_limit=1)
    assert result['scan_order'] == 'file_offset_then_virtual_address'
    assert result['complete'] is False and result['total_candidate_bytes'] > 1
    assert result['byte_limit'] == 1 and result['checked_bytes'] == 1
    assert memory_validation.MAP_LIMIT == 1024 * 1024


def test_tracer_pid_unknown_is_never_zero(tmp_path):
    (tmp_path / '7').mkdir()
    (tmp_path / '7' / 'status').write_text('Name:\tx\nTracerPid:\t4242\n')
    assert read_tracer_pid(7, proc_root=tmp_path) == 4242
    (tmp_path / '7' / 'status').write_text('Name:\tx\nTracerPid:\tabc\n')
    assert read_tracer_pid(7, proc_root=tmp_path) is None
    assert read_tracer_pid(8, proc_root=tmp_path) is None
    assert read_tracer_pid(os.getpid()) == 0


def test_unchanged_code_is_not_stopped_on_a_memory_claim(store, child):
    result = memory_stop(store, child.pid)
    assert result['status'] == 'code_recheck_failed' and result['stage'] == 'before_sigterm'
    assert result['signal_sent'] is False and child.poll() is None
    assert 'regions' not in result['recheck']


@pytest.mark.parametrize('tracer,status', [(4242, 'debugger_attached_review_required'), (None, 'debugger_state_unknown')])
def test_debugger_or_unknown_debugger_state_blocks_a_memory_stop(store, child, monkeypatch, tracer, status):
    monkeypatch.setattr(process_identity, 'read_tracer_pid', lambda pid: tracer)
    monkeypatch.setattr(memory_validation, 'validate_executable', lambda path: {'status': 'CODE_MISMATCH', 'complete': True})
    result = memory_stop(store, child.pid)
    assert result['status'] == status and result['signal_sent'] is False and child.poll() is None


def test_code_restored_after_sigterm_prevents_sigkill(store, monkeypatch):
    stubborn = subprocess.Popen([sys.executable, '-c',
        'import signal,time; signal.signal(signal.SIGTERM,signal.SIG_IGN); print("ready",flush=True); time.sleep(60)'],
        stdout=subprocess.PIPE, text=True)
    try:
        assert stubborn.stdout.readline().strip() == 'ready'
        verdicts = iter([{'status': 'CODE_MISMATCH', 'complete': True}, {'status': 'CODE_MATCH', 'complete': True}])
        monkeypatch.setattr(memory_validation, 'validate_executable', lambda path: next(verdicts))
        result = memory_stop(store, stubborn.pid)
        assert result['status'] == 'code_recheck_failed' and result['stage'] == 'before_sigkill'
        assert result['signal_sent'] is True and result['escalated'] is False and stubborn.poll() is None
        assert 'SIGTERM gönderildi; SIGKILL uygulanmadı (SIGKILL öncesi)' in action_outcome(result)
    finally:
        stubborn.kill(); stubborn.wait(timeout=5); stubborn.stdout.close()


def test_rule_stop_without_memory_basis_needs_no_code_recheck(store, child, monkeypatch):
    monkeypatch.setattr(process_identity, 'read_tracer_pid', lambda pid: pytest.fail('not a memory stop'))
    evidence = {**capture_process_identity(child.pid), 'timestamp': time.time(), 'source': 'sys_proc'}
    result = ResponseWorker(store, {'response_enabled': True}).terminate_process(
        child.pid, 'test', evidence=evidence, context={'rule_id': 'SATSUMA-PRIV-001'})
    assert result['status'] == 'terminated' and result['rule_id'] == 'SATSUMA-PRIV-001'
    assert child.wait(timeout=5) < 0


def test_unverifiable_executable_memory_is_classified():
    assert classify('r-xp', 0, '') == 'anonymous_exec'
    assert classify('rwxp', 0, '[heap]') == 'anonymous_exec'
    assert classify('r-xp', 5, '/memfd:jit (deleted)') == 'memfd_exec'
    assert classify('r-xp', 9, '/usr/bin/foo (deleted)') == 'deleted_exec'
    assert classify('r-xp', 9, '/usr/bin/foo') is None
    assert classify('r-xp', 0, '[vdso]') is None
    assert classify('rw-p', 0, '') is None
    assert classify('r-xs', 0, '') is None


def test_inventory_is_observation_only_and_capped(tmp_path):
    lines = ['%x-%x r-xp 00000000 00:00 0' % (0x7f0000000000 + i * 0x1000, 0x7f0000001000 + i * 0x1000) for i in range(20)]
    lines.append('00400000-00401000 r-xp 00000000 08:01 1234 /usr/bin/foo')
    (tmp_path / 'maps').write_text('\n'.join(lines) + '\n')
    result = inventory(tmp_path, region_cap=4)
    assert result['status'] == 'OBSERVED' and result['status'] not in ('CODE_MATCH', 'CODE_MISMATCH')
    assert result['counts']['anonymous_exec'] == 20 and len(result['regions']) == 4 and result['truncated']
    assert inventory(tmp_path / 'missing')['status'] == 'UNVERIFIED'


def test_worker_reports_unverifiable_memory_without_events(tmp_path, monkeypatch):
    d = tmp_path / '42'
    d.mkdir()
    (d / 'stat').write_text('42 (p) ' + ' '.join(['0'] * 19 + ['100']))
    (d / 'exe').symlink_to('/usr/bin/fixture')
    (d / 'maps').write_text('7f0000000000-7f0000001000 r-xp 00000000 00:00 0\n')
    monkeypatch.setattr(worker_memory, 'validate_executable', lambda path: {'status': 'CODE_MATCH', 'complete': True})
    monkeypatch.setattr(worker_memory, 'inspect_process', lambda path: [])

    class S(dict):
        def get(self, k, d=None): return dict.get(self, k, d)
        def set(self, k, v): self[k] = v
        def add(self, *a): pass
    events = []
    s = S()
    worker_memory.WorkerMemory(s, proc_root=tmp_path).tick(type('P', (), {'ingest_host': lambda self, e: events.append(e)})())
    health = s['worker.memory.health']
    assert health['unverifiable_exec_processes'] == 1 and health['unverifiable_exec_totals']['anonymous_exec'] == 1
    assert health['status'] == 'RUNNING' and events == []
