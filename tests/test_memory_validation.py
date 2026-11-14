"""Real executable-page validation and containment of disposable children."""
import os
import json
from pathlib import Path
import shutil
import signal
import subprocess
import time

import pytest

from satsuma.memory_validation import validate_executable
from satsuma.worker_memory import WorkerMemory
from satsuma.smart_rules import SmartRuleEngine
from satsuma.auto_action import AutoActionEngine
from satsuma.process_identity import capture_process_identity
from satsuma.store import Store
from satsuma.pipeline import Pipeline as HostPipeline
from run_satsuma_teams import _smart_event, _automatic_actions


@pytest.fixture(scope='module')
def executable(tmp_path_factory):
    compiler = shutil.which('cc')
    if not compiler:
        pytest.skip('C compiler needed for live code-modification test')
    root = tmp_path_factory.mktemp('code-integrity')
    source = root / 'child.c'
    source.write_text(r'''
#include <stdio.h>
#include <unistd.h>
#include <stdint.h>
#include <sys/mman.h>
__attribute__((noinline)) int target(void) { return 37; }
int main(int argc, char **argv) {
    if (argc > 1) {
        long size = sysconf(_SC_PAGESIZE);
        unsigned char *code = (unsigned char *)(uintptr_t)target;
        void *page = (void *)((uintptr_t)code & ~((uintptr_t)size - 1));
        if (mprotect(page, size, PROT_READ|PROT_WRITE|PROT_EXEC)) return 2;
        *code ^= 1;
        if (argv[1][0] != 'w' && mprotect(page, size, PROT_READ|PROT_EXEC)) return 3;
    }
    puts("ready"); fflush(stdout);
    sleep(60);
    return 0;
}
''')
    output = root / 'code-child'
    subprocess.run([compiler, '-O0', '-o', str(output), str(source)], check=True, capture_output=True)
    return output


@pytest.fixture
def children(executable):
    running = []
    def start(tamper=False, writable=False):
        child = subprocess.Popen([str(executable), *(['writable'] if writable else ['tamper'] if tamper else [])],
                                 stdout=subprocess.PIPE, text=True)
        running.append(child)
        assert child.stdout.readline().strip() == 'ready'
        return child
    yield start
    for child in running:
        if child.poll() is None:
            child.kill()
        child.wait(timeout=5)
        child.stdout.close()


def event_for(child, validation):
    identity = capture_process_identity(child.pid)
    assert identity
    return {**identity, 'source': 'memory', 'action': 'executable_code_mismatch',
            'timestamp': time.time(), 'metadata': {'extensions': {
                'host.memory_validation': validation}}}


def test_live_unchanged_code_matches(children):
    child = children()
    result = validate_executable('/proc/' + str(child.pid))
    assert result['status'] == 'CODE_MATCH'
    assert result['complete'] is True
    assert result['checked_bytes'] > 0
    assert all(row['matches'] for row in result['regions'])


def test_live_changed_code_is_detected(children):
    child = children(True)
    result = validate_executable('/proc/' + str(child.pid))
    assert result['status'] == 'CODE_MISMATCH'
    assert any(not row['matches'] for row in result['regions'])
    assert 'content' not in repr(result)


def test_writable_executable_code_cannot_bypass_validation(children):
    child = children(writable=True)
    assert validate_executable('/proc/' + str(child.pid))['status'] == 'CODE_MISMATCH'


def test_memory_rule_stops_live_modified_process_without_second_sensor(children, tmp_path):
    child = children(True)
    validation = validate_executable('/proc/' + str(child.pid))
    findings = SmartRuleEngine().match(event_for(child, validation))
    finding = next(f for f in findings if f['rule_id'] == 'SATSUMA-RAM-005')
    with_store = Store(tmp_path / 'data', test=True)
    try:
        config = dict(response_enabled=True, destructive_response_enabled=True,
                      destructive_allowed_actions=['process_kill'], auto_action_process_enabled=True)
        result = AutoActionEngine(with_store, config).process(finding)['process_response']
        assert result['memory_revalidation']['status'] == 'CODE_MISMATCH'
        assert result['exit_verified'] is True
        assert child.wait(timeout=5) == -signal.SIGTERM
    finally:
        with_store.close()


def test_forged_or_stale_mismatch_cannot_kill_unchanged_process(children, tmp_path):
    child = children()
    event = event_for(child, {'status': 'CODE_MISMATCH'})
    finding = SmartRuleEngine().match(event)[0]
    store = Store(tmp_path / 'data', test=True)
    try:
        config = dict(response_enabled=True, destructive_response_enabled=True,
                      destructive_allowed_actions=['process_kill'], auto_action_process_enabled=True)
        result = AutoActionEngine(store, config).process(finding)['process_response']
        assert result['memory_revalidation']['status'] == 'CODE_MATCH'
        assert result['signal_sent'] is False
        assert child.poll() is None
    finally:
        store.close()


def test_read_denial_is_not_clean(children, monkeypatch):
    child = children()
    original = Path.open
    def denied(path, *args, **kwargs):
        if path.name == 'mem':
            raise PermissionError('test access denial')
        return original(path, *args, **kwargs)
    monkeypatch.setattr(Path, 'open', denied)
    assert validate_executable('/proc/' + str(child.pid))['status'] == 'ACCESS_DENIED'


def test_budget_does_not_claim_full_validation(children):
    child = children()
    result = validate_executable('/proc/' + str(child.pid), byte_limit=1)
    assert result['status'] == 'CODE_MATCH'
    assert result['complete'] is False
    assert result['checked_bytes'] == 1


def test_worker_emits_code_mismatch_with_detection_identity(children, tmp_path):
    child = children(True)
    # Limit discovery to the test-owned process while reads use real procfs.
    root = tmp_path / 'proc'
    root.mkdir()
    (root / str(child.pid)).symlink_to('/proc/' + str(child.pid), target_is_directory=True)
    events = []
    class Pipeline:
        def ingest_host(self, event): events.append(event)
    store = Store(tmp_path / 'data', test=True)
    try:
        WorkerMemory(store, proc_root=root).tick(Pipeline())
        event = next(e for e in events if e['action'] == 'executable_code_mismatch')
        ext = event['metadata']['extensions']
        assert ext['host.pid'] == child.pid
        assert ext['host.starttime'] > 0
        assert ext['host.memory_validation']['status'] == 'CODE_MISMATCH'
        assert store.get('worker.memory.health')['validation_counts']['CODE_MISMATCH'] == 1
        pipeline = object.__new__(HostPipeline)
        normalized = pipeline._build_host_normalized(event)
        smart = _smart_event(1, json.dumps({'event': normalized, 'raw_id': 1}))
        findings = SmartRuleEngine().match(smart)
        config = dict(response_enabled=True, destructive_response_enabled=True,
                      destructive_allowed_actions=['process_kill'], auto_action_process_enabled=True)
        _automatic_actions(store, config, findings)
        assert child.wait(timeout=5) == -signal.SIGTERM
    finally:
        store.close()
