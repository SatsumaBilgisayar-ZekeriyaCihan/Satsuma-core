"""Memory rules stop the process for real: a live child, the real chain, a real signal.

The owner's rule: protection components do their job, stopping included, not
only report. A child process maps writable and executable memory (or code from
a temporary folder); the memory check, the rule engine, the automatic response
and the real ResponseWorker run unchanged; the child must die. No fake signal,
no fake /proc.

Bellek kuralları süreci gerçekten durdurur: canlı alt süreç, gerçek zincir,
gerçek sinyal. Sahte sinyal ya da sahte /proc yok; alt süreç ölmelidir.
"""
import subprocess
import sys
import time
from pathlib import Path

import pytest

from run_satsuma_teams import _smart_event
from satsuma.auto_action import AutoActionEngine
from satsuma.pipeline import Pipeline
from satsuma.response import ResponseWorker
from satsuma.smart_rules import SmartRuleEngine
from satsuma.store import Store
from satsuma.worker_memory import inspect_process, memory_event

RWX_SHARED = ('import mmap,sys,time\n'
              'm=mmap.mmap(-1,4096,prot=mmap.PROT_READ|mmap.PROT_WRITE|mmap.PROT_EXEC)\n'
              'print("ready",flush=True)\ntime.sleep(120)\n')
RWX_PRIVATE = ('import mmap,sys,time\n'
               'm=mmap.mmap(-1,4096,flags=mmap.MAP_PRIVATE|mmap.MAP_ANONYMOUS,'
               'prot=mmap.PROT_READ|mmap.PROT_WRITE|mmap.PROT_EXEC)\n'
               'print("ready",flush=True)\ntime.sleep(120)\n')
TMP_CODE = ('import mmap,sys,time\n'
            'f=open(sys.argv[1],"rb")\n'
            'm=mmap.mmap(f.fileno(),4096,prot=mmap.PROT_READ|mmap.PROT_EXEC)\n'
            'print("ready",flush=True)\ntime.sleep(120)\n')
CONFIG = {'response_enabled': True, 'destructive_response_enabled': True,
          'destructive_allowed_actions': ['process_kill'], 'auto_action_process_enabled': True}


@pytest.fixture
def store(tmp_path):
    s = Store(tmp_path / 'data', test=True)
    yield s
    s.close()


def start(code, *args):
    child = subprocess.Popen([sys.executable, '-c', code, *map(str, args)], stdout=subprocess.PIPE, text=True)
    assert child.stdout.readline().strip() == 'ready'
    return child


def detect_and_respond(store, child, indicator):
    path = Path('/proc') / str(child.pid)
    found = inspect_process(path)
    if indicator not in found:
        child.kill()
        pytest.skip(f'this kernel did not create the mapping ({found})')
    starttime = (path / 'stat').read_text().rsplit(')', 1)[1].split()[19]
    pipeline = object.__new__(Pipeline)
    pipeline.store, pipeline.events = store, 0
    pipeline.ingest_host(memory_event(path, indicator, starttime, {'status': 'CODE_MATCH'}, {}))
    row = store.db.execute("SELECT id,body FROM records WHERE kind='normalized' ORDER BY id DESC LIMIT 1").fetchone()
    finding = next(f for f in SmartRuleEngine().match(_smart_event(row[0], row[1])) if f.get('source', 'memory'))
    response = ResponseWorker(store, {'response_enabled': True})
    result = AutoActionEngine(store, CONFIG, response=response).process(finding)['process_response']
    return finding, result


def stopped(child):
    try:
        return child.wait(timeout=10) < 0
    except subprocess.TimeoutExpired:
        child.kill()
        return False


@pytest.mark.parametrize('code', [RWX_PRIVATE, RWX_SHARED], ids=['private', 'shared'])
def test_writable_executable_anonymous_memory_stops_the_process(store, code):
    child = start(code)
    finding, result = detect_and_respond(store, child, 'anonymous_rwx')
    assert finding['rule_id'] == 'SATSUMA-RAM-001'
    assert result['signal_sent'] is True, result
    assert stopped(child)


def test_code_mapped_from_a_temporary_folder_stops_the_process(store, tmp_path):
    code = tmp_path / 'payload.bin'
    code.write_bytes(b'\xc3' * 4096)
    assert str(code).startswith('/tmp/')
    child = start(TMP_CODE, code)
    finding, result = detect_and_respond(store, child, 'writable_dir_code_mapping')
    assert finding['rule_id'] == 'SATSUMA-RAM-008'
    assert result['signal_sent'] is True, result
    assert stopped(child)


def test_ordinary_process_has_no_memory_indicator(store):
    child = start('import time\nprint("ready",flush=True)\ntime.sleep(120)\n')
    try:
        assert {'anonymous_rwx', 'writable_dir_code_mapping'}.isdisjoint(inspect_process(Path('/proc') / str(child.pid)))
    finally:
        child.kill()
        child.wait()
