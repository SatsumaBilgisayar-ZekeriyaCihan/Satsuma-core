"""Code mapped from world-writable folders and ptrace attachment reach the rules.

Herkesin yazabildiği klasörden eşlenen kod ve ptrace bağlantısı kurallara ulaşır.
"""
import pytest

from satsuma import worker_memory
from satsuma.ai_rule_package import MEMORY_ACTIONS
from satsuma.smart_rules import SmartRuleEngine
from satsuma.worker_memory import WorkerMemory, inspect_process


def process(tmp_path, maps, tracer=0):
    (tmp_path / 'exe').symlink_to('/usr/bin/fixture')
    (tmp_path / 'maps').write_text(maps)
    (tmp_path / 'status').write_text(f'Name:\tfixture\nTracerPid:\t{tracer}\n')
    return tmp_path


@pytest.mark.parametrize('path', ['/tmp/.x/libhook.so', '/dev/shm/a', '/var/tmp/b.so', '/run/user/1000/c'])
def test_executable_mapping_from_writable_folder(tmp_path, path):
    line = f'7f0000000000-7f0000001000 r-xp 00000000 fd:01 42 {path}\n'
    assert 'writable_dir_code_mapping' in inspect_process(process(tmp_path, line), replaced=lambda e: False)


def test_data_mapping_or_system_library_is_not_reported(tmp_path):
    maps = ('7f0000000000-7f0000001000 rw-p 00000000 fd:01 42 /tmp/data.bin\n'
            '7f0000001000-7f0000002000 r-xp 00000000 fd:01 43 /usr/lib64/libc.so.6\n')
    assert 'writable_dir_code_mapping' not in inspect_process(process(tmp_path, maps), replaced=lambda e: False)


def test_traced_process(tmp_path):
    assert 'process_traced' in inspect_process(process(tmp_path, '', tracer=4242), replaced=lambda e: False)
    other = tmp_path / 'other'
    other.mkdir()
    assert 'process_traced' not in inspect_process(process(other, ''), replaced=lambda e: False)


@pytest.mark.parametrize('action,rule', [('writable_dir_code_mapping', 'SATSUMA-RAM-008'),
                                         ('process_traced', 'SATSUMA-RAM-009')])
def test_rules_match_and_ai_packages_may_use_the_actions(action, rule):
    assert action in MEMORY_ACTIONS
    matched = SmartRuleEngine().match({'source': 'memory', 'action': action, 'cmd': ''})
    assert rule in {f['rule_id'] for f in matched}


class Store:
    def __init__(self): self.data = {}
    def get(self, key, default=None): return self.data.get(key, default)
    def set(self, key, value): self.data[key] = value
    def add(self, *args): pass


class Pipeline:
    def __init__(self): self.events = []
    def ingest_host(self, event): self.events.append(event)


class Monitor:
    def drain(self): return []
    def health(self): return {}
    def ack(self): pass


def test_event_names_the_tracer(tmp_path, monkeypatch):
    target = tmp_path / '500'
    target.mkdir()
    (target / 'stat').write_text('500 (p) ' + ' '.join(['0'] * 19 + ['100']))
    process(target, '', tracer=77)
    tracer = tmp_path / '77'
    tracer.mkdir()
    (tracer / 'stat').write_text('77 (gdb) ' + ' '.join(['0'] * 19 + ['50']))
    process(tracer, '')
    (tracer / 'exe').unlink()
    (tracer / 'exe').symlink_to('/usr/bin/gdb')
    monkeypatch.setattr(worker_memory, 'validate_executable', lambda path: {'status': 'CODE_MATCH', 'complete': True})
    worker = WorkerMemory(Store(), proc_root=tmp_path)
    worker.ram_v2 = Monitor()
    pipeline = Pipeline()
    worker.tick(pipeline)
    event = next(e for e in pipeline.events if e['action'] == 'process_traced')
    extensions = event['metadata']['extensions']
    assert (event['pid'], extensions['host.tracer_pid'], extensions['host.tracer_exe']) == (500, 77, '/usr/bin/gdb')
