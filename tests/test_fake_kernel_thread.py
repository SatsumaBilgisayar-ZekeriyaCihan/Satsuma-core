"""2.2.56: a user process that calls itself a kernel thread (PF_KTHREAD missing)."""
import time
from pathlib import Path

import pytest

from satsuma import enforcement
from satsuma.dashboard_api import RULES_DIR
from satsuma.smart_rules import SmartRuleEngine
from satsuma.worker_memory import fake_kernel_thread, memory_event


def proc(tmp_path, comm, cmdline):
    d = tmp_path / '4242'
    d.mkdir()
    (d / 'comm').write_text(comm + '\n')
    (d / 'cmdline').write_bytes(cmdline.encode() + b'\0')
    return d


@pytest.mark.parametrize('comm,cmdline', [
    ('kworker/0:1', '/home/u/.cache/kworker'), ('miner', '[kworker/u8:2]'), ('ksoftirqd/3', '/usr/bin/ksoftirqd/3'),
    ('kthreadd', './kthreadd'), ('rcu_sched', 'rcu_sched'),
])
def test_disguise_is_seen(tmp_path, comm, cmdline):
    assert fake_kernel_thread(proc(tmp_path, comm, cmdline))


@pytest.mark.parametrize('comm,cmdline', [
    ('firefox', '/snap/firefox/x/firefox'), ('watchdog', '/usr/sbin/watchdog'), ('kerneloops', '/usr/sbin/kerneloops'),
    ('python3', 'python3 [x].py'), ('bash', '-bash'),
])
def test_ordinary_programs_are_not(tmp_path, comm, cmdline):
    assert not fake_kernel_thread(proc(tmp_path, comm, cmdline))


def test_rule_stops_it():
    engine = SmartRuleEngine(RULES_DIR)
    event = {'source': 'memory', 'kind': 'memory', 'action': 'fake_kernel_thread', 'timestamp': time.time(), 'pid': 4242,
             'category': 'memory', 'metadata': {'extensions': {'host.pid': 4242, 'host.exe': '/tmp/x'}}}
    found = [f for f in engine.match(event) if f['rule_id'] == 'SATSUMA-GAP-072']
    assert found and enforcement.eligible(found[0])


def test_module_load_from_file_or_forced_is_flagged():
    from satsuma.smart_rules import SmartRuleEngine
    engine = SmartRuleEngine()
    hit = lambda cmd: any(f['rule_id'] == 'SATSUMA-GAP-073' for f in engine.match(
        {'source': 'sys_proc', 'action': 'new_process', 'cmd': cmd, 'exe': '/usr/bin/kmod'}))
    assert hit('insmod /tmp/.x/rootkit.ko')
    assert hit('/usr/sbin/insmod ./diamorphine.ko.xz')
    assert hit('modprobe -f nvidia')
    assert hit('modprobe /dev/shm/r.ko')
    assert not hit('modprobe nvidia')
    assert not hit('/sbin/modprobe -q -- snd-pcm')
