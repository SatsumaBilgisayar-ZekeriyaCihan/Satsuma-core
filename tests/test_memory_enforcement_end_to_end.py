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
def test_writable_executable_anonymous_memory_stops_the_process(store, code, monkeypatch):
    # 2.2.38: a program in a root-only place is recorded (JIT); here the program is
    # outside such a place, so it is stopped. Burada program güvenilir yerde değil.
    monkeypatch.setattr('satsuma.trusted_process.trusted_path', lambda value: False)
    # 2.2.41: the running file is judged too; the test's interpreter is root's.
    monkeypatch.setattr('satsuma.trusted_process.trusted_running_program', lambda pid: False)
    child = start(code)
    finding, result = detect_and_respond(store, child, 'anonymous_rwx')
    assert finding['rule_id'] == 'SATSUMA-RAM-001'
    assert result['signal_sent'] is True, result
    assert stopped(child)


@pytest.mark.parametrize('code', [RWX_PRIVATE, RWX_SHARED], ids=['private', 'shared'])
def test_rwx_memory_of_a_trusted_program_is_recorded_not_stopped(store, code, monkeypatch):
    """Owner, 2026-11-16: JIT buffers of an installed program must not stop it.

    Sahibi, 2026-11-16: kurulu programın JIT tamponu süreci durdurmaz, kaydedilir.
    """
    monkeypatch.setattr('satsuma.trusted_process.trusted_path', lambda value: True)
    child = start(code)
    try:
        finding, result = detect_and_respond(store, child, 'anonymous_rwx')
        assert finding['rule_id'] == 'SATSUMA-RAM-001'
        assert result['signal_sent'] is False, result
        assert result.get('kept') == 'trusted_program_jit_memory', result
        assert child.poll() is None
    finally:
        child.kill()
        child.wait()


def test_rwx_kept_never_excuses_memfd_deleted_or_other_rules(monkeypatch):
    from satsuma import enforcement
    # Only the installed browser is a root-owned file in a root-only folder.
    monkeypatch.setattr('satsuma.trusted_process.trusted_path', lambda value: value == '/usr/bin/firefox')
    ram1 = {'rule_id': 'SATSUMA-RAM-001'}
    assert enforcement.rwx_kept(ram1, '/usr/bin/firefox') == 'trusted_program_jit_memory'
    assert enforcement.rwx_kept(ram1, '/usr/bin/x (deleted)') is None   # nothing back at the path
    # 2.2.38: replaced by a package update while it ran: kept, as worker_memory does.
    assert enforcement.rwx_kept(ram1, '/usr/bin/firefox (deleted)') == 'trusted_program_jit_memory'
    assert enforcement.rwx_kept(ram1, '/tmp/dropper (deleted)') is None
    assert enforcement.rwx_kept(ram1, '/memfd:payload') is None
    assert enforcement.rwx_kept(ram1, None) is None
    for other in ('SATSUMA-RAM-002', 'SATSUMA-RAM-003', 'SATSUMA-RAM-004', 'SATSUMA-RAM-008', 'SATSUMA-RAM-009'):
        assert enforcement.rwx_kept({'rule_id': other}, '/usr/bin/firefox') is None
    monkeypatch.setattr('satsuma.trusted_process.trusted_path', lambda value: False)
    assert enforcement.rwx_kept(ram1, '/tmp/dropper') is None


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


# 2.2.41 (owner, Fedora Atomic: RAM-001 still closed applications): sandboxed
# programs (Flatpak) report /app/... paths of their own mount namespace.
def test_sandboxed_program_is_judged_by_the_running_file(tmp_path):
    import os
    from satsuma import trusted_process
    if os.geteuid() != 0:
        import pytest
        pytest.skip('needs root to own the fixture files')
    proc = tmp_path / 'proc'
    system = tmp_path / 'flatpak-app-firefox'
    system.write_text('elf'); os.chmod(system, 0o755)
    mine = tmp_path / 'user-flatpak'
    mine.write_text('elf'); os.chmod(mine, 0o755); os.chown(mine, 65534, 65534)
    writable = tmp_path / 'writable'
    writable.write_text('elf'); os.chmod(writable, 0o777)
    for pid, target in ((100, system), (200, mine), (300, writable)):
        (proc / str(pid)).mkdir(parents=True)
        os.symlink(target, proc / str(pid) / 'exe')   # the kernel link opens the running file
    assert trusted_process.trusted_running_program(100, proc_root=proc)
    assert not trusted_process.trusted_running_program(200, proc_root=proc)
    assert not trusted_process.trusted_running_program(300, proc_root=proc)
    assert not trusted_process.trusted_running_program(999, proc_root=proc)
    assert not trusted_process.trusted_running_program('x', proc_root=proc)


def test_rwx_kept_uses_the_running_file_only_when_the_path_is_not_found(monkeypatch):
    from satsuma import enforcement
    seen = []
    monkeypatch.setattr('satsuma.trusted_process.trusted_path', lambda value: False)
    monkeypatch.setattr('satsuma.trusted_process.trusted_running_program', lambda pid: seen.append(pid) or pid == 42)
    ram1 = {'rule_id': 'SATSUMA-RAM-001'}
    assert enforcement.rwx_kept(ram1, '/app/lib/firefox/firefox', pid=42) == 'trusted_program_jit_memory'
    assert enforcement.rwx_kept(ram1, '/app/lib/firefox/firefox', pid=7) is None
    assert enforcement.rwx_kept(ram1, '/app/lib/firefox/firefox') is None          # no pid: path only
    assert enforcement.rwx_kept(ram1, '/memfd:x', pid=42) is None                  # memfd never
    assert enforcement.rwx_kept({'rule_id': 'SATSUMA-RAM-002'}, '/app/x', pid=42) is None
    assert seen == [42, 7]


def test_auto_process_passes_the_pid_to_the_keep_decision():
    from pathlib import Path
    source = (Path(__file__).parents[1] / 'satsuma/auto_process.py').read_text()
    assert "pid=event.get('pid') or memory_extensions.get('host.pid')" in source
