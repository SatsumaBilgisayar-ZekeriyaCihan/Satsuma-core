"""2.2.48: hidden processes from unhide — threads are not hidden, and the user can end a real one.

Field report 2026-11-19: "unhide finds many hidden processes and there is no
button to end them". A thread answers kill(TID, 0) but is not listed in
/proc, so every thread of every program was reported as a hidden process;
ending one of them would have ended the whole program.

Saha bildirimi: unhide çok sayıda gizli süreç buluyor, sonlandırma düğmesi
yok. İş parçacıkları gizli süreç sanılıyordu.
"""
import json
import os
import signal
import subprocess
import threading
import time

import pytest

from satsuma import operator_messages, unhide_scan as unhide


class Host:
    """The findings table of the host database, nothing else."""
    def __init__(self):
        import sqlite3
        self.db = sqlite3.connect(':memory:')
        self.db.execute('CREATE TABLE findings(finding_id TEXT PRIMARY KEY,last_seen REAL,body TEXT)')

    def add(self, pid, status='REVIEW', exe='/tmp/.x/kworker'):
        body = {'finding_id': f'unhide:hidden_pid:{pid}', 'rule_id': 'SATSUMA-SCAN-002', 'status': status,
                'item': {'kind': 'hidden_pid', 'pid': pid, 'executable': exe}}
        self.db.execute('INSERT INTO findings VALUES(?,?,?)', (body['finding_id'], time.time(), json.dumps(body)))

    def body(self, pid):
        return json.loads(self.db.execute('SELECT body FROM findings WHERE finding_id=?', (f'unhide:hidden_pid:{pid}',)).fetchone()[0])


def test_a_thread_of_a_visible_program_is_not_hidden():
    event = threading.Event()
    worker = threading.Thread(target=event.wait)
    worker.start()
    try:
        time.sleep(0.05)
        tid = worker.native_id
        assert tid not in unhide._proc_pids()           # what made it look hidden
        assert unhide.confirm_pid(tid) == 'thread'
        assert unhide._status(tid)['tgid'] == os.getpid()
    finally:
        event.set()
        worker.join()


def test_a_thread_of_a_hidden_group_stays_hidden():
    status = lambda pid: {'tgid': 900, 'ppid': 1, 'name': 'x', 'uid': 0}
    assert unhide.confirm_pid(901, listed=lambda: {1, 2}, alive=lambda p: True, status=status) == 'hidden'
    assert unhide.confirm_pid(901, listed=lambda: {1, 900}, alive=lambda p: True, status=status) == 'thread'


def test_run_discards_threads():
    from types import SimpleNamespace
    text = 'Found HIDDEN PID: 4242\n'
    report = unhide.run(runner=lambda *a, **k: SimpleNamespace(stdout=text if a[0][0] != unhide.UNHIDE_TCP else ''),
                        confirm_pid=lambda pid: 'thread', confirm_port=lambda *a: 'visible', confirm_fake=lambda p: 'real')
    assert report['findings'] == [] and report['discarded'][0]['verdict'] == 'thread'


def test_recheck_closes_threads_and_vanished_processes_and_keeps_hidden_ones():
    host = Host()
    for pid in (101, 102, 103):
        host.add(pid)
    host.add(104, status='RESOLVED')
    verdicts = {101: 'thread', 102: 'transient', 103: 'hidden'}
    status = lambda pid: {101: {'tgid': 50, 'ppid': 1, 'name': 'w', 'uid': 1000}, 50: {'tgid': 50, 'name': 'firefox'}}.get(pid)
    result = unhide.recheck(host, confirm=lambda pid: verdicts[pid], status=status)
    assert result == {'checked': 3, 'still_hidden': [103], 'dismissed': {'thread': 1, 'transient': 1}}
    closed = host.body(101)
    assert closed['status'] == 'DISMISSED' and closed['thread_of'] == 50 and closed['thread_of_name'] == 'firefox'
    assert 'iş parçacığı' in closed['resolution_text']
    assert host.body(103)['status'] == 'REVIEW' and host.body(104)['status'] == 'RESOLVED'


def test_end_terminates_a_real_process_and_records_it():
    child = subprocess.Popen(['sleep', '60'])
    host, records = Host(), []
    host.add(child.pid)
    try:
        time.sleep(0.05)
        result = unhide.end(host, child.pid, records.append, confirm=lambda pid: 'hidden')
        assert result['status'] == 'terminated' and result['signal'] == 'SIGTERM'
        assert child.wait(timeout=5) == -signal.SIGTERM
        assert host.body(child.pid)['status'] == 'RESOLVED'
        assert records[0]['action'] == 'process.terminate' and records[0]['exit_verified'] is True
        assert records[0]['evidence']['exe'].endswith('sleep')
    finally:
        if child.poll() is None:
            child.kill()


def test_a_process_that_ignores_sigterm_is_killed():
    child = subprocess.Popen(['sh', '-c', 'trap "" TERM; while :; do sleep 1; done'])
    try:
        time.sleep(0.2)
        result = unhide.terminate(child.pid, confirm=lambda pid: 'hidden', wait=0.3)
        assert result['status'] == 'killed' and child.wait(timeout=5) == -signal.SIGKILL
    finally:
        if child.poll() is None:
            child.kill()


def test_nothing_is_signalled_unless_it_is_hidden_now():
    sent = []
    send = lambda fd, sig: sent.append(sig)
    for verdict in ('thread', 'visible', 'transient'):
        assert unhide.terminate(os.getppid(), confirm=lambda pid, v=verdict: v, send=send)['status'] == 'not_hidden'
    assert unhide.terminate(os.getpid(), confirm=lambda pid: 'hidden', send=send)['status'] == 'refused'
    kernel = unhide.terminate(4000, confirm=lambda pid: 'hidden', status=lambda pid: {'ppid': 2, 'tgid': 4000}, send=send)
    assert kernel['status'] == 'refused'
    # A thread has no pidfd of its own: refused, the program is untouched.
    event = threading.Event()
    worker = threading.Thread(target=event.wait)
    worker.start()
    try:
        time.sleep(0.05)
        result = unhide.terminate(worker.native_id, confirm=lambda pid: 'hidden', send=send)
        assert result['status'] == 'refused' and result['reason'].startswith('no_pidfd')
    finally:
        event.set()
        worker.join()
    # Changed between the first check and the pidfd: nothing sent.
    answers = iter(['hidden', 'visible'])
    child = subprocess.Popen(['sleep', '60'])
    try:
        assert unhide.terminate(child.pid, confirm=lambda pid: next(answers), send=send)['status'] == 'not_hidden'
        assert child.poll() is None
    finally:
        child.kill()
        child.wait()
    assert sent == []


def test_only_a_pid_from_an_open_finding_can_be_ended():
    host = Host()
    host.add(555, status='DISMISSED')
    with pytest.raises(ValueError, match='açık bulguları arasında değil'):
        unhide.end(host, 555, lambda r: None, confirm=lambda pid: 'hidden')
    with pytest.raises(ValueError, match='açık bulguları arasında değil'):
        unhide.end(host, os.getppid(), lambda r: None, confirm=lambda pid: 'hidden')


def test_operator_sentences():
    assert operator_messages.describe('unhide_terminate', {}, {'ok': True, 'pid': 9, 'status': 'killed'}) == \
        ('ok', 'Gizli süreç 9 kapanmayı reddetti; zorla sonlandırıldı.')
    tone, text = operator_messages.describe('unhide_terminate', {}, {'ok': True, 'pid': 9, 'status': 'not_hidden', 'verdict': 'thread'})
    assert tone == 'warn' and 'iş parçacığı' in text
    tone, text = operator_messages.describe('unhide_recheck', {}, {'ok': True, 'checked': 40, 'still_hidden': [],
                                                                  'dismissed': {'thread': 38, 'transient': 2}})
    assert tone == 'ok' and '38 iş parçacığı' in text and 'Gizli süreç kalmadı' in text


def test_the_operator_refuses_without_confirmation(monkeypatch):
    import inspect
    from satsuma import operator_service
    source = inspect.getsource(operator_service)
    block = source[source.index("elif method in ('unhide_recheck', 'unhide_terminate'):"):]
    block = block[:block.index("elif method == 'device_decision':")]
    assert "params.get('confirmed') is not True" in block and 'unhide_scan.end(host,pid,record)' in block


def test_antivirus_page_shows_open_and_closed_hidden_processes():
    pytest.importorskip('PyQt6.QtWidgets')
    from satsuma.dashboard_qt.panels.scanners import hidden_text
    assert hidden_text({'open': [{'pid': 7}], 'closed': {'thread': 38, 'transient': 2}}) == \
        'Açık: 1 gizli süreç\nKapatılan: 38 iş parçacığı, 2 artık yok'
    assert hidden_text({'open': [], 'closed': {}}) == 'Açık gizli süreç bulgusu yok'
    assert hidden_text({}) == 'Veri alınamadı'
