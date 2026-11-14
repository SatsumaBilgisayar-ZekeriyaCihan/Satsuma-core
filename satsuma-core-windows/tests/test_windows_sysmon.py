"""Sysmon on Windows: verified install, event reading, build tool stop, immediate memory scan.

Windows'ta Sysmon: doğrulanmış kurulum, olay okuma, derleme aracı durdurma, anında bellek taraması.
"""
import io
import json
import zipfile
from types import SimpleNamespace

import pytest

from satsuma_win import guard as guard_module, sysmon
from satsuma_win.guard import Guard

EVENT = ('<Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event"><System>'
         '<EventID>{id}</EventID><EventRecordID>{record}</EventRecordID></System><EventData>{data}</EventData></Event>')


def xml(event_id, record, **fields):
    return EVENT.format(id=event_id, record=record,
                        data=''.join(f'<Data Name="{k}">{v}</Data>' for k, v in fields.items()))


def test_events_are_parsed_and_a_dtd_is_refused():
    event = sysmon.parse(xml(1, 7, ProcessId='4321', Image='C:\\x\\gcc.exe'))
    assert event == {'id': 1, 'record': 7, 'ProcessId': '4321', 'Image': 'C:\\x\\gcc.exe'}
    with pytest.raises(ValueError):
        sysmon.parse('<!DOCTYPE x [<!ENTITY a "b">]>' + xml(1, 1))


def test_injection_events_point_at_both_processes():
    assert sysmon.pids_to_scan({'id': 8, 'TargetProcessId': '900', 'SourceProcessId': '800'}) == [900, 800]
    assert sysmon.pids_to_scan({'id': 10, 'TargetProcessId': '4', 'SourceProcessId': 'x'}) == []
    assert sysmon.pids_to_scan({'id': 3, 'ProcessId': '900'}) == []


def zipped():
    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, 'w') as archive:
        archive.writestr('Sysmon64.exe', b'MZ sysmon')
    return buffer.getvalue()


def runner(signature, installed=False, fails=False, channel_missing=False):
    calls = []
    def run(argv, **kwargs):
        calls.append(argv)
        if argv[0].startswith('powershell'):
            return SimpleNamespace(returncode=0, stdout=json.dumps(signature), stderr='')
        if argv[0] == 'sc.exe':
            return SimpleNamespace(returncode=0 if installed else 1060, stdout='', stderr='')
        if argv[0] == 'wevtutil.exe':
            return SimpleNamespace(returncode=1 if channel_missing else 0, stdout='', stderr='not found')
        return SimpleNamespace(returncode=1 if fails else 0, stdout='', stderr='boom' if fails else '')
    run.calls = calls
    return run


MICROSOFT = {'status': 'Valid', 'subject': 'CN=Microsoft Corporation, O=Microsoft Corporation, L=Redmond'}


def test_only_a_valid_microsoft_signature_is_installed(tmp_path):
    run = runner(MICROSOFT)
    result = sysmon.install(tmp_path, run, fetch=lambda url: zipped())
    assert result['ok'] and result['status'] == 'INSTALLED'
    assert run.calls[-2][1:3] == ['-accepteula', '-i'] and (tmp_path / 'satsuma-sysmon.xml').exists()
    assert run.calls[-1][:2] == ['wevtutil.exe', 'gl']
    for bad in ({'status': 'NotSigned', 'subject': ''}, {'status': 'Valid', 'subject': 'CN=Evil, O=Evil Corp'},
                {'status': 'HashMismatch', 'subject': MICROSOFT['subject']}):
        run = runner(bad)
        result = sysmon.install(tmp_path / 'x', run, fetch=lambda url: zipped())
        assert result['status'] == 'SIGNATURE_REJECTED' and not (tmp_path / 'x' / sysmon.EXE).exists()
        assert not any('-i' in call for call in run.calls)


def test_a_failed_download_or_install_is_reported(tmp_path):
    def offline(url):
        raise OSError('no network')
    assert sysmon.install(tmp_path, runner(MICROSOFT), fetch=offline)['status'] == 'DOWNLOAD_FAILED'
    assert sysmon.install(tmp_path, runner(MICROSOFT, fails=True), fetch=lambda u: zipped())['status'] == 'INSTALL_FAILED'
    assert sysmon.install(tmp_path, runner(MICROSOFT, installed=True), fetch=lambda u: zipped())['status'] == 'UPDATED'


def test_config_records_injection_events_and_every_process():
    for part in ('<ProcessCreate onmatch="exclude" />', '<CreateRemoteThread onmatch="exclude" />',
                 '<ProcessTampering onmatch="exclude" />', '\\AppData\\Local\\Temp\\', '0x1FFFFF'):
        assert part in sysmon.CONFIG


class Events:
    def __init__(self, batches):
        self.batches = list(batches)

    def read(self):
        return self.batches.pop(0) if self.batches else []


class Reader:
    def __init__(self):
        self.stopped = []

    def stop_if_image(self, pid, image):
        self.stopped.append((pid, image))
        return 'stopped'


class Memory:
    def __init__(self):
        self.reader, self.scanned, self.enforce, self.counts = Reader(), [], True, {}

    def scan(self, pids=None):
        self.scanned.append(pids)
        return []


def make_guard(tmp_path, batches, pm=False):
    memory = Memory()
    ok = lambda argv, **kw: SimpleNamespace(returncode=0, stdout='{}', stderr='')
    g = Guard(runner=ok, read=lambda: [], directory=tmp_path, echo=lambda *_: None,
              memory_factory=lambda record, directory, key: memory, sysmon_factory=lambda: Events([[]] + batches),
              package_manager_running=lambda: pm)
    g.start()
    return g, memory


def test_a_build_tool_started_is_stopped_and_injection_targets_are_scanned_at_once(tmp_path):
    batch = [{'id': 1, 'record': 2, 'ProcessId': '700', 'Image': 'C:\\proof\\gcc.exe', 'ParentImage': 'C:\\x.exe'},
             {'id': 1, 'record': 3, 'ProcessId': '701', 'Image': 'C:\\Windows\\System32\\notepad.exe'},
             {'id': 8, 'record': 4, 'TargetProcessId': '900', 'SourceProcessId': '800'}]
    g, memory = make_guard(tmp_path, [batch])
    assert g.startup['sysmon']['ok']
    g.check_sysmon()
    assert memory.reader.stopped == [(700, 'C:\\proof\\gcc.exe')]
    assert memory.scanned == [[700, 701, 800, 900]]
    text = (tmp_path / 'events.jsonl').read_text()
    assert '"build_tool_stopped"' in text and '"SATSUMA-BUILD-001"' in text
    assert g.counts['build_tool_stopped'] == 1 and g.counts['sysmon_events'] == 3


def test_during_windows_installer_the_tool_runs_and_is_recorded(tmp_path):
    batch = [{'id': 1, 'record': 2, 'ProcessId': '700', 'Image': 'C:\\x\\csc.exe'}]
    g, memory = make_guard(tmp_path, [batch], pm=True)
    g.check_sysmon()
    assert memory.reader.stopped == [] and '"build_tool_allowed"' in (tmp_path / 'events.jsonl').read_text()


def test_without_sysmon_the_guard_runs_says_so_and_retries(tmp_path):
    clock = [0.0]
    attempts = []
    def missing():
        attempts.append(clock[0])
        raise OSError('channel not found')
    ok = lambda argv, **kw: SimpleNamespace(returncode=0, stdout='{}', stderr='')
    installs = []
    g = Guard(runner=ok, read=lambda: [], directory=tmp_path, echo=lambda *_: None, clock=lambda: clock[0],
              memory_factory=lambda record, directory, key: Memory(), sysmon_factory=missing,
              sysmon_installer=lambda: installs.append(clock[0]) or {'ok': False, 'status': 'DOWNLOAD_FAILED'})
    g.start()
    assert g.startup['sysmon']['status'] == 'UNAVAILABLE'
    g.check_sysmon()
    clock[0] = 61.0
    g.check_sysmon()
    assert attempts == [0.0, 0.0, 61.0]
    assert installs == [0.0], 'Satsuma installs Sysmon itself, at most every ten minutes'
    assert '"sysmon_install"' in (tmp_path / 'events.jsonl').read_text()


@pytest.mark.skipif(__import__('os').name != 'nt', reason='Win32 layer runs only on Windows')
def test_live_stop_if_image_stops_only_the_named_program():
    import subprocess
    import sys
    from satsuma_win.memory import Win32Reader
    reader = Win32Reader()
    child = subprocess.Popen([sys.executable, '-c', 'import time; time.sleep(60)'])
    try:
        assert reader.stop_if_image(child.pid, 'C:\\Windows\\System32\\notepad.exe') == 'changed'
        assert child.poll() is None
        assert reader.stop_if_image(child.pid, sys.executable) == 'stopped'
        assert child.wait(timeout=10) == 0xC5A75B
    finally:
        if child.poll() is None:
            child.kill()


def test_install_is_ok_only_when_the_event_channel_exists(tmp_path):
    result = sysmon.install(tmp_path, runner(MICROSOFT, channel_missing=True), fetch=lambda u: zipped())
    assert result['ok'] is False and result['status'] == 'CHANNEL_MISSING'
