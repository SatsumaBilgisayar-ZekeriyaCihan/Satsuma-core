"""Memory signature scan (RAM v2) on Windows: ClamAV installation, clamd connection, the scan thread, decisions.

Windows'ta bellek imza taraması (RAM v2): ClamAV kurulumu, clamd bağlantısı, tarama iş parçacığı, kararlar.
"""
import hashlib
import io
import os
import socket
import sys
import zipfile
from types import SimpleNamespace

import pytest

from satsuma import memory_decision
from satsuma_win import clamav, ramscan
from satsuma_win.guard import Guard

RULES = memory_decision.load_rules()
FILES = {'clamd.exe': hashlib.sha256(b'clamd').hexdigest(), 'freshclam.exe': hashlib.sha256(b'fresh').hexdigest(),
         'libclamav.dll': hashlib.sha256(b'lib').hexdigest(), 'certs/clamav.crt': hashlib.sha256(b'crt').hexdigest()}
CONTENT = {'clamd.exe': b'clamd', 'freshclam.exe': b'fresh', 'libclamav.dll': b'lib', 'certs/clamav.crt': b'crt'}


def archive(content=CONTENT, top='top/'):
    data = io.BytesIO()
    with zipfile.ZipFile(data, 'w') as z:
        for name, body in content.items():
            z.writestr(top + name, body)
        z.writestr(top + 'clamd.pdb', b'not taken')
    return data.getvalue()


def fetcher(payload):
    def fetch(url, target):
        assert url == clamav.URL
        with open(target, 'wb') as stream:
            stream.write(payload)
    return fetch


# -- installation ----------------------------------------------------------------

def test_pinned_release_is_the_official_clamav_1_5_4_windows_archive():
    assert clamav.URL.startswith('https://github.com/Cisco-Talos/clamav/releases/download/clamav-1.5.4/')
    assert clamav.ARCHIVE_SHA256 == '0d9e0228b2674137ea1a2853566c98a0278ad52ab2582c3d6dbd75373848c395'
    for name in ('clamd.exe', 'freshclam.exe', 'libclamav.dll', 'libfreshclam.dll', 'certs/clamav.crt'):
        assert len(clamav.FILES[name]) == 64
    assert not any(name.endswith(('.pdb', '.lib')) for name in clamav.FILES)


def test_an_archive_with_another_digest_installs_nothing(tmp_path):
    engine = tmp_path / 'ClamAV'
    result = clamav.install_engine(engine, fetcher(archive()), archive_sha256='0' * 64, files=FILES, top='top/')
    assert result['status'] == 'ARCHIVE_REJECTED' and not result['ok']
    assert not engine.exists() and not list(tmp_path.glob('*.part'))


def test_a_changed_file_inside_the_archive_installs_nothing(tmp_path):
    payload = archive({**CONTENT, 'libclamav.dll': b'evil'})
    engine = tmp_path / 'ClamAV'
    result = clamav.install_engine(engine, fetcher(payload), archive_sha256=hashlib.sha256(payload).hexdigest(),
                                   files=FILES, top='top/')
    assert result == {'ok': False, 'status': 'FILE_REJECTED', 'file': 'libclamav.dll'}
    assert not engine.exists()


def test_only_the_listed_files_are_installed_and_checked_again(tmp_path):
    payload = archive()
    engine = tmp_path / 'ClamAV'
    result = clamav.install_engine(engine, fetcher(payload), archive_sha256=hashlib.sha256(payload).hexdigest(),
                                   files=FILES, top='top/')
    assert result['ok'] and result['status'] == 'INSTALLED'
    assert sorted(p.relative_to(engine).as_posix() for p in engine.rglob('*') if p.is_file()) == sorted(FILES)
    assert clamav.verify_engine(engine, FILES) == []
    again = clamav.install_engine(engine, lambda *a: pytest.fail('downloaded again'), files=FILES)
    assert again['status'] == 'PRESENT'
    (engine / 'libclamav.dll').write_bytes(b'changed')
    (engine / 'version.dll').write_bytes(b'planted')
    assert clamav.verify_engine(engine, FILES) == ['changed:libclamav.dll', 'foreign:version.dll']


def test_a_failed_download_is_reported(tmp_path):
    def broken(url, target):
        raise OSError('network down')
    result = clamav.install_engine(tmp_path / 'ClamAV', broken, files=FILES)
    assert result['status'] == 'DOWNLOAD_FAILED' and 'network down' in result['error']


def test_clamd_listens_only_on_loopback_with_its_own_folders(tmp_path):
    text = clamav.clamd_config(tmp_path / 'ClamAV', tmp_path / 'data')
    assert 'TCPAddr 127.0.0.1\n' in text and 'TCPSocket 3311\n' in text
    assert 'DatabaseDirectory "%s"' % (tmp_path / 'data' / 'database') in text
    assert 'CVDCertsDirectory "%s"' % (tmp_path / 'ClamAV' / 'certs') in text
    assert 'DetectPUA no' in text and 'StreamMaxLength 4M' in text
    fresh = clamav.freshclam_config(tmp_path / 'ClamAV', tmp_path / 'data')
    assert 'DatabaseMirror database.clamav.net' in fresh and 'DatabaseDirectory' in fresh
    with pytest.raises(ValueError):
        clamav.clamd_config('C:\\a"b', tmp_path)


def test_database_needs_daily_and_main(tmp_path):
    clamav.prepare(tmp_path / 'ClamAV', tmp_path)
    assert not clamav.database_present(tmp_path)
    (tmp_path / 'database' / 'daily.cld').write_bytes(b'x')
    assert not clamav.database_present(tmp_path)
    (tmp_path / 'database' / 'main.cvd').write_bytes(b'x')
    assert clamav.database_present(tmp_path)


def test_freshclam_runs_with_the_satsuma_configuration(tmp_path):
    calls = []

    def runner(argv, **kwargs):
        calls.append(argv)
        (tmp_path / 'data' / 'database' / 'daily.cvd').write_bytes(b'x')
        (tmp_path / 'data' / 'database' / 'main.cvd').write_bytes(b'x')
        return SimpleNamespace(returncode=0, stdout='', stderr='')
    result = clamav.update_database(tmp_path / 'ClamAV', tmp_path / 'data', runner)
    assert result['ok'] and result['status'] == 'UPDATED'
    assert calls[0][0].endswith('freshclam.exe') and calls[0][1] == '--config-file=' + str(
        tmp_path / 'data' / 'freshclam.conf')


# -- clamd connection ------------------------------------------------------------

def test_replies_signature_review_and_errors():
    assert clamav.parse_reply(b'stream: OK') == {'status': 'NO_MATCH'}
    assert clamav.parse_reply(b'stream: Win.Trojan.X-1 FOUND') == {'status': 'SIGNATURE_MATCH',
                                                                    'signature': 'Win.Trojan.X-1'}
    assert clamav.parse_reply(b'stream: Heuristics.Y FOUND')['status'] == 'REVIEW_REQUIRED'
    assert clamav.parse_reply(b'stream: PUA.Z FOUND')['status'] == 'REVIEW_REQUIRED'
    assert clamav.parse_reply(b'stream: Heuristics.Limits.Exceeded.MaxScanTime FOUND') == {
        'status': 'LIMIT_EXCEEDED', 'signature': 'Heuristics.Limits.Exceeded.MaxScanTime'}
    with pytest.raises(RuntimeError):
        clamav.parse_reply(b'INSTREAM size limit exceeded. ERROR')


def test_the_other_end_must_be_the_private_clamd_not_just_the_port():
    client = SimpleNamespace(getsockname=lambda: ('127.0.0.1', 50000), getpeername=lambda: ('127.0.0.1', 3311))
    child = SimpleNamespace(pid=77, poll=lambda: None)
    mine = [SimpleNamespace(status='ESTABLISHED', laddr=('127.0.0.1', 3311), raddr=('127.0.0.1', 50000))]
    clamav.verify_peer(client, child, mine)
    other = [SimpleNamespace(status='ESTABLISHED', laddr=('127.0.0.1', 3311), raddr=('127.0.0.1', 50001))]
    with pytest.raises(PermissionError):
        clamav.verify_peer(client, child, other)
    with pytest.raises(PermissionError):
        clamav.verify_peer(client, SimpleNamespace(pid=77, poll=lambda: 1), mine)


def test_instream_protocol_against_a_local_fake_clamd():
    import threading
    server = socket.socket()
    server.bind(('127.0.0.1', 0))
    server.listen(1)
    port = server.getsockname()[1]
    received = []

    def serve():
        connection, _ = server.accept()
        with connection:
            data = b''
            while not data.endswith(b'\0\0\0\0'):
                data += connection.recv(65536)
            received.append(data)
            connection.sendall(b'stream: Satsuma.Proof FOUND\0')
    thread = threading.Thread(target=serve)
    thread.start()
    import time
    scanner = clamav.Clamd(port, None, verifier=lambda client, child: None)
    answer = scanner.scan(b'A' * 70000, time.monotonic() + 5)
    thread.join(5)
    server.close()
    assert answer == {'status': 'SIGNATURE_MATCH', 'signature': 'Satsuma.Proof'}
    assert received[0].startswith(b'zINSTREAM\0\x00\x01\x00\x00')


class FakeChild:
    pid = 900

    def __init__(self):
        self.code = None

    def poll(self):
        return self.code

    def terminate(self):
        self.code = 1

    def wait(self, timeout=None):
        return self.code


def ready_engine(tmp_path, monkeypatch):
    monkeypatch.setattr(clamav, 'verify_engine', lambda engine, files=None: [])
    clamav.prepare(tmp_path / 'ClamAV', tmp_path / 'data')
    for name in ('daily.cvd', 'main.cvd'):
        (tmp_path / 'data' / 'database' / name).write_bytes(b'x')


def test_runtime_refuses_to_start_a_changed_engine_or_without_a_database(tmp_path, monkeypatch):
    runtime = clamav.Runtime(tmp_path / 'ClamAV', tmp_path / 'data', clock=lambda: 0.0,
                             popen=lambda *a, **k: pytest.fail('started'), job_factory=lambda: None)
    assert not runtime.ensure_ready() and runtime.state == 'UNAVAILABLE' and 'engine_not_sound' in runtime.error
    monkeypatch.setattr(clamav, 'verify_engine', lambda engine, files=None: [])
    runtime.retry_at = 0
    assert not runtime.ensure_ready() and 'database_missing' in runtime.error


def test_runtime_starts_clamd_in_its_job_and_waits_for_the_database(tmp_path, monkeypatch):
    ready_engine(tmp_path, monkeypatch)
    started, assigned, now = [], [], [0.0]
    child = FakeChild()

    class Job:
        def assign(self, process):
            assigned.append(process)

        def close(self):
            pass
    runtime = clamav.Runtime(tmp_path / 'ClamAV', tmp_path / 'data', clock=lambda: now[0],
                             popen=lambda argv, **k: started.append(argv) or child, job_factory=Job)
    pings = iter([OSError('loading'), None])

    def ping(deadline):
        outcome = next(pings)
        if outcome:
            raise outcome
    monkeypatch.setattr(clamav.Clamd, 'ping', lambda self, deadline: ping(deadline))
    assert not runtime.ensure_ready() and runtime.state == 'LOADING_DATABASE'
    assert started[0][0].endswith('clamd.exe') and assigned == [child]
    assert runtime.ensure_ready() and runtime.state == 'READY'
    runtime.close()
    assert child.code == 1


def test_maintenance_installs_when_missing_and_updates_every_four_hours(tmp_path, monkeypatch):
    now = [0.0]
    installs, updates = [], []
    runtime = clamav.Runtime(tmp_path / 'ClamAV', tmp_path / 'data', clock=lambda: now[0],
                             installer=lambda: installs.append(1) or {'ok': False, 'status': 'DOWNLOAD_FAILED'},
                             updater=lambda: updates.append(1) or {'ok': True, 'status': 'UPDATED'})
    assert runtime.maintain()['status'] == 'DOWNLOAD_FAILED'
    now[0] = 300
    assert runtime.maintain() is None and len(installs) == 1
    now[0] = 600
    runtime.maintain()
    assert len(installs) == 2
    ready_engine(tmp_path, monkeypatch)
    now[0] = 700
    assert runtime.maintain() is None and not updates
    now[0] = 600 + clamav.UPDATE_EVERY
    assert runtime.maintain()['status'] == 'UPDATED' and updates == [1]


# -- scan thread -----------------------------------------------------------------

class FakeProcess:
    def __init__(self, pid, data=b'', critical=False, image='C:\\Users\\a\\Downloads\\x.exe', change_after=None):
        self.pid, self.data, self.critical, self._image = pid, data, critical, image
        self.terminated, self.reads, self.change_after = None, 0, change_after

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        return False

    def snapshot(self):
        return (self.pid, 111, self._image, 0, 0), '%x-%x rw-p 00000000 00:00 0 [windows:private]\n' % (
            0x10000, 0x10000 + len(self.data))

    def read(self, address, size):
        self.reads += 1
        if self.change_after is not None and self.reads > self.change_after:
            return b'\0' * size
        offset = address - 0x10000
        return self.data[offset:offset + size]

    def eligible(self, region):
        return True, None

    def info(self):
        return {'pid': self.pid, 'image': self._image, 'critical': self.critical, 'parent': 1}

    def terminate(self, created):
        assert created == 111
        self.terminated = created


class MarkerScanner:
    def __init__(self, marker=b'SATSUMA-PROOF', name='Satsuma.Proof.UNOFFICIAL'):
        self.marker, self.name = marker, name

    def scan(self, payload, deadline):
        if self.marker not in payload:
            return {'status': 'NO_MATCH'}
        # As clamav.parse_reply: heuristic and PUA names are review only.
        review = self.name.startswith(('Heuristics.', 'PUA.'))
        return {'status': 'REVIEW_REQUIRED' if review else 'SIGNATURE_MATCH', 'signature': self.name}


class FakeRuntime:
    def __init__(self, scanner=None, ready=True):
        self.scanner, self.ready, self.child = scanner or MarkerScanner(), ready, SimpleNamespace(pid=900)
        self.closed = False

    def maintain(self):
        return None

    def ensure_ready(self):
        return self.ready

    def health(self):
        return {'state': 'READY' if self.ready else 'LOADING_DATABASE'}

    def close(self):
        self.closed = True


def monitor_for(processes, scanner=None, enforce=True, own_pid=1):
    return ramscan.SignatureMonitor(FakeRuntime(scanner), RULES, own_pid=own_pid, enforce=enforce,
                                    pids=lambda: list(processes), process_factory=lambda pid: processes[pid],
                                    monotonic=lambda: 0.0)


def test_a_new_process_is_visited_first():
    monitor = monitor_for({})
    monitor.refresh([10, 11, 12])
    monitor.order.rotate(-2)
    monitor.refresh([10, 11, 12, 50])
    assert monitor.order[0] == 50
    monitor.refresh([11, 50])
    assert sorted(monitor.order) == [11, 50] and set(monitor.progress) == {11, 50}


def test_a_reproduced_signature_is_ram_106_and_the_process_is_stopped():
    target = FakeProcess(500, b'\0' * 4096 + b'SATSUMA-PROOF' + b'\0' * 4096)
    monitor = monitor_for({500: target})
    report = monitor.step()
    assert report['status'] == 'FINDING'
    assert target.terminated == 111
    (event,) = monitor.drain()
    assert event['kind'] == 'ram_signature_finding' and event['outcome'] == 'stopped'
    assert event['rule_id'] == 'SATSUMA-RAM-106' and event['indicator'] == 'ram_signature_match_v2'
    assert event['signature'] == 'Satsuma.Proof.UNOFFICIAL' and event['rule_stops'] is True
    assert monitor.counts['stopped'] == 1 and monitor.drain() == []


def test_a_heuristic_signature_is_ram_107_and_stops():
    # 2.2.38 (owner, 2026-11-13): RAM-107 stops too; nothing detected is only recorded.
    target = FakeProcess(500, b'SATSUMA-PROOF')
    monitor = monitor_for({500: target}, MarkerScanner(name='Heuristics.Encrypted.PDF'))
    monitor.step()
    (event,) = monitor.drain()
    assert event['rule_id'] == 'SATSUMA-RAM-107' and event['outcome'] == 'stopped' and event['rule_stops']
    assert target.terminated == 111


def test_a_scan_limit_is_counted_as_not_covered_and_is_no_finding():
    # GitHub's Windows server 2026-11-11: three svchost pieces hit MaxScanTime and were recorded as RAM-107.
    class Limited:
        def scan(self, payload, deadline):
            return {'status': 'LIMIT_EXCEEDED', 'signature': 'Heuristics.Limits.Exceeded.MaxScanTime'}
    target = FakeProcess(500, b'\0' * 8192, image='C:\\Windows\\System32\\svchost.exe')
    monitor = monitor_for({500: target}, Limited())
    report = monitor.step()
    assert report['findings'] == [] and report['scan_limit_exceeded'] >= 1
    assert report['coverage_state'] == 'INCOMPLETE' and monitor.drain() == []
    assert monitor.counts['scan_limits'] >= 1 and monitor.counts['findings'] == 0
    assert target.terminated is None


def test_bytes_that_changed_before_the_stop_are_not_stopped():
    # Found and confirmed inside the turn, but different when read again just before the stop.
    target = FakeProcess(500, b'SATSUMA-PROOF', change_after=2)
    monitor = monitor_for({500: target})
    monitor.step()
    (event,) = monitor.drain()
    assert event['outcome'] == 'refused' and event['detail'] == 'evidence_no_longer_matches'
    assert target.terminated is None


def test_a_critical_process_is_a_critical_alarm_and_a_foreign_clamd_is_stopped():
    # 2.2.38: a clamd that is not the service's own child is stopped like any program.
    critical = FakeProcess(500, b'SATSUMA-PROOF', critical=True)
    clamd = FakeProcess(501, b'SATSUMA-PROOF', image='C:\\Program Files\\Satsuma\\ClamAV\\clamd.exe')
    # The fake processes report parent 1; the service here is PID 7, so this clamd is foreign.
    monitor = monitor_for({500: critical, 501: clamd}, own_pid=7)
    monitor.step()
    monitor.step()
    events = monitor.drain()
    assert [e['outcome'] for e in events] == ['exempt', 'stopped']
    assert events[0]['exempt'] == 'windows_critical_process' and events[0]['alarm'] == 'critical'
    assert critical.terminated is None and clamd.terminated is not None


def test_the_services_own_clamd_child_is_not_stopped():
    own = FakeProcess(501, b'SATSUMA-PROOF', image='C:\\Program Files\\Satsuma\\ClamAV\\clamd.exe')
    monitor = monitor_for({501: own}, own_pid=1)
    monitor.step()
    (event,) = monitor.drain()
    assert event['outcome'] == 'exempt' and event['exempt'] == 'satsuma_clamav' and own.terminated is None


def test_without_enforcement_a_finding_is_only_recorded():
    target = FakeProcess(500, b'SATSUMA-PROOF')
    monitor = monitor_for({500: target}, enforce=False)
    monitor.step()
    assert monitor.drain()[0]['outcome'] == 'recorded' and target.terminated is None


def test_own_process_and_the_private_clamd_are_never_scanned():
    own, scanner_process = FakeProcess(1, b'SATSUMA-PROOF'), FakeProcess(900, b'SATSUMA-PROOF')
    monitor = monitor_for({1: own, 900: scanner_process}, own_pid=1)
    assert monitor.step() is None
    assert own.reads == 0 and scanner_process.reads == 0 and monitor.drain() == []


def test_nothing_is_scanned_until_clamd_is_ready_and_health_never_says_clean():
    target = FakeProcess(500, b'SATSUMA-PROOF')
    monitor = monitor_for({500: target})
    monitor.runtime.ready = False
    assert monitor.step() is None and target.reads == 0
    health = monitor.health()
    assert health['state'] == 'LOADING_DATABASE'
    assert health['full_ram_coverage'] is False and health['clean_verdict'] is False


def test_an_unreadable_process_is_counted_not_hidden():
    class Denied:
        def __enter__(self):
            raise PermissionError(5, 'OpenProcess')

        def __exit__(self, *exc):
            return False
    monitor = ramscan.SignatureMonitor(FakeRuntime(), RULES, own_pid=1, pids=lambda: [500],
                                       process_factory=lambda pid: Denied(), monotonic=lambda: 0.0)
    report = monitor.step()
    assert report['status'] == 'PROCESS_UNAVAILABLE' and report['error'] == 'PermissionError'
    assert monitor.health()['result_status_counts'] == {'PROCESS_UNAVAILABLE': 1}


def test_the_guard_records_what_the_scan_thread_found(tmp_path):
    class Monitor:
        enforce = True

        def __init__(self):
            self.closed = False

        def start(self):
            return self

        def drain(self):
            return [{'kind': 'ram_signature_finding', 'pid': 500, 'outcome': 'stopped'}]

        def health(self):
            return {'state': 'SCANNING'}

        def close(self):
            self.closed = True
    monitor = Monitor()
    guard = Guard(directory=tmp_path, echo=lambda *_: None, clock=lambda: 5.0,
                  signature_factory=lambda directory: monitor)
    assert guard.start_signatures() == {'ok': True, 'status': 'STARTED', 'enforce': True}
    (event,) = guard.check_signatures()
    assert event['kind'] == 'ram_signature_finding' and event['outcome'] == 'stopped'
    assert 'ram_signature_finding' in (tmp_path / 'events.jsonl').read_text()
    assert guard.save_state()['ram_signatures'] == {'state': 'SCANNING'}
    guard.stop()
    assert monitor.closed


def test_a_failing_scan_thread_start_is_reported_and_the_guard_goes_on(tmp_path):
    def broken(directory):
        raise RuntimeError('no rules')
    guard = Guard(directory=tmp_path, echo=lambda *_: None, signature_factory=broken)
    result = guard.start_signatures()
    assert result['ok'] is False and 'no rules' in result['error'] and guard.check_signatures() == []


@pytest.mark.skipif(os.name != 'nt', reason='reads a real Windows process')
def test_windows_process_reads_a_live_process_like_the_engine_expects():
    import ctypes
    import subprocess
    marker = b'SATSUMA-' + b'LIVE-READ-' + os.urandom(8).hex().encode()
    child = subprocess.Popen([sys.executable, '-c', 'import sys,time; b=bytearray(sys.stdin.buffer.readline()); '
                              'print(id(b), flush=True); time.sleep(60)'],
                             stdin=subprocess.PIPE, stdout=subprocess.PIPE)
    try:
        child.stdin.write(marker + b'\n')
        child.stdin.flush()
        child.stdout.readline()
        from satsuma.ram.proc import parse_maps
        with ramscan.WindowsProcess(child.pid) as process:
            identity, maps = process.snapshot()
            assert identity[0] == child.pid and identity[2].lower().endswith('.exe')
            regions = parse_maps(maps)
            assert regions and all(r.end > r.start for r in regions)
            found = False
            for region in regions:
                if 'w' not in region.perms or region.end - region.start > 64 << 20:
                    continue
                for offset in range(region.start, region.end, 1 << 20):
                    try:
                        if marker in process.read(offset, min(1 << 20, region.end - offset)):
                            found = True
                            break
                    except OSError:
                        break
                if found:
                    break
            assert found
            assert process.info()['critical'] is False
    finally:
        child.kill()
    del ctypes
