"""Windows memory protection: indicators, the shared decision, stopping through the read handle, exemptions.

Windows bellek koruması: göstergeler, ortak karar, okunan tutamaçla durdurma, muaf süreçler.
"""
from contextlib import contextmanager

from satsuma import memory_decision
from satsuma_win import memory
from satsuma_win.guard import Guard

RULES = memory_decision.load_rules()
RWX_PRIVATE = {'base': 0x1000, 'size': 4096, 'state': memory.MEM_COMMIT, 'protect': 0x40,
               'type': memory.MEM_PRIVATE, 'file': None}
RWX_SHARED = {**RWX_PRIVATE, 'type': memory.MEM_MAPPED}
TEMP_DLL = {'base': 0x7000, 'size': 4096, 'state': memory.MEM_COMMIT, 'protect': 0x20, 'type': memory.MEM_IMAGE,
            'file': 'C:\\Users\\ali\\AppData\\Local\\Temp\\x\\evil.dll'}
SYSTEM_DLL = {**TEMP_DLL, 'file': 'C:\\Windows\\System32\\kernel32.dll'}


def info(pid=500, regions=(), image='C:\\Program Files\\App\\app.exe', **extra):
    return {'pid': pid, 'created': 111, 'image': image, 'image_exists': True, 'debugged': False,
            'critical': False, 'parent': 1, 'regions': list(regions), **extra}


def test_writable_and_executable_memory_without_a_file_is_ram_001_private_or_shared():
    assert memory.indicators(info(regions=[RWX_PRIVATE])) == ['anonymous_rwx']
    assert memory.indicators(info(regions=[RWX_SHARED])) == ['anonymous_rwx']
    assert memory.indicators(info(regions=[{**RWX_SHARED, 'file': 'C:\\data\\x.bin'}])) == []
    assert memory.indicators(info(regions=[{**RWX_PRIVATE, 'protect': 0x20}])) == []
    assert memory.indicators(info(regions=[{**RWX_PRIVATE, 'state': 0x2000}])) == []


def test_code_from_a_folder_anyone_can_write_is_ram_008_system_code_is_not():
    assert memory.indicators(info(regions=[TEMP_DLL])) == ['writable_dir_code_mapping']
    assert memory.indicators(info(image='C:\\Windows\\Temp\\drop.exe')) == ['writable_dir_code_mapping']
    assert memory.indicators(info(image='c:/users/public/x.exe')) == ['writable_dir_code_mapping']
    assert memory.indicators(info(regions=[SYSTEM_DLL])) == []


def test_a_missing_program_file_and_an_attached_debugger_are_named():
    assert memory.indicators(info(image_exists=False, debugged=True)) == ['deleted_executable', 'process_traced']


def test_windows_words_are_the_linux_rule_words():
    for word in ('anonymous_rwx', 'writable_dir_code_mapping', 'deleted_executable', 'process_traced'):
        assert word in RULES
    stops = {word: memory_decision.decide(word, RULES)['stop'] for word in RULES}
    # 2.2.38 (owner, 2026-11-13): every memory detection stops the process, on both platforms.
    assert stops['anonymous_rwx'] and stops['writable_dir_code_mapping']
    assert stops['deleted_executable'] and stops['process_traced']


class Process:
    def __init__(self, data, fail=None):
        self.data, self.fail, self.terminated = data, fail, None

    def read(self):
        return self.data

    def terminate(self, created):
        if self.fail:
            raise OSError(self.fail)
        self.terminated = created


class Reader:
    def __init__(self, processes):
        self.processes = processes

    def pids(self):
        return list(self.processes)

    @contextmanager
    def open(self, pid):
        yield self.processes.get(pid)


def scanner(processes, own_pid=1, enforce=True):
    events = []
    record = lambda kind, **fields: events.append((kind, fields)) or fields
    return memory.Scanner(RULES, Reader(processes), record, own_pid=own_pid, enforce=enforce), events


def test_a_process_with_rwx_memory_is_stopped_through_its_handle_and_recorded():
    target = Process(info(regions=[RWX_PRIVATE]))
    scan, events = scanner({500: target})
    scan.scan()
    assert target.terminated == 111
    kind, fields = events[0]
    assert kind == 'memory_finding' and fields['rule_id'] == 'SATSUMA-RAM-001' and fields['outcome'] == 'stopped'
    assert fields['regions'][0]['protect'] == '0x40'
    scan.scan()
    assert len(events) == 1, 'the same process and finding is recorded once'


def test_a_traced_process_is_stopped_not_only_recorded():
    # 2.2.38: RAM-009 stops (owner, 2026-11-13: nothing detected is only recorded).
    target = Process(info(debugged=True))
    scan, events = scanner({500: target})
    scan.scan()
    assert target.terminated == 111 and events[0][1]['outcome'] == 'stopped'
    assert events[0][1]['rule_id'] == 'SATSUMA-RAM-009'


def test_a_failed_stop_is_recorded_never_hidden():
    scan, events = scanner({500: Process(info(regions=[RWX_PRIVATE]), fail='access denied')})
    scan.scan()
    assert events[0][1]['outcome'] == 'stop_failed' and 'access denied' in events[0][1]['error']
    assert scan.counts['stop_failed'] == 1


def test_only_a_critical_process_and_satsumas_own_children_are_not_stopped():
    # 2.2.38 (owner, 2026-11-13): remote support, the desktop, Defender and Sysmon are stopped
    # like any program; a critical process raises a critical alarm.
    cases = {
        600: info(600, [RWX_PRIVATE], critical=True),
        601: info(601, [RWX_PRIVATE], image='C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe',
                  parent=1),
        603: info(603, [RWX_PRIVATE], image='C:\\Program Files\\Satsuma\\ClamAV\\clamd.exe', parent=1),
    }
    processes = {pid: Process(data) for pid, data in cases.items()}
    scan, events = scanner(processes)
    scan.scan()
    assert all(p.terminated is None for p in processes.values())
    assert sorted(f['exempt'] for _, f in events) == ['satsuma_clamav', 'satsuma_powershell', 'windows_critical_process']
    assert [f.get('alarm') for _, f in events if f['exempt'] == 'windows_critical_process'] == ['critical']


def test_remote_support_desktop_and_security_programs_are_stopped():
    for image in ('C:\\Program Files\\TeamViewer\\TeamViewer.exe', 'C:\\Program Files (x86)\\AnyDesk\\AnyDesk.exe',
                  'C:\\Windows\\explorer.exe', 'C:\\Windows\\System32\\dwm.exe',
                  'C:\\Program Files\\Windows Defender\\MsMpEng.exe', 'C:\\Windows\\Sysmon64.exe',
                  # a clamd that is not the service's own child, or outside its folder
                  'C:\\Program Files\\Satsuma\\ClamAV\\clamd.exe', 'C:\\Users\\a\\clamd.exe'):
        target = Process(info(610, [RWX_PRIVATE], image=image, parent=999))
        scan, events = scanner({610: target})
        scan.scan()
        assert target.terminated is not None and events[0][1]['outcome'] == 'stopped', image


def test_a_lookalike_outside_its_location_or_another_parents_powershell_is_stopped():
    cases = {
        700: info(700, [RWX_PRIVATE], image='C:\\Users\\ali\\Downloads\\TeamViewer.exe'),
        701: info(701, [RWX_PRIVATE], image='C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe',
                  parent=999),
    }
    processes = {pid: Process(data) for pid, data in cases.items()}
    scanner(processes)[0].scan()
    assert all(p.terminated == 111 for p in processes.values())


def test_report_mode_stops_nothing_and_unreadable_processes_are_counted():
    target = Process(info(regions=[RWX_PRIVATE]))
    scan, events = scanner({500: target, 501: None}, enforce=False)
    scan.scan()
    assert target.terminated is None and events[0][1]['outcome'] == 'recorded'
    assert scan.counts['unreadable'] == 1 and scan.counts['scanned'] == 1


def test_guard_scans_memory_and_reports_a_reader_that_cannot_start(tmp_path):
    target = Process(info(regions=[RWX_PRIVATE]))
    fake = lambda record, directory, key: memory.Scanner(RULES, Reader({500: target}), record, own_pid=1)
    ok = lambda argv, **kw: __import__('types').SimpleNamespace(returncode=0, stdout='{}', stderr='')
    guard = Guard(runner=ok, read=lambda: [], directory=tmp_path, echo=lambda *_: None, memory_factory=fake)
    guard.start()
    assert guard.startup['memory']['status'] == 'ACTIVE'
    guard.check_memory()
    assert target.terminated == 111

    def broken(record, directory, key):
        raise OSError('no reader')
    guard = Guard(runner=ok, read=lambda: [], directory=tmp_path, echo=lambda *_: None, memory_factory=broken)
    guard.start()
    assert guard.startup['memory']['ok'] is False and 'no reader' in guard.startup['memory']['error']
    assert '"startup_memory"' in (tmp_path / 'events.jsonl').read_text()


@__import__('pytest').mark.skipif(__import__('os').name != 'nt', reason='Win32 layer runs only on Windows')
def test_win32_reader_reads_a_live_process_and_finds_a_real_rwx_child(tmp_path):
    """On GitHub's Windows server: the real reader, a real harmless child, a real stop.

    GitHub'ın Windows sunucusunda: gerçek okuyucu, gerçek zararsız alt süreç, gerçek durdurma.
    """
    import os
    import subprocess
    import sys
    import time
    from pathlib import Path
    reader = memory.Win32Reader()
    with reader.open(os.getpid()) as own:
        data = own.read()
    assert data['image'].lower().endswith('python.exe') and data['regions'] and data['created']
    script = Path(__file__).resolve().parents[1] / 'proof' / 'memory_targets.py'
    pid_file = tmp_path / 'pid'
    child = subprocess.Popen([sys.executable, str(script), 'rwx_private', str(pid_file)])
    thread_child = None
    try:
        for _ in range(100):
            if pid_file.exists() and pid_file.read_text():
                break
            time.sleep(0.1)
        with reader.open(child.pid) as process:
            assert memory.executing_from_fileless(process.read()) == []
        thread_pid = tmp_path / 'thread_pid'
        thread_child = subprocess.Popen([sys.executable, str(script), 'rwx_thread', str(thread_pid)])
        for _ in range(100):
            if thread_pid.exists() and thread_pid.read_text():
                break
            time.sleep(0.1)
        with reader.open(thread_child.pid) as process:
            assert memory.executing_from_fileless(process.read()), 'the reader sees the thread started in RWX memory'
        events = []
        scan = memory.Scanner(RULES, reader, lambda kind, **f: events.append(f) or f)
        scan.scan([child.pid])
        assert [e['rule_id'] for e in events] == ['SATSUMA-RAM-001'] and events[0]['outcome'] == 'stopped'
        assert child.wait(timeout=10) == 0xC5A75A
    finally:
        for process in (child, thread_child):
            if process is not None and process.poll() is None:
                process.kill()


SIGNED_TEMP = {**info(regions=[TEMP_DLL]), 'temp_signed': True}


def test_signed_code_in_temp_is_recorded_unsigned_is_stopped():
    """Owner's decision 2026-11-11. Sahibinin kararı: imzalı kaydedilir, imzasız durdurulur."""
    signed, unsigned = Process(SIGNED_TEMP), Process({**SIGNED_TEMP, 'pid': 501, 'temp_signed': False})
    scan, events = scanner({500: signed, 501: unsigned})
    scan.scan()
    assert signed.terminated is None and unsigned.terminated == 111
    by_pid = {f['pid']: f for _, f in events}
    assert by_pid[500]['outcome'] == 'recorded' and by_pid[500]['kept'] == 'signed_publisher'
    assert by_pid[501]['outcome'] == 'stopped' and 'kept' not in by_pid[501]


def test_a_signature_never_excuses_rwx_memory():
    target = Process({**info(regions=[TEMP_DLL, RWX_PRIVATE]), 'temp_signed': True})
    scanner({500: target})[0].scan()
    assert target.terminated == 111


def machine(tmp_path):
    from satsuma_win import machine_key
    return machine_key.ensure(tmp_path / 'key', protect=lambda b: b[::-1], unprotect=lambda b: b[::-1])[0]


def test_only_an_approved_unexpired_satsuma_setup_runs_from_temp(tmp_path):
    key = machine(tmp_path)
    digest = 'ab' * 32
    setup = {**info(image='C:\\Users\\ali\\AppData\\Local\\Temp\\is-1.tmp\\setup.tmp'), 'temp_signed': False,
             'image_sha256': 'cd' * 32, 'parent_sha256': digest}
    now = [1000.0]
    memory.approve_setup(tmp_path, digest, key, minutes=30, clock=lambda: now[0])
    approvals = lambda: memory.load_approvals(tmp_path, key, clock=lambda: now[0])
    events = []
    approved = Process(setup)
    memory.Scanner(RULES, Reader({500: approved}), lambda k, **f: events.append(f) or f, own_pid=1,
                   approvals=approvals).scan()
    assert approved.terminated is None and events[0]['kept'] == 'approved_satsuma_setup'
    now[0] += 31 * 60
    late = Process({**setup, 'pid': 502})
    memory.Scanner(RULES, Reader({502: late}), lambda k, **f: f, own_pid=1, approvals=approvals).scan()
    assert late.terminated == 111, 'an expired approval approves nothing'
    other = Process({**setup, 'pid': 503, 'parent_sha256': 'ef' * 32})
    memory.Scanner(RULES, Reader({503: other}), lambda k, **f: f, own_pid=1,
                   approvals=lambda: memory.load_approvals(tmp_path, key, clock=lambda: 1000.0)).scan()
    assert other.terminated == 111, 'another setup is not approved'


def test_a_malformed_or_hand_written_approval_approves_nothing(tmp_path):
    import json
    import pytest
    key = machine(tmp_path)
    for bad in ('not-a-hash', 'ab' * 31):
        with pytest.raises(ValueError):
            memory.approve_setup(tmp_path, bad, key)
    with pytest.raises(ValueError):
        memory.approve_setup(tmp_path, 'ab' * 32, key, minutes=600)
    hand = [{'sha256': 'ab' * 32, 'expires': 9e18}, {'sha256': 'ab' * 32, 'expires': 9e18, 'signature': 'A' * 88},
            'x', {'sha256': 'zz', 'expires': 9e18}]
    (tmp_path / memory.APPROVALS).write_text(json.dumps(hand))
    assert memory.load_approvals(tmp_path, key) == frozenset()
    memory.approve_setup(tmp_path, 'cd' * 32, key)
    rows = json.loads((tmp_path / memory.APPROVALS).read_text())
    rows[-1]['expires'] += 3600            # a later expiry breaks the signature
    (tmp_path / memory.APPROVALS).write_text(json.dumps(rows))
    assert memory.load_approvals(tmp_path, key) == frozenset()
    assert memory.load_approvals(tmp_path, None) == frozenset()


def test_machine_key_is_created_once_and_never_stored_in_clear(tmp_path):
    from satsuma_win import machine_key
    protect, unprotect = (lambda b: b'P' + b[::-1]), (lambda b: b[1:][::-1])
    first, created = machine_key.ensure(tmp_path, protect=protect, unprotect=unprotect)
    again, created_again = machine_key.ensure(tmp_path, protect=protect, unprotect=unprotect)
    assert created and not created_again and first.public_bytes == again.public_bytes
    stored = (tmp_path / machine_key.PRIVATE).read_bytes()
    assert stored.startswith(b'P'), 'the private key is written only through the protector'
    assert again.verify(b'x', first.sign(b'x')) and not again.verify(b'y', first.sign(b'x'))
    (tmp_path / machine_key.PUBLIC).write_text('AAAA' * 11 + '\n')
    import pytest
    with pytest.raises(ValueError):
        machine_key.ensure(tmp_path, protect=protect, unprotect=unprotect)


def test_temp_files_are_the_image_and_each_writable_folder_mapping():
    data = info(image='C:\\Users\\Public\\a.exe', regions=[TEMP_DLL, SYSTEM_DLL])
    assert memory.temp_files(data) == {'C:\\Users\\Public\\a.exe', TEMP_DLL['file']}


@__import__('pytest').mark.skipif(__import__('os').name != 'nt', reason='DPAPI runs only on Windows')
def test_machine_key_with_real_dpapi(tmp_path):
    from satsuma_win import machine_key
    key, created = machine_key.ensure(tmp_path, protect=machine_key.dpapi_protect,
                                      unprotect=machine_key.dpapi_unprotect)
    again, created_again = machine_key.ensure(tmp_path, protect=machine_key.dpapi_protect,
                                              unprotect=machine_key.dpapi_unprotect)
    assert created and not created_again and key.public_bytes == again.public_bytes
    assert again.verify(b'satsuma', key.sign(b'satsuma'))


def test_rwx_in_a_program_files_process_is_recorded_unless_a_thread_starts_there():
    """Owner's decision 2026-11-11: .NET JIT memory is recorded; code running from it is stopped."""
    jit = Process({**info(regions=[RWX_PRIVATE], image='C:\\Program Files\\PowerShell\\7\\pwsh.exe'),
                   'thread_starts': [0x7FF0000]})
    injected = Process({**info(pid=501, regions=[RWX_PRIVATE], image='C:\\Program Files\\PowerShell\\7\\pwsh.exe'),
                        'thread_starts': [0x7FF0000, RWX_PRIVATE['base'] + 16]})
    scan, events = scanner({500: jit, 501: injected})
    scan.scan()
    by_pid = {f['pid']: f for _, f in events}
    assert jit.terminated is None and by_pid[500]['kept'] == 'no_thread_from_fileless_memory'
    assert injected.terminated == 111 and by_pid[501]['stop_reason'] == 'thread_started_from_fileless_memory'
    assert by_pid[501]['thread_starts'] == [hex(RWX_PRIVATE['base'] + 16)]


def test_rwx_in_a_program_outside_windows_and_program_files_is_stopped():
    for image in ('C:\\Users\\ali\\AppData\\Local\\App\\app.exe', 'D:\\tools\\app.exe', None):
        target = Process({**info(regions=[RWX_PRIVATE], image=image), 'thread_starts': [0x7FF0000]})
        scan, events = scanner({500: target})
        scan.scan()
        assert target.terminated == 111, image
        assert events[0][1]['stop_reason'] == 'program_not_in_expected_location'


def test_a_thread_in_private_rx_memory_counts_as_running_from_fileless_memory():
    rx = {**RWX_PRIVATE, 'base': 0x9000, 'protect': 0x20}
    data = {**info(regions=[RWX_PRIVATE, rx, SYSTEM_DLL]), 'thread_starts': [0x9010, SYSTEM_DLL['base'] + 4]}
    assert memory.executing_from_fileless(data) == [0x9010]


def test_an_approved_location_counts_as_expected_and_a_hand_written_one_does_not(tmp_path):
    import json
    key = machine(tmp_path)
    memory.approve_location(tmp_path, 'C:\\actions-runner', key)
    assert memory.load_locations(tmp_path, key) == ('c:\\actions-runner\\',)
    assert memory.expected_location('C:\\actions-runner\\bin\\Runner.Worker.exe', memory.load_locations(tmp_path, key))
    assert not memory.expected_location('C:\\actions-runner-evil\\x.exe', memory.load_locations(tmp_path, key))
    rows = json.loads((tmp_path / memory.LOCATIONS).read_text())
    rows.append({'folder': 'c:\\users\\', 'signature': rows[0]['signature']})
    (tmp_path / memory.LOCATIONS).write_text(json.dumps(rows))
    assert memory.load_locations(tmp_path, key) == ('c:\\actions-runner\\',)
    assert memory.load_locations(tmp_path, None) == ()


def test_jit_memory_in_an_approved_folder_is_recorded_but_a_thread_from_it_is_stopped(tmp_path):
    key = machine(tmp_path)
    memory.approve_location(tmp_path, 'C:\\actions-runner', key)
    image = 'C:\\actions-runner\\bin\\Runner.Worker.exe'
    jit = Process({**info(regions=[RWX_PRIVATE], image=image), 'thread_starts': [0x7FF0000]})
    shell = Process({**info(pid=501, regions=[RWX_PRIVATE], image=image), 'thread_starts': [RWX_PRIVATE['base']]})
    memory.Scanner(RULES, Reader({500: jit, 501: shell}), lambda k, **f: f, own_pid=1,
                   locations=lambda: memory.load_locations(tmp_path, key)).scan()
    assert jit.terminated is None and shell.terminated == 111


def test_install_approvals_are_signed_only_on_the_first_start(tmp_path):
    from satsuma_win import service
    exe = tmp_path / 'provjobd.exe'
    exe.write_bytes(b'MZ provisioner')
    service.write_install_approvals(tmp_path, ['C:\\WindowsAzure'], [exe])
    key = machine(tmp_path)
    done = memory.apply_install_approvals(tmp_path, key, created=True)
    assert done['locations'] == ['c:\\windowsazure\\'] and len(done['setups']) == 1
    assert memory.load_locations(tmp_path, key) == ('c:\\windowsazure\\',)
    assert __import__('hashlib').sha256(b'MZ provisioner').hexdigest() in memory.load_approvals(tmp_path, key)
    assert not (tmp_path / memory.PENDING).exists()
    service.write_install_approvals(tmp_path, ['C:\\Users'], [])
    ignored = memory.apply_install_approvals(tmp_path, key, created=False)
    assert ignored['ignored'] and memory.load_locations(tmp_path, key) == ('c:\\windowsazure\\',)
    assert not (tmp_path / memory.PENDING).exists()


def test_install_flags_are_parsed_and_unknown_ones_refused():
    import pytest
    from satsuma_win.guard import install_approvals
    assert install_approvals(['--approve-location', 'C:\\a', '--approve-file', 'C:\\b.exe']) == {
        'locations': ['C:\\a'], 'files': ['C:\\b.exe']}
    with pytest.raises(ValueError):
        install_approvals(['--approve-everything'])
    with pytest.raises(ValueError):
        memory.approve_location('.', 'relative\\folder', None)


def test_the_one_file_launcher_of_satsuma_itself_is_never_stopped():
    import os
    launcher = info(pid=os.getppid(), regions=[RWX_PRIVATE],
                    image='C:\\Users\\a\\AppData\\Local\\Temp\\x.zip.f87\\satsuma-core-windows.exe')
    assert memory.exemption(launcher, own_pid=1) == 'satsuma_service'
    lookalike = {**launcher, 'pid': 99999}
    assert memory.exemption(lookalike, own_pid=1) is None


def test_double_click_without_arguments_does_not_start_the_guard(monkeypatch, capsys):
    from satsuma_win import guard as guard_module
    monkeypatch.setattr(guard_module, 'is_admin', lambda: True)
    started = []
    monkeypatch.setattr(guard_module, 'Guard', lambda *a, **k: started.append(1))
    assert guard_module.main([]) == 2 and started == []
    assert '--install' in capsys.readouterr().out


def test_a_key_this_account_cannot_open_is_kept_aside_and_a_new_one_created(tmp_path):
    from satsuma_win import machine_key
    first, _ = machine_key.ensure(tmp_path, protect=lambda b: b'P' + b, unprotect=lambda b: b[1:])
    def foreign(data):
        raise OSError(3, 'CryptUnprotectData', 'Sistem belirtilen yolu bulamıyor.')
    second, created = machine_key.ensure(tmp_path, protect=lambda b: b'Q' + b, unprotect=foreign)
    assert created and second.replaced and second.public_bytes != first.public_bytes
    kept = list(tmp_path.glob('unreadable-*'))
    assert len(kept) == 2, 'the old key and its public key are kept, never deleted'
    third, created_again = machine_key.ensure(tmp_path, protect=lambda b: b'Q' + b, unprotect=lambda b: b[1:])
    assert not created_again and third.public_bytes == second.public_bytes
