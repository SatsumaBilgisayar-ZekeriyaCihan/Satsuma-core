"""The Windows service "Satsuma Core": automatic, LocalSystem, restarted after a failure; never from a writable folder.

"Satsuma Core" Windows hizmeti: otomatik, LocalSystem, hatadan sonra yeniden başlar; yazılabilir klasörden asla.
"""
import json
from types import SimpleNamespace

import pytest

from satsuma_win import firewall, service
from satsuma_win.guard import run_loop


def answering(payload):
    calls = []
    def run(argv, **kwargs):
        assert argv[:-1] == firewall.POWERSHELL
        calls.append(argv[-1])
        return SimpleNamespace(returncode=0, stdout=json.dumps(payload), stderr='')
    run.calls = calls
    return run


OWNED = lambda tmp: {'owner': 'S-1-5-21-1-2-3-1001', 'directory': tmp}
RUNNING = {'ok': True, 'status': 'Running', 'start': 'Auto', 'account': 'LocalSystem',
           'program': '"C:\\Program Files\\Satsuma\\satsuma-core-windows.exe" --service', 'restarts': 3}


@pytest.mark.parametrize('bad', ['C:\\x\\run.bat', 'C:\\x\\a.exe\nRemove-Item C:\\', ''])
def test_only_an_exe_can_be_installed(bad):
    with pytest.raises(ValueError):
        service.install_script(bad)


def test_a_quote_in_the_path_cannot_end_the_powershell_string():
    script = service.install_script("C:\\Users\\O'Brien\\Downloads\\satsuma-core-windows.exe")
    assert "'C:\\Users\\O''Brien\\Downloads\\satsuma-core-windows.exe'" in script


def test_service_is_automatic_localsystem_with_restart_and_replaces_the_old_task():
    script = service.install_script('C:\\Satsuma\\satsuma-core-windows.exe')
    for part in ("New-Service -Name 'SatsumaCore'", '-StartupType Automatic', "StartName='LocalSystem'",
                 'actions= restart/60000/restart/60000/restart/60000', 'failureflag SatsumaCore 1',
                 "Unregister-ScheduledTask -TaskPath '\\Satsuma\\' -TaskName 'Satsuma Core'",
                 "Join-Path $env:ProgramFiles 'Satsuma'", '--service'):
        assert part in script, part
    for sid in service.TRUSTED_SIDS:
        assert sid in script
    assert 'catch { $sid = $ace.IdentityReference.Value }' in script


@pytest.mark.parametrize('field,value', [('status', 'Stopped'), ('start', 'Manual'), ('account', 'NT AUTHORITY\\LocalService'),
                                         ('program', 'C:\\Users\\x\\satsuma-core-windows.exe --service'),
                                         ('program', '"C:\\Program Files\\Satsuma\\satsuma-core-windows.exe"'),
                                         ('restarts', 0)])
def test_install_is_ok_only_when_every_setting_reads_back(field, value, tmp_path):
    assert service.install('C:\\Satsuma\\satsuma-core-windows.exe', answering(RUNNING), **OWNED(tmp_path))['ok'] is True
    assert service.install('C:\\Satsuma\\satsuma-core-windows.exe', answering({**RUNNING, field: value}), **OWNED(tmp_path))['ok'] is False


def test_a_writable_program_folder_refuses_the_install(tmp_path):
    unsafe = {'ok': False, 'status': 'UNSAFE_FOLDER', 'writable': ['BUILTIN\\Users:Modify']}
    result = service.install('C:\\Satsuma\\satsuma-core-windows.exe', answering(unsafe), **OWNED(tmp_path))
    assert result['ok'] is False and result['status'] == 'UNSAFE_FOLDER'


def test_uninstall_is_confirmed_by_the_service_being_gone():
    assert service.uninstall(answering({'ok': False, 'status': 'NOT_INSTALLED'}))['ok'] is True
    assert service.uninstall(answering(RUNNING))['ok'] is False


def test_uninstall_waits_for_the_stop_and_asks_again_after_an_empty_answer():
    import json
    from types import SimpleNamespace
    assert "WaitForStatus('Stopped'" in service.uninstall_script()
    answers = iter(['\r\n', '', json.dumps({'ok': False, 'status': 'NOT_INSTALLED'})])
    waits = []
    runner = lambda argv, **kw: SimpleNamespace(returncode=0, stdout=next(answers), stderr='')
    assert service.uninstall(runner, wait=waits.append)['ok'] is True and waits == [5, 5]
    empty = lambda argv, **kw: SimpleNamespace(returncode=0, stdout='\r\n', stderr='')
    assert service.uninstall(empty, wait=lambda s: None) == {'ok': False, 'status': 'NO_ANSWER'}


def test_the_loop_ends_cleanly_on_a_stop_request_and_records_it():
    class Guard:
        polls, events = 0, []
        def poll(self):
            self.polls += 1
            if self.polls == 2:
                raise RuntimeError('boom')
        def record(self, kind, **fields):
            self.events.append(kind)
        def stop(self):
            self.events.append('stopped')
    guard = Guard()
    requests = iter([False, False, True])
    run_loop(guard, lambda seconds: next(requests))
    assert guard.polls == 3 and guard.events == ['guard_error', 'stop_requested', 'stopped']


def test_service_host_is_wired_to_the_same_loop():
    text = (service.__file__.replace('service.py', 'winservice.py'))
    source = open(text, encoding='utf-8').read()
    assert "_svc_name_ = SERVICE_NAME" in source and 'run_loop(guard' in source
    assert service.SERVICE_NAME == 'SatsumaCore'


def test_main_writes_turkish_text_to_a_cp1252_console(monkeypatch):
    import io
    import sys
    from satsuma_win import guard
    raw = io.BytesIO()
    console = io.TextIOWrapper(raw, encoding='cp1252')
    monkeypatch.setattr(sys, 'stdout', console)
    monkeypatch.setattr(sys, 'stderr', console)
    monkeypatch.setattr(guard, 'is_admin', lambda: False)
    assert guard.main([]) == 1          # prints "Yönetici olarak çalıştırın" (ı is not in cp1252)
    console.flush()
    assert 'çalıştırın'.encode('utf-8') in raw.getvalue()


def test_powershell_never_inherits_powershell_7_module_path():
    env = firewall.powershell_environment({'PSModulePath': 'C:\\pwsh7\\Modules', 'Path': 'C:\\Windows', 'psmodulepath': 'x'})
    assert env == {'Path': 'C:\\Windows'}
    seen = {}
    def run(argv, **kwargs):
        seen.update(kwargs)
        return SimpleNamespace(returncode=0, stdout='', stderr='')
    firewall.run_powershell('Get-Date', run)
    assert 'env' in seen and not any(k.upper() == 'PSMODULEPATH' for k in seen['env'])


def test_localised_console_output_never_breaks_reading():
    import sys
    result = firewall.safe_run([sys.executable, '-c', 'import sys; sys.stdout.buffer.write(bytes([0x8d, 0x41]))'],
                               capture_output=True, text=True)
    assert result.returncode == 0 and 'A' in result.stdout
    script = []
    firewall.run_powershell('Get-Date', lambda argv, **kw: script.append(argv[-1]) or SimpleNamespace(
        returncode=0, stdout='', stderr=''))
    assert script[0].startswith(firewall.UTF8_OUTPUT)
