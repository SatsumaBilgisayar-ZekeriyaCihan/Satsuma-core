"""Stage 36: real post-exec identity and bounded Exec Guard UI records."""
import subprocess
import sys
import time
from pathlib import Path

import pytest
from satsuma import app_firewall, exec_guard_view, python_entry


def _start(script):
    return subprocess.Popen([sys.executable, str(script)], cwd=str(script.parent),
                            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)


def test_two_python_scripts_have_distinct_verified_app_keys(tmp_path):
    a=tmp_path/'alpha.py'; b=tmp_path/'beta.py'
    a.write_text('import time\ntime.sleep(30)\n')
    b.write_text('import time\ntime.sleep(31)\n')
    procs=[_start(a),_start(b)]
    try:
        time.sleep(0.15)
        id1=app_firewall.identity(procs[0].pid)
        id2=app_firewall.identity(procs[1].pid)
        assert id1['python_entry']['status']=='verified',id1
        assert id2['python_entry']['status']=='verified',id2
        assert id1['python_entry']['path']==str(a)
        assert id2['python_entry']['path']==str(b)
        assert id1['application_key']!=id2['application_key']
        assert id1['identity_verified'] and id2['identity_verified']
    finally:
        for p in procs: p.terminate()
        for p in procs: p.wait(timeout=5)


def test_python_command_string_never_leaks_or_gets_persistent_app_grant():
    class FakeProc:
        pid=123
        def create_time(self):return 1
        def exe(self):return '/usr/bin/python3'
        def cwd(self):return '/tmp'
        def cmdline(self):return ['/usr/bin/python3','-c','secret-password-123']
    result=python_entry.resolve(FakeProc(),'/usr/bin/python3')
    assert result == {'status':'unverified', 'reason':'command_or_module'}
    assert 'secret-password' not in str(result)


def test_exec_guard_view_tracks_denied_launch_not_terminated_process(tmp_path):
    path=tmp_path/'events.jsonl'
    path.write_text('{"time":100,"kind":"build_tool_refused","pid":456,"path":"/usr/bin/gcc","process_name":"gcc"}\n'
                    '{"time":101,"kind":"build_tool_allowed","pid":500,"process_name":"make"}\n')
    denied=exec_guard_view.events(path,kind='refused')
    assert denied['count']==1
    assert denied['items'][0]['proc_dir']=='/proc/456'
    assert denied['items'][0]['action']=='Çalıştırma engellendi'
    assert 'terminated' not in str(denied)
    allowed=exec_guard_view.events(path,kind='allowed')
    assert 'Teyit Edildi' in allowed['items'][0]['action']


def test_log_reader_malformed_and_missing_not_silent_success(tmp_path):
    assert exec_guard_view.events(tmp_path/'missing')['status']=='UNAVAILABLE'
    path=tmp_path/'log'
    path.write_text('{bad json\n{"kind":"build_tool_refused","pid":"notpid"}\n')
    assert exec_guard_view.events(path)['items']==[]
