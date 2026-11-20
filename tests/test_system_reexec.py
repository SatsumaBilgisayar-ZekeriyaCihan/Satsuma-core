"""2.2.65 (field 2026-11-18): bootc running its own /tmp copy was FILELESS-002 90 times."""
import shutil

from satsuma import system_reexec as sr


def _proc(tmp_path, pid, content):
    d = tmp_path / 'proc' / str(pid)
    d.mkdir(parents=True)
    (d / 'exe').write_bytes(content)
    return tmp_path / 'proc'


def test_an_exact_copy_of_bootc_is_bootc(tmp_path, monkeypatch):
    tool = tmp_path / 'bootc'
    tool.write_bytes(b'\x7fELF bootc binary')
    monkeypatch.setattr(sr, 'TOOLS', (str(tool),))
    proc = _proc(tmp_path, 4242, tool.read_bytes())
    event = {'exe': '/tmp/.tmp7Ffrcz', 'pid': 4242, 'cmd': 'bootc status --format=json --format-version=1'}
    assert sr.is_tool_copy(event, proc)
    assert sr.is_tool_copy({**event, 'exe': '/tmp/.tmp7Ffrcz (deleted)'}, proc)


def test_name_or_command_line_alone_is_never_enough(tmp_path, monkeypatch):
    tool = tmp_path / 'bootc'
    tool.write_bytes(b'\x7fELF bootc binary')
    monkeypatch.setattr(sr, 'TOOLS', (str(tool),))
    proc = _proc(tmp_path, 4243, b'\x7fELF something else')
    event = {'exe': '/tmp/.tmpABCDEF', 'pid': 4243, 'cmd': 'bootc status --format=json'}
    assert not sr.is_tool_copy(event, proc)                       # different content
    assert not sr.is_tool_copy({**event, 'pid': 9999}, proc)      # process gone: finding stays
    assert not sr.is_tool_copy({**event, 'exe': '/dev/shm/.tmpABCDEF'}, proc)
    assert not sr.is_tool_copy({**event, 'exe': '/tmp/evil'}, proc)
