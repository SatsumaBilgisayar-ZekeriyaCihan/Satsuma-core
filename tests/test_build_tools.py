"""The compile tool block decides the same on Linux and Windows (owner's decision 2026-11-11).

Derleme aracı engeli Linux ve Windows'ta aynı kararı verir.
"""
import pytest

from satsuma import build_tools


@pytest.mark.parametrize('path,tool', [
    ('/usr/bin/gcc', 'gcc'), ('/usr/bin/x86_64-redhat-linux-gcc', 'gcc'), ('/usr/bin/gcc-14', 'gcc'),
    ('/usr/bin/cc', 'cc'), ('/usr/bin/c++', 'c++'), ('/usr/bin/g++', 'g++'), ('/usr/bin/clang-18', 'clang'),
    ('/usr/bin/as', 'as'), ('/usr/bin/ld.bfd', 'ld.bfd'), ('/usr/bin/ld.gold', 'ld.gold'), ('/usr/bin/gold', 'gold'),
    ('/usr/bin/make', 'make'), ('/usr/bin/cmake', 'cmake'), ('/usr/bin/meson', 'meson'), ('/usr/bin/ninja', 'ninja'),
    ('/home/a/.cargo/bin/rustc', 'rustc'), ('/home/a/.cargo/bin/cargo', 'cargo'), ('/usr/local/go/bin/go', 'go'),
    ('/usr/bin/nasm', 'nasm'), ('/usr/bin/yasm', 'yasm'), ('/tmp/tcc', 'tcc'), ('/home/a/.local/bin/pyinstaller',
                                                                                'pyinstaller'),
    ('/usr/bin/nuitka3', 'nuitka3'), ('/tmp/x/gcc (deleted)', 'gcc')])
def test_every_listed_linux_tool_is_named(path, tool):
    assert build_tools.tool_name(path) == tool


@pytest.mark.parametrize('path', ['/usr/bin/bash', '/usr/bin/python3', '/usr/bin/goa-daemon', '/usr/bin/gnome-shell',
                                  '/usr/bin/makedb', '/usr/bin/ldd', '/usr/bin/asciidoc', '/usr/bin/gcc-ar-x',
                                  '/usr/bin/csc', '/usr/bin/google-chrome', '/usr/bin/ninja-build-helper-x'])
def test_other_programs_are_not_build_tools(path):
    assert build_tools.tool_name(path) is None


@pytest.mark.parametrize('path,tool', [
    ('C:\\Windows\\Microsoft.NET\\Framework64\\v4.0.30319\\csc.exe', 'csc'),
    ('C:\\Windows\\Microsoft.NET\\Framework64\\v4.0.30319\\vbc.exe', 'vbc'),
    ('C:\\msys64\\mingw64\\bin\\GCC.EXE', 'gcc'), ('C:\\msys64\\mingw64\\bin\\x86_64-w64-mingw32-gcc.exe', 'gcc'),
    ('C:\\Program Files\\Go\\bin\\go.exe', 'go'), ('C:\\Users\\a\\.cargo\\bin\\cargo.exe', 'cargo'),
    ('C:\\Python313\\Scripts\\pyinstaller.exe', 'pyinstaller'), ('C:\\nasm\\nasm.exe', 'nasm')])
def test_windows_names_include_csc_and_vbc(path, tool):
    assert build_tools.tool_name(path, windows=True) == tool


def test_windows_only_tools_are_not_linux_tools_and_ordinary_windows_programs_pass():
    assert build_tools.tool_name('C:\\Windows\\System32\\cmd.exe', windows=True) is None
    assert build_tools.tool_name('C:\\Windows\\explorer.exe', windows=True) is None
    assert build_tools.tool_name('C:\\Windows\\System32\\cl.exe', windows=True) is None


def test_stopped_unless_the_package_manager_runs_and_always_recorded():
    stop = build_tools.decide('/usr/bin/gcc', package_manager_running=False)
    assert stop == {'rule_id': 'SATSUMA-BUILD-001', 'tool': 'gcc', 'path': '/usr/bin/gcc', 'stop': True}
    kept = build_tools.decide('/usr/bin/gcc', package_manager_running=True)
    assert kept['stop'] is False and kept['kept'] == 'package_manager_running'
    assert build_tools.decide('/usr/bin/bash', package_manager_running=False) is None
