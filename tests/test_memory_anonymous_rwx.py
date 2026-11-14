"""Writable and executable memory without a file is anonymous_rwx, whatever its name.

Yazılabilir ve çalıştırılabilir dosyasız bellek, adı ne olursa olsun anonymous_rwx'tir.
"""
import pytest

from satsuma.worker_memory import inspect_process


def process(tmp_path, maps):
    (tmp_path / 'exe').symlink_to('/usr/bin/fixture')
    (tmp_path / 'maps').write_text(maps)
    return tmp_path


@pytest.mark.parametrize('name', ['', '[heap]', '[stack]', '[anon:shellcode]', '[anon_shmem:x]',
                                  '/dev/zero (deleted)', '/SYSV00000000 (deleted)'])
def test_rwx_without_a_file_is_reported(tmp_path, name):
    line = '7f0000000000-7f0000001000 rwxp 00000000 00:00 0 ' + name
    assert 'anonymous_rwx' in inspect_process(process(tmp_path, line.rstrip() + '\n'),
                                               replaced=lambda exe: False)


@pytest.mark.parametrize('line', [
    '7f0000000000-7f0000001000 r-xp 00000000 00:00 0 [anon:jit]',
    '7f0000000000-7f0000001000 rw-p 00000000 00:00 0 [heap]',
    '7f0000000000-7f0000001000 rwxp 00000000 fd:01 42 /usr/lib64/libfixture.so',
    '7f0000000000-7f0000001000 r-xp 00000000 00:00 0 [vdso]'])
def test_other_regions_are_not_anonymous_rwx(tmp_path, line):
    assert 'anonymous_rwx' not in inspect_process(process(tmp_path, line + '\n'),
                                                   replaced=lambda exe: False)
