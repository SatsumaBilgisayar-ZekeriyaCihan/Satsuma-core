"""Mount policy tests use simulated mount state; never remount the host."""
from copy import deepcopy
import pytest
from satsuma.memory_mounts import check, harden, mount_table
from satsuma.early_guard import run_guard


def state():
    return {'/dev': {'fstype': 'devtmpfs', 'options': {'rw', 'nosuid', 'relatime'}},
            '/dev/shm': {'fstype': 'tmpfs', 'options': {'rw', 'nosuid', 'nodev'}}}


def test_remount_enforces_and_reads_back_execution_restrictions():
    mounts = state()
    calls = []
    def run(args, **kwargs):
        calls.append(args)
        mounts[args[-1]]['options'] = set(args[2].split(',')) - {'remount'}
        assert kwargs['check'] is True
    result = harden(reader=lambda: mounts, runner=run)
    assert result['ok'] is True
    assert len(calls) == 2
    assert 'nodev' not in mounts['/dev']['options']
    assert {'noexec', 'nosuid', 'nodev'} <= mounts['/dev/shm']['options']
    assert 'relatime' in mounts['/dev']['options']
    harden(reader=lambda: mounts, runner=lambda *a, **k: pytest.fail('already hardened'))


def test_wrong_filesystem_causes_no_mutation():
    mounts = state()
    mounts['/dev/shm']['fstype'] = 'ext4'
    with pytest.raises(RuntimeError, match='Unexpected'):
        harden(reader=lambda: mounts, runner=lambda *a, **k: pytest.fail('unsafe remount'))


def test_successful_command_without_effect_fails_readback():
    with pytest.raises(RuntimeError, match='readback failed'):
        harden(reader=state, runner=lambda *a, **k: None)


def test_unsafe_mounts_keep_boot_response_locked():
    result = run_guard(verifier=lambda: 1, boot_id='fixture',
                       memory_checker=lambda: check(reader=state))
    assert result['response_unlocked'] is False
    assert any(r['code'] == 'MEMORY_MOUNTS_UNSAFE' for r in result['failure_reasons'])


def test_parser_uses_per_mount_flags(tmp_path):
    path = tmp_path / 'mountinfo'
    path.write_text('1 0 0:1 / /dev rw,nosuid,noexec - devtmpfs devtmpfs rw\n'
                    '2 1 0:2 / /dev/shm rw,nosuid,nodev,noexec - tmpfs tmpfs rw\n')
    assert check(reader=lambda: mount_table(path))['ok'] is True
