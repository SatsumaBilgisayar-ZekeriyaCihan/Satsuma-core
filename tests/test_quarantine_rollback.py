"""2.2.15: every quarantine can be undone; a boot that does not complete
puts a quarantined program back by itself.

2.2.15: her karantina geri alınabilir; tamamlanmayan açılış karantinadaki
programı kendiliğinden yerine koyar.
"""
import os
import stat
import subprocess
from pathlib import Path

import pytest

from satsuma import scan_quarantine as q

SCRIPT = Path('packaging/root/usr/libexec/satsuma-quarantine-rollback')


@pytest.fixture
def system_tree(tmp_path, monkeypatch):
    bin_dir = tmp_path / 'usr' / 'bin'
    bin_dir.mkdir(parents=True)
    monkeypatch.setattr(q, 'SYSTEM_ROOTS', (bin_dir,))
    monkeypatch.setattr('satsuma.protected_storage.open_directory',
                        lambda p: os.open(p, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW))
    program = bin_dir / 'suspect'
    program.write_bytes(b'#!/bin/sh\necho hi\n')
    program.chmod(0o755)
    return tmp_path, program


def _quarantine(tmp_path, program):
    return q.quarantine_target(q.inspect_target(program), lambda r: None, directory=tmp_path / 'quarantine',
                               system_ok=True, pending=tmp_path / 'pending')


def test_restore_puts_the_file_back_with_its_mode(system_tree):
    tmp_path, program = system_tree
    result = _quarantine(tmp_path, program)
    assert not program.exists() and result['restorable'] and result['boot_verification']
    pending = Path(result['boot_verification'])
    assert (pending / 'original').read_text() == str(program) and (pending / 'mode').read_text() == '755'
    assert [r['path'] for r in q.list_quarantine(tmp_path / 'quarantine', tmp_path / 'pending')] == [str(program)]
    restored = q.restore_target(result['quarantine_id'], lambda r: None, directory=tmp_path / 'quarantine',
                                pending=tmp_path / 'pending')
    assert restored['status'] == 'restored' and program.read_bytes() == b'#!/bin/sh\necho hi\n'
    assert stat.S_IMODE(program.stat().st_mode) == 0o755 and not pending.exists()
    assert q.list_quarantine(tmp_path / 'quarantine', tmp_path / 'pending') == []


def test_restore_never_overwrites_a_new_file(system_tree):
    tmp_path, program = system_tree
    result = _quarantine(tmp_path, program)
    program.write_bytes(b'new')
    with pytest.raises(FileExistsError):
        q.restore_target(result['quarantine_id'], lambda r: None, directory=tmp_path / 'quarantine',
                         pending=tmp_path / 'pending')
    assert program.read_bytes() == b'new'


def _run(tmp_path, mode, state='running'):
    env = {**os.environ, 'SATSUMA_QUARANTINE_PENDING': str(tmp_path / 'pending'),
           'SATSUMA_QUARANTINE_DONE': str(tmp_path / 'done'), 'SATSUMA_SYSTEM_STATE': state}
    return subprocess.run(['sh', str(SCRIPT), mode], env=env, capture_output=True, text=True, check=True).stdout


def test_unfinished_boot_restores_the_program(system_tree):
    tmp_path, program = system_tree
    result = _quarantine(tmp_path, program)
    _run(tmp_path, 'boot')                      # first boot after quarantine starts …
    assert not program.exists()
    _run(tmp_path, 'confirm', state='starting')  # … and never finishes
    out = _run(tmp_path, 'boot')                # next boot: put it back
    assert 'restored' in out and program.read_bytes() == b'#!/bin/sh\necho hi\n'
    assert stat.S_IMODE(program.stat().st_mode) == 0o755
    assert (tmp_path / 'done' / result['quarantine_id']).is_dir()


def test_completed_boot_confirms_and_keeps_quarantine(system_tree):
    tmp_path, program = system_tree
    result = _quarantine(tmp_path, program)
    _run(tmp_path, 'boot')
    assert 'confirmed' in _run(tmp_path, 'confirm', state='degraded')
    _run(tmp_path, 'boot')
    assert not program.exists() and not (tmp_path / 'pending' / result['quarantine_id']).exists()
    assert (tmp_path / 'quarantine' / result['quarantine_id']).exists()


def test_rollback_units_run_early_and_after_a_finished_boot():
    unit = Path('systemd/satsuma-quarantine-rollback.service').read_text()
    assert 'DefaultDependencies=no' in unit and 'Before=sysinit.target' in unit
    assert 'satsuma-quarantine-rollback boot' in unit
    timer = Path('systemd/satsuma-quarantine-confirm.timer').read_text()
    assert 'OnBootSec=5min' in timer
    assert os.access(SCRIPT, os.X_OK)

