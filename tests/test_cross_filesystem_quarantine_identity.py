"""Verify source stays intact if changed during cross-filesystem quarantine copy."""
import os
from unittest.mock import patch

import pytest

from satsuma import scan_quarantine as sq


def test_cross_volume_copy_refuses_modified_original(tmp_path):
    source_dir = tmp_path / 'original'
    quarantine_dir = tmp_path / 'quarantine'
    source_dir.mkdir()
    quarantine_dir.mkdir()
    path = source_dir / 'fixture'
    path.write_bytes(b'FIRST_BYTES')
    parent = os.open(source_dir, os.O_RDONLY | os.O_DIRECTORY)
    dest = os.open(quarantine_dir, os.O_RDONLY | os.O_DIRECTORY)
    fd = os.open(path, os.O_RDONLY)
    original = sq.fingerprint(fd)
    original_stat = sq.os.stat
    changed = False

    def mutation_before_final_check(*args, **kwargs):
        nonlocal changed
        result = original_stat(*args, **kwargs)
        if not changed and args[0] == 'fixture' and kwargs.get('dir_fd') == parent:
            changed = True
            path.write_bytes(b'CHANGED_NOW')  # same size; same inode
        return result

    try:
        with patch.object(sq.os, 'stat', side_effect=mutation_before_final_check):
            with pytest.raises(RuntimeError, match='Original changed'):
                sq._copy_then_unlink(fd, original, 'fixture', parent, 'quarantine-file', dest)
        assert path.read_bytes() == b'CHANGED_NOW'
        assert (quarantine_dir / 'quarantine-file').read_bytes() == b'FIRST_BYTES'
    finally:
        os.close(fd)
        os.close(parent)
        os.close(dest)


def test_cross_volume_copy_accepts_unchanged_original(tmp_path):
    origin = tmp_path / 'origin'
    destination = tmp_path / 'dest'
    origin.mkdir()
    destination.mkdir()
    path = origin / 'fixture'
    path.write_bytes(b'SAFE_FIXTURE')
    parent = os.open(origin, os.O_RDONLY | os.O_DIRECTORY)
    dest = os.open(destination, os.O_RDONLY | os.O_DIRECTORY)
    fd = os.open(path, os.O_RDONLY)
    try:
        sq._copy_then_unlink(fd, sq.fingerprint(fd), 'fixture', parent, 'archived', dest)
        assert not path.exists()
        assert (destination / 'archived').read_bytes() == b'SAFE_FIXTURE'
    finally:
        os.close(fd)
        os.close(parent)
        os.close(dest)
