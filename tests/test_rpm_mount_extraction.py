"""Execute the RPM extraction gate with disposable mount/helper commands."""
import os
from pathlib import Path
import subprocess

import pytest

ROOT = Path(__file__).parents[1]


@pytest.mark.parametrize('scenario,expected', [('absent', 0), ('mounted', 0), ('busy', 1), ('still-mounted', 1), ('foreign', 1)])
def test_pre_extraction_gate_never_allows_a_live_mount(tmp_path, scenario, expected):
    spec = (ROOT/'packaging/satsuma-core.spec').read_text()
    gate = spec.split('# BEGIN RPM MOUNT EXTRACTION GATE\n', 1)[1].split('# END RPM MOUNT EXTRACTION GATE', 1)[0]
    state = tmp_path/'mounted'
    if scenario != 'absent':
        state.touch()
    probe = tmp_path/'mountpoint'
    probe.write_text('#!/bin/sh\ntest -f "$STATE"\n')
    helper = tmp_path/'helper'
    helper.write_text('#!/bin/sh\necho unmount >> "$LOG"\ncase "$SCENARIO" in busy|foreign) exit 32;; still-mounted) exit 0;; esac\nrm "$STATE"\n')
    for p in (probe, helper):
        p.chmod(0o755)
    gate = gate.replace('/usr/bin/mountpoint', str(probe)).replace('/usr/bin/python3 -I -B /usr/libexec/satsuma-image', str(helper))
    env = {**os.environ, 'STATE': str(state), 'LOG': str(tmp_path/'calls'), 'SCENARIO': scenario}
    result = subprocess.run(['/bin/sh', '-c', gate+'\necho EXTRACTION_ALLOWED'], env=env, capture_output=True, text=True)
    assert result.returncode == expected
    assert ('EXTRACTION_ALLOWED' in result.stdout) == (expected == 0)
    assert state.exists() == (scenario in ('busy', 'foreign', 'still-mounted'))
    assert (tmp_path/'calls').exists() == (scenario != 'absent')


def test_pre_stops_producers_then_consumers_then_image_before_extraction():
    spec = (ROOT/'packaging/satsuma-core.spec').read_text()
    pre = spec.split('%pre\n', 1)[1].split('%preun\n', 1)[0]
    assert pre.index('for timer in') < pre.index('for unit in') < pre.index('systemctl stop satsuma-image.service') < pre.index('# BEGIN RPM MOUNT EXTRACTION GATE')
    known = pre.split('case "$retired" in', 1)[1].split(') :;;', 1)[0]
    assert 'satsuma-image.service' in known
    assert 'umount -l' not in pre and 'umount -f' not in pre
