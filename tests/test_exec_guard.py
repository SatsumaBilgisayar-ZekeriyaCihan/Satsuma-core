"""Linux compile tool block: the kernel asks, build tools are refused before they run (owner's decision 2026-11-11).

Linux derleme aracı engeli: çekirdek sorar, derleme araçları çalışmadan reddedilir.
"""
import ctypes
import os
import shutil
import subprocess
import threading

import pytest

from satsuma import exec_guard


class Kernel:
    def __init__(self, events=(), fail_mounts=()):
        self.events, self.answers, self.marks, self.fail_mounts = list(events), [], [], set(fail_mounts)

    def mark(self, point):
        if point in self.fail_mounts:
            raise OSError(1, 'refused')
        self.marks.append(point)
        return 'filesystem'

    def read(self):
        events, self.events = self.events, []
        return events

    def answer(self, fd, allow):
        self.answers.append((fd, allow))

    def wait(self, timeout):
        return bool(self.events)


def guard(tmp_path, kernel, paths, pm=False):
    clock = [0.0]
    return exec_guard.Guard(kernel=kernel, pm_running=lambda: pm, clock=lambda: clock[0], wall=lambda: 1.0,
                            state_dir=tmp_path, echo=lambda *a, **k: None, path_of=lambda fd: paths[fd],
                            mountinfo=tmp_path / 'mountinfo')


MOUNTINFO = ('22 1 0:21 / / rw - btrfs /dev/vda3 rw\n'
             '23 22 0:5 / /proc rw - proc proc rw\n'
             '24 22 0:22 / /tmp rw - tmpfs tmpfs rw\n'
             '25 22 0:21 /home /home rw - btrfs /dev/vda3 rw\n'
             '26 22 0:23 / /run/media/a\\040b rw - vfat /dev/sdb1 rw\n')


def test_every_real_filesystem_is_marked_once_and_a_refusal_is_recorded(tmp_path):
    (tmp_path / 'mountinfo').write_text(MOUNTINFO)
    kernel = Kernel(fail_mounts={'/tmp'})
    g = guard(tmp_path, kernel, {})
    g.mark_all()
    assert kernel.marks == ['/', '/run/media/a b'] and '/tmp' in g.mark_failures
    assert '"mark_failed"' in (tmp_path / 'events.jsonl').read_text()


def test_a_build_tool_is_refused_everything_else_is_allowed(tmp_path):
    (tmp_path / 'mountinfo').write_text('')
    kernel = Kernel(events=[(10, 1), (11, 1), (12, 1)])
    g = guard(tmp_path, kernel, {10: '/usr/bin/gcc', 11: '/usr/bin/bash', 12: '/usr/bin/x86_64-redhat-linux-ld.bfd'})
    g.handle()
    assert kernel.answers == [(10, False), (11, True), (12, False)]
    assert g.counts['refused'] == 2 and g.counts['allowed'] == 1
    assert (tmp_path / 'events.jsonl').read_text().count('"build_tool_refused"') == 2


def test_while_the_package_manager_runs_the_tool_runs_and_is_recorded(tmp_path):
    kernel = Kernel(events=[(10, 1)])
    g = guard(tmp_path, kernel, {10: '/usr/bin/make'}, pm=True)
    g.handle()
    assert kernel.answers == [(10, True)]
    assert '"package_manager_running"' in (tmp_path / 'events.jsonl').read_text()


def test_an_unreadable_event_or_a_failing_decision_is_still_answered(tmp_path):
    kernel = Kernel(events=[(10, 1)])
    def broken(fd):
        raise OSError('gone')
    g = exec_guard.Guard(kernel=kernel, pm_running=lambda: False, state_dir=tmp_path, echo=lambda *a, **k: None,
                         path_of=broken)
    g.handle()
    assert kernel.answers == [(10, True)]


def test_unit_never_hides_mounts_and_is_watched_by_systemd():
    from pathlib import Path
    text = (Path(__file__).resolve().parents[1] / 'systemd/satsuma-exec-guard.service').read_text()
    for part in ('-m satsuma.exec_guard --loop', 'Type=notify', 'WatchdogSec=', 'Restart=always',
                 'CAP_SYS_ADMIN'):
        assert part in text, part
    assert 'PrivateTmp=yes' not in text and 'ProtectHome=yes' not in text


def _fanotify_available():
    if os.geteuid() != 0:
        return False
    libc = ctypes.CDLL(None, use_errno=True)
    fd = libc.fanotify_init(0x5, os.O_RDONLY)
    if fd < 0:
        return False
    os.close(fd)
    return True


@pytest.mark.skipif(not _fanotify_available(), reason='needs root and fanotify permission events')
def test_live_the_kernel_refuses_a_program_named_gcc_before_it_runs(tmp_path):
    """A harmless copy of /bin/true named gcc is refused by the kernel; the same copy named other runs."""
    tool, other = tmp_path / 'gcc', tmp_path / 'other'
    shutil.copy2(shutil.which('true'), tool)
    shutil.copy2(shutil.which('true'), other)
    kernel = exec_guard.Fanotify()
    assert kernel.mark(str(tmp_path)) in ('filesystem', 'mount')
    g = exec_guard.Guard(kernel=kernel, pm_running=lambda: False, state_dir=tmp_path / 'state',
                         echo=lambda *a, **k: None)
    stop = threading.Event()

    def serve():
        while not stop.is_set():
            if kernel.wait(0.1):
                g.handle()
    thread = threading.Thread(target=serve, daemon=True)
    thread.start()
    try:
        assert subprocess.run([str(other)], timeout=10).returncode == 0
        with pytest.raises(PermissionError):
            subprocess.run([str(tool)], timeout=10)
        assert g.counts['refused'] == 1
    finally:
        stop.set()
        thread.join(5)
        os.close(kernel.fd)
