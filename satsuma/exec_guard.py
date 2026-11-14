"""Linux compile tool block: the kernel asks before a program runs, Satsuma refuses build tools (owner's decision 2026-11-11).

fanotify permission events (FAN_OPEN_EXEC_PERM) are marked on every real
filesystem; before any program file is executed the kernel waits for this
guard's answer. A program that satsuma.build_tools names as a build tool is
refused (it never starts) unless the package manager runs; everything else is
allowed at once. Every refusal and every allowed build tool is recorded
(events.jsonl, state.json, journal). Filesystems mounted later are marked
within a minute.

The kernel waits while an answer is pending, so the guard does nothing else:
one small process, a decision from a fixed table and a one-second cached
check of the package manager. systemd's watchdog restarts it when it stops
answering; when the guard's fanotify descriptor closes, the kernel allows the
pending executions, so a failing guard can never freeze the machine.

Linux derleme aracı engeli: çekirdek bir program çalışmadan önce sorar,
Satsuma derleme araçlarını reddeder (sahibinin kararı 2026-11-11). Her
gerçek dosya sisteminde fanotify izin olayları (FAN_OPEN_EXEC_PERM)
işaretlenir; bir program dosyası çalıştırılmadan önce çekirdek bu bekçinin
yanıtını bekler. satsuma.build_tools'un derleme aracı saydığı program,
paket yöneticisi çalışmıyorsa reddedilir (hiç başlamaz); diğer her şeye
anında izin verilir. Her ret ve izin verilen her derleme aracı kaydedilir.
Sonradan bağlanan dosya sistemleri bir dakika içinde işaretlenir. Çekirdek
yanıt beklerken bekler; bu yüzden bekçi başka bir şey yapmaz. systemd
gözcüsü yanıt vermeyi bırakan bekçiyi yeniden başlatır; bekçinin fanotify
tanıtıcısı kapanınca çekirdek bekleyen çalıştırmalara izin verir, bozulan
bekçi makineyi asla donduramaz.
"""
import ctypes
import json
import os
import select
import socket
import struct
import sys
import time
from pathlib import Path

from . import build_tools

STATE_DIR = Path('/var/lib/satsuma-core/exec-guard')
FAN_CLOEXEC, FAN_CLASS_CONTENT = 0x1, 0x4
FAN_MARK_ADD, FAN_MARK_MOUNT, FAN_MARK_FILESYSTEM = 0x1, 0x10, 0x100
FAN_OPEN_EXEC_PERM = 0x00040000
FAN_ALLOW, FAN_DENY = 0x01, 0x02
AT_FDCWD = -100
EVENT = struct.Struct('=IBBHQii')          # event_len, vers, reserved, metadata_len, mask, fd, pid
RESPONSE = struct.Struct('=iI')
PSEUDO = frozenset(('proc', 'sysfs', 'cgroup', 'cgroup2', 'devpts', 'mqueue', 'debugfs', 'tracefs', 'securityfs',
                    'pstore', 'bpf', 'configfs', 'fusectl', 'hugetlbfs', 'autofs', 'binfmt_misc', 'efivarfs',
                    'selinuxfs', 'nsfs', 'rpc_pipefs', 'devtmpfs', 'ramfs'))
REMARK_EVERY = 60.0
PM_CACHE_SECONDS = 1.0


def mount_points(mountinfo='/proc/self/mountinfo'):
    """Mount points of real filesystems (one per superblock), from mountinfo."""
    seen, points = set(), []
    for line in Path(mountinfo).read_text().splitlines():
        left, _, right = line.partition(' - ')
        fields, tail = left.split(), right.split()
        if len(fields) < 5 or not tail:
            continue
        device, point, fstype = fields[2], fields[4].encode().decode('unicode_escape'), tail[0]
        if fstype in PSEUDO or device in seen:
            continue
        seen.add(device)
        points.append(point)
    return points


class Fanotify:
    """The kernel side: one permission-class fanotify descriptor."""

    def __init__(self, libc=None):
        self.libc = libc or ctypes.CDLL(None, use_errno=True)
        self.libc.fanotify_init.argtypes = (ctypes.c_uint, ctypes.c_uint)
        self.libc.fanotify_mark.argtypes = (ctypes.c_int, ctypes.c_uint, ctypes.c_uint64, ctypes.c_int,
                                            ctypes.c_char_p)
        self.fd = self.libc.fanotify_init(FAN_CLOEXEC | FAN_CLASS_CONTENT, os.O_RDONLY | os.O_CLOEXEC)
        if self.fd < 0:
            error = ctypes.get_errno()
            raise OSError(error, 'fanotify_init: ' + os.strerror(error))

    def mark(self, point):
        """Mark one filesystem (or, where that is refused, the mount); returns the way it was marked."""
        for flags, how in ((FAN_MARK_ADD | FAN_MARK_FILESYSTEM, 'filesystem'), (FAN_MARK_ADD | FAN_MARK_MOUNT, 'mount')):
            if self.libc.fanotify_mark(self.fd, flags, FAN_OPEN_EXEC_PERM, AT_FDCWD, point.encode()) == 0:
                return how
        error = ctypes.get_errno()
        raise OSError(error, 'fanotify_mark %s: %s' % (point, os.strerror(error)))

    def wait(self, timeout):
        return bool(select.select([self.fd], [], [], timeout)[0])

    def read(self):
        """Pending permission events as (event fd, pid)."""
        data = os.read(self.fd, 4096 * EVENT.size)
        events, offset = [], 0
        while offset + EVENT.size <= len(data):
            length, _, _, _, mask, fd, pid = EVENT.unpack_from(data, offset)
            if length < EVENT.size:
                break
            if mask & FAN_OPEN_EXEC_PERM and fd >= 0:
                events.append((fd, pid))
            elif fd >= 0:
                os.close(fd)
            offset += length
        return events

    def answer(self, fd, allow):
        try:
            os.write(self.fd, RESPONSE.pack(fd, FAN_ALLOW if allow else FAN_DENY))
        finally:
            os.close(fd)


def _notify(message):
    """sd_notify without libsystemd: READY=1 and WATCHDOG=1 to systemd."""
    address = os.environ.get('NOTIFY_SOCKET')
    if not address:
        return
    if address.startswith('@'):
        address = '\0' + address[1:]
    try:
        with socket.socket(socket.AF_UNIX, socket.SOCK_DGRAM) as sock:
            sock.sendto(message.encode(), address)
    except OSError:
        pass


class Guard:
    def __init__(self, kernel=None, pm_running=None, clock=time.monotonic, wall=time.time,
                 state_dir=STATE_DIR, echo=print, mountinfo='/proc/self/mountinfo', path_of=None):
        if pm_running is None:
            from .kernel_guard import package_manager_running as pm_running
        self.kernel, self.pm_running, self.clock, self.wall = kernel, pm_running, clock, wall
        self.state_dir, self.echo, self.mountinfo = Path(state_dir), echo, mountinfo
        self.path_of = path_of or (lambda fd: os.readlink('/proc/self/fd/%d' % fd))
        self.marked, self.mark_failures = {}, {}
        self.pm_value, self.pm_at = False, None
        self.marked_at = None
        self.counts = {'allowed': 0, 'refused': 0, 'build_tool_allowed': 0, 'unreadable': 0}

    def record(self, kind, **fields):
        event = {'time': self.wall(), 'kind': kind, **fields}
        self.echo(json.dumps(event, ensure_ascii=False, sort_keys=True), flush=True)
        try:
            self.state_dir.mkdir(parents=True, exist_ok=True)
            with open(self.state_dir / 'events.jsonl', 'a', encoding='utf-8') as stream:
                stream.write(json.dumps(event, ensure_ascii=False, sort_keys=True) + '\n')
        except OSError:
            pass
        return event

    def mark_all(self):
        """Mark every real filesystem not yet marked; a failure is recorded, never hidden."""
        now = self.clock()
        if self.marked_at is not None and now - self.marked_at < REMARK_EVERY:
            return
        self.marked_at = now
        for point in mount_points(self.mountinfo):
            if point in self.marked:
                continue
            try:
                self.marked[point] = self.kernel.mark(point)
                self.mark_failures.pop(point, None)
            except OSError as exc:
                if self.mark_failures.get(point) != str(exc):
                    self.mark_failures[point] = str(exc)
                    self.record('mark_failed', mount=point, error=str(exc)[:300])

    def package_manager(self):
        now = self.clock()
        if self.pm_at is None or now - self.pm_at >= PM_CACHE_SECONDS:
            self.pm_value, self.pm_at = bool(self.pm_running()), now
        return self.pm_value

    def decide(self, fd, pid):
        """Allow or refuse one execution; True means allow."""
        try:
            path = self.path_of(fd)
        except OSError:
            self.counts['unreadable'] += 1
            return True
        decision = build_tools.decide(path, False) if build_tools.tool_name(path) else None
        if decision is None:
            self.counts['allowed'] += 1
            return True
        decision = build_tools.decide(path, self.package_manager())
        try:
            parent = os.readlink('/proc/%d/exe' % pid)
        except OSError:
            parent = None
        if decision['stop']:
            self.counts['refused'] += 1
            self.record('build_tool_refused', pid=pid, proc_dir='/proc/%d' % pid, process_name=os.path.basename(path), action='execution_denied', caller=parent, **decision)
            return False
        self.counts['build_tool_allowed'] += 1
        self.record('build_tool_allowed', pid=pid, proc_dir='/proc/%d' % pid, process_name=os.path.basename(path), action='execution_allowed', confirmation='Teyit Edildi: çalıştırma izni', caller=parent, **decision)
        return True

    def handle(self):
        for fd, pid in self.kernel.read():
            allow = True
            try:
                allow = self.decide(fd, pid)
            finally:
                self.kernel.answer(fd, allow)

    def save_state(self):
        state = {'updated_at': self.wall(), 'marked': self.marked, 'mark_failures': self.mark_failures,
                 'counts': self.counts}
        try:
            self.state_dir.mkdir(parents=True, exist_ok=True)
            temporary = self.state_dir / 'state.json.tmp'
            temporary.write_text(json.dumps(state, sort_keys=True), encoding='utf-8')
            os.replace(temporary, self.state_dir / 'state.json')
        except OSError:
            pass
        return state


def run(guard, rounds=None):
    """Answer the kernel until stopped; watchdog notifications keep systemd informed."""
    guard.mark_all()
    guard.record('started', marked=guard.marked, mark_failures=guard.mark_failures)
    _notify('READY=1')
    saved_at = 0.0
    while rounds is None or rounds > 0:
        if guard.kernel.wait(1.0):
            guard.handle()
        guard.mark_all()
        _notify('WATCHDOG=1')
        if guard.clock() - saved_at >= 10:
            guard.save_state()
            saved_at = guard.clock()
        if rounds is not None:
            rounds -= 1


def main(argv=None):
    args = list(sys.argv[1:] if argv is None else argv)
    if args != ['--loop']:
        print('usage: python3 -m satsuma.exec_guard --loop', file=sys.stderr)
        return 2
    run(Guard(kernel=Fanotify()))
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
