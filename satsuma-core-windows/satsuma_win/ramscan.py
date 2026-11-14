"""Memory signature scan on Windows (RAM v2): process memory to the private clamd, the shared rules decide.

The scan itself is the shared Linux engine (satsuma.ram.engine): bounded
turns of at most 4 MiB and 2 seconds per process, 1 MiB pieces with 64 KiB
overlap, and a signature counts only when the same bytes, read again from
the same process with the same memory map, give the same signature again.
Only reading memory is Windows specific: WindowsProcess walks the memory map
with VirtualQueryEx and reads with ReadProcessMemory through one handle.
Processes are visited in turn; a process that has just started is visited
first.

What a finding means is decided by the shared rules (satsuma.memory_decision,
the same rule files as Linux): a reproduced signature is SATSUMA-RAM-106 and
is stopped; a heuristic or unreproduced one is SATSUMA-RAM-107 and recorded.
Before stopping, through the same handle, the process creation time is
compared and the bytes are read and scanned once more; Windows critical
processes (with a critical alarm), Satsuma itself and its own ClamAV children
are never stopped (satsuma_win.memory.exemption); since 2.2.38 remote support
and the desktop are stopped like any program. The scan never covers all RAM: what
it could not read is counted, never reported clean.

Windows'ta bellek imza taraması (RAM v2): süreç belleği özel clamd'ye gider,
ortak kurallar karar verir. Taramanın kendisi Linux'la ortak motordur: süreç
başına en çok 4 MiB ve 2 saniyelik turlar, 64 KiB örtüşmeli 1 MiB parçalar;
bir imza ancak aynı süreçten aynı bellek haritasıyla yeniden okunan aynı
baytlar aynı imzayı yeniden verirse sayılır. Platforma özgü olan yalnızca
belleği okumaktır: WindowsProcess tek tutamaçla VirtualQueryEx ve
ReadProcessMemory kullanır. Süreçler sırayla ziyaret edilir; yeni başlayan
süreç önce. Bulgunun anlamına ortak kurallar karar verir: yeniden doğrulanan
imza SATSUMA-RAM-106'dır ve süreç durdurulur; sezgisel ya da yeniden
üretilemeyen imza SATSUMA-RAM-107'dir ve kaydedilir. Durdurmadan önce aynı
tutamaçla oluşturma zamanı karşılaştırılır, baytlar bir kez daha okunup
taranır; Windows'un kritik süreçleri, Satsuma, ClamAV, uzak destek ve
masaüstü asla durdurulmaz. Tarama hiçbir zaman bütün RAM'i kapsamaz:
okunamayan sayılır, asla temiz bildirilmez.
"""
import os
import threading
import time
from collections import deque

from satsuma.ram.engine import Progress, confirm, scan_turn

from . import memory

REQUEST_SECONDS = 3.0
REFRESH_SECONDS = 5.0
MAX_TRACKED = 4096
STILL_ACTIVE = 259
PAGE_NOACCESS, PAGE_GUARD = 0x01, 0x100
READABLE = (0x02, 0x04, 0x08, 0x20, 0x40, 0x80)
WRITABLE = (0x04, 0x08, 0x40, 0x80)
EXECUTABLE = (0x10, 0x20, 0x40, 0x80)
TYPE_NAMES = {0x20000: 'private', 0x40000: 'mapped', 0x1000000: 'image'}
EXIT_CODE = 0xC5A75C

_KERNEL32 = None


def _kernel32():
    global _KERNEL32
    if _KERNEL32 is None:
        import ctypes
        from ctypes import wintypes
        k = ctypes.WinDLL('kernel32', use_last_error=True)
        k.OpenProcess.restype = wintypes.HANDLE
        k.OpenProcess.argtypes = (wintypes.DWORD, wintypes.BOOL, wintypes.DWORD)
        k.CloseHandle.argtypes = (wintypes.HANDLE,)
        k.VirtualQueryEx.restype = ctypes.c_size_t
        k.VirtualQueryEx.argtypes = (wintypes.HANDLE, ctypes.c_void_p, ctypes.c_void_p, ctypes.c_size_t)
        k.ReadProcessMemory.restype = wintypes.BOOL
        k.ReadProcessMemory.argtypes = (wintypes.HANDLE, ctypes.c_void_p, ctypes.c_void_p, ctypes.c_size_t,
                                        ctypes.POINTER(ctypes.c_size_t))
        k.GetProcessTimes.argtypes = (wintypes.HANDLE,) + (ctypes.POINTER(wintypes.FILETIME),) * 4
        k.GetExitCodeProcess.argtypes = (wintypes.HANDLE, ctypes.POINTER(wintypes.DWORD))
        k.QueryFullProcessImageNameW.argtypes = (wintypes.HANDLE, wintypes.DWORD, wintypes.LPWSTR,
                                                 ctypes.POINTER(wintypes.DWORD))
        k.IsProcessCritical.argtypes = (wintypes.HANDLE, ctypes.POINTER(wintypes.BOOL))
        k.TerminateProcess.argtypes = (wintypes.HANDLE, wintypes.UINT)
        k.WaitForSingleObject.restype = wintypes.DWORD
        k.WaitForSingleObject.argtypes = (wintypes.HANDLE, wintypes.DWORD)
        k.GetLongPathNameW.restype = wintypes.DWORD
        k.GetLongPathNameW.argtypes = (wintypes.LPCWSTR, wintypes.LPWSTR, wintypes.DWORD)
        _KERNEL32 = k
    return _KERNEL32


class WindowsProcess:
    """One process for the shared engine: snapshot (identity, map), read, eligible; and stopping by handle."""

    ACCESS = 0x0400 | 0x0010 | 0x0001 | 0x00100000      # query, read, terminate, synchronize
    READ_ONLY = 0x0400 | 0x0010

    def __init__(self, pid):
        import ctypes
        from ctypes import wintypes
        self.ctypes, self.wintypes, self.k = ctypes, wintypes, _kernel32()
        self.pid = int(pid)
        if self.pid <= 4:
            raise ValueError('invalid_pid')
        self.handle = self.k.OpenProcess(self.ACCESS, False, self.pid) or self.k.OpenProcess(
            self.READ_ONLY, False, self.pid)
        if not self.handle:
            raise PermissionError(ctypes.get_last_error(), 'OpenProcess')

        class MBI(ctypes.Structure):
            _fields_ = [('BaseAddress', ctypes.c_void_p), ('AllocationBase', ctypes.c_void_p),
                        ('AllocationProtect', wintypes.DWORD), ('PartitionId', wintypes.WORD),
                        ('RegionSize', ctypes.c_size_t), ('State', wintypes.DWORD),
                        ('Protect', wintypes.DWORD), ('Type', wintypes.DWORD)]
        self.MBI = MBI

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        self.close()
        return False

    def close(self):
        if self.handle:
            self.k.CloseHandle(self.handle)
            self.handle = None

    def created(self):
        times = [self.wintypes.FILETIME() for _ in range(4)]
        if not self.k.GetProcessTimes(self.handle, *(self.ctypes.byref(t) for t in times)):
            raise OSError(self.ctypes.get_last_error(), 'GetProcessTimes')
        return (times[0].dwHighDateTime << 32) | times[0].dwLowDateTime

    def image(self):
        size, buffer = self.wintypes.DWORD(32768), self.ctypes.create_unicode_buffer(32768)
        if not self.k.QueryFullProcessImageNameW(self.handle, 0, buffer, self.ctypes.byref(size)):
            raise OSError(self.ctypes.get_last_error(), 'QueryFullProcessImageNameW')
        path, long_buffer = buffer.value, self.ctypes.create_unicode_buffer(32768)
        if '~' in path and self.k.GetLongPathNameW(path, long_buffer, 32768):
            path = long_buffer.value
        return path

    def _alive(self):
        code = self.wintypes.DWORD()
        if not self.k.GetExitCodeProcess(self.handle, self.ctypes.byref(code)):
            raise OSError(self.ctypes.get_last_error(), 'GetExitCodeProcess')
        if code.value != STILL_ACTIVE:
            raise ProcessLookupError('process_exited')

    def snapshot(self):
        """(identity, map text in the engine's format): every committed, readable, non-guard region."""
        self._alive()
        identity = (self.pid, self.created(), self.image(), 0, 0)
        lines, address, mbi = [], 0, self.MBI()
        while len(lines) < 200000:
            if not self.k.VirtualQueryEx(self.handle, self.ctypes.c_void_p(address), self.ctypes.byref(mbi),
                                         self.ctypes.sizeof(mbi)):
                break                                   # end of the user address range
            base, size = mbi.BaseAddress or 0, mbi.RegionSize
            if not size or base + size <= address:
                raise RuntimeError('nonadvancing_virtual_region')
            protect = mbi.Protect & 0xFF
            if mbi.State == 0x1000 and not mbi.Protect & PAGE_GUARD and protect != PAGE_NOACCESS:
                perms = (('r' if protect in READABLE else '-') + ('w' if protect in WRITABLE else '-')
                         + ('x' if protect in EXECUTABLE else '-') + 'p')
                lines.append('%x-%x %s 00000000 00:00 0 [windows:%s]\n'
                             % (base, base + size, perms, TYPE_NAMES.get(mbi.Type, hex(mbi.Type))))
            address = base + size
        else:
            raise RuntimeError('region_count_limit_exceeded')
        return identity, ''.join(lines)

    def read(self, address, size):
        if type(address) is not int or address < 0 or type(size) is not int or not 0 < size <= 1 << 20:
            raise ValueError('invalid_bounded_read')
        buffer, count = self.ctypes.create_string_buffer(size), self.ctypes.c_size_t()
        if not self.k.ReadProcessMemory(self.handle, self.ctypes.c_void_p(address), buffer, size,
                                        self.ctypes.byref(count)):
            error = self.ctypes.get_last_error()
            if error in (5, 299):                       # access denied, partial copy
                raise PermissionError(error, 'ReadProcessMemory')
            raise OSError(error, 'ReadProcessMemory')
        return buffer.raw[:count.value]

    def eligible(self, region):
        if 'r' not in region.perms:
            return False, 'not_readable'
        return True, None

    def info(self):
        """What satsuma_win.memory.exemption needs. Muafiyet denetimi için gerekenler."""
        flag = self.wintypes.BOOL()
        critical = bool(self.k.IsProcessCritical(self.handle, self.ctypes.byref(flag)) and flag.value)
        try:
            import psutil
            parent = psutil.Process(self.pid).ppid()
        except Exception:  # the parent is context for the record only
            parent = None
        try:
            image = self.image()
        except OSError:
            image = None
        return {'pid': self.pid, 'image': image, 'critical': critical, 'parent': parent}

    def terminate(self, created):
        """Stop this process through this handle, only if it is still the same process."""
        if self.created() != created:
            raise OSError('process identity changed')
        if not self.k.TerminateProcess(self.handle, EXIT_CODE):
            raise OSError(self.ctypes.get_last_error(), 'TerminateProcess')
        self.k.WaitForSingleObject(self.handle, 2000)


def default_pids():
    import psutil
    return psutil.pids()


class SignatureMonitor:
    """The scan thread: keeps clamd ready, visits processes in turn, stops what the shared rules stop."""

    def __init__(self, runtime, rules, own_pid=None, satsuma_exe=None, enforce=True, pids=default_pids,
                 process_factory=WindowsProcess, clock=time.time, monotonic=time.monotonic):
        from satsuma import memory_decision
        self.decide = lambda action: memory_decision.decide(action, rules)
        self.runtime, self.enforce, self.pids = runtime, enforce, pids
        self.process_factory, self.clock, self.monotonic = process_factory, clock, monotonic
        self.own_pid = os.getpid() if own_pid is None else own_pid
        self.satsuma_exe = satsuma_exe
        self.order, self.progress, self.reports = deque(), {}, {}
        self.events, self.seen = deque(maxlen=1000), set()
        self.lock, self.stopped = threading.Lock(), threading.Event()
        self.refresh_at = 0.0
        self.thread = None
        self.counts = {'turns': 0, 'read_bytes': 0, 'scanner_bytes': 0, 'unavailable': 0, 'findings': 0,
                       'stopped': 0, 'stop_failed': 0, 'refused': 0, 'exempt': 0, 'recorded': 0, 'scan_limits': 0,
                       'enumerated': 0, 'capacity_excluded': 0}

    # -- order -----------------------------------------------------------------
    def refresh(self, live):
        """Forget exited processes; a new process goes to the front. Yeni süreç sıranın başına."""
        live = set(live)
        self.order = deque(pid for pid in self.order if pid in live)
        self.progress = {pid: p for pid, p in self.progress.items() if pid in live}
        new = sorted(live - set(self.order), reverse=True)
        for pid in new:
            self.order.appendleft(pid)
            self.progress[pid] = Progress()
        while len(self.order) > MAX_TRACKED:
            self.progress.pop(self.order.pop(), None)
        self.counts['enumerated'] = len(live)
        self.counts['capacity_excluded'] = max(0, len(live) - len(self.order))

    def skipped(self):
        scanner = (self.runtime.child.pid if getattr(self.runtime, 'child', None) is not None else None)
        return {0, 4, self.own_pid, scanner}

    # -- one turn --------------------------------------------------------------
    def step(self):
        """One turn of the scan thread; returns the report, or None when clamd is not ready."""
        maintenance = self.runtime.maintain()
        if maintenance is not None:
            self._event('clamav_maintenance', **maintenance)
        if not self.runtime.ensure_ready():
            return None
        if self.monotonic() >= self.refresh_at:
            self.refresh(self.pids())
            self.refresh_at = self.monotonic() + REFRESH_SECONDS
        skipped = self.skipped()
        while self.order and self.order[0] in skipped:
            self.order.rotate(-1)
            if all(pid in skipped for pid in self.order):
                return None
        if not self.order:
            return None
        pid = self.order[0]
        self.order.rotate(-1)
        try:
            with self.process_factory(pid) as process:
                report = scan_turn(process, self.runtime.scanner, self.progress[pid],
                                   request_seconds=REQUEST_SECONDS)
                for finding in report.get('findings') or ():
                    self.respond(process, finding)
        except (OSError, ValueError, RuntimeError) as exc:
            report = {'pid': pid, 'status': 'PROCESS_UNAVAILABLE', 'error': type(exc).__name__, 'findings': []}
        with self.lock:
            self.counts['turns'] += 1
            self.counts['read_bytes'] += report.get('read_bytes_this_turn', 0)
            self.counts['scanner_bytes'] += report.get('scanner_bytes_this_turn', 0)
            self.counts['unavailable'] += report.get('status') == 'SCANNER_UNAVAILABLE'
            self.counts['scan_limits'] += report.get('scan_limit_exceeded', 0)
            self.reports[pid] = {k: report.get(k) for k in ('status', 'coverage_state', 'next_offset',
                                                            'candidate_bytes', 'layout_resets', 'error',
                                                            'cycle_limited_bytes')}
            if len(self.reports) > 128:
                self.reports.pop(next(iter(self.reports)))
        return report

    def respond(self, process, finding):
        """Decide with the shared rules; stop through the same handle after one more exact confirmation."""
        action = 'ram_signature_match_v2' if finding.get('status') == 'REPRODUCED_SIGNATURE' else 'ram_review_v2'
        identity = tuple(finding['identity'])
        key = (identity[0], identity[1], finding.get('signature'), finding.get('address'))
        if key in self.seen:
            return None
        self.seen.add(key)
        decision = self.decide(action) or {'rule_id': None, 'name': '', 'stop': False}
        info = process.info()
        reason = memory.exemption(info, self.own_pid, self.satsuma_exe)
        outcome, detail = 'recorded', None
        if decision['stop'] and reason:
            outcome = 'exempt'
        elif decision['stop'] and self.enforce:
            try:
                if confirm(process, {**finding, 'identity': identity}, self.runtime.scanner,
                           self.monotonic() + REQUEST_SECONDS):
                    process.terminate(identity[1])
                    outcome = 'stopped'
                else:
                    outcome, detail = 'refused', 'evidence_no_longer_matches'
            except (OSError, RuntimeError, ValueError) as exc:
                outcome, detail = 'stop_failed', type(exc).__name__ + ': ' + str(exc)[:200]
        with self.lock:
            self.counts['findings'] += 1
            self.counts[outcome] += 1
        fields = {'pid': identity[0], 'image': identity[2], 'parent': info.get('parent'),
                  'rule_id': decision['rule_id'], 'rule': decision.get('name', ''), 'indicator': action,
                  'rule_stops': decision['stop'], 'signature': finding.get('signature'),
                  'status': finding.get('status'), 'address': hex(finding.get('address') or 0),
                  'bytes': finding.get('bytes'), 'sha256': finding.get('sha256'), 'outcome': outcome}
        if reason:
            fields['exempt'] = reason
            if reason == 'windows_critical_process' and decision['stop']:
                fields['alarm'] = 'critical'
        if detail:
            fields['detail'] = detail
        return self._event('ram_signature_finding', **fields)

    def _event(self, kind, **fields):
        event = {'kind': kind, **fields}
        with self.lock:
            self.events.append(event)
        return event

    def drain(self):
        with self.lock:
            events = list(self.events)
            self.events.clear()
        return events

    def health(self):
        with self.lock:
            counts = dict(self.counts)
            reports = dict(self.reports)
        statuses = {}
        for report in reports.values():
            statuses[report.get('status')] = statuses.get(report.get('status'), 0) + 1
        clamd = self.runtime.health()
        state = clamd['state'] if clamd['state'] != 'READY' else (
            'DEGRADED' if statuses.get('SCANNER_UNAVAILABLE') else 'SCANNING')
        return {'state': state, 'clamd': clamd, 'counts': counts, 'result_status_counts': statuses,
                'enforce': self.enforce, 'coverage_state': 'INCOMPLETE', 'full_ram_coverage': False,
                'clean_verdict': False, 'raw_memory_persisted': False,
                'scope': 'committed readable user-process memory; guard, no-access, kernel and '
                         'Windows-protected (PPL) memory excluded'}

    # -- thread ----------------------------------------------------------------
    def run(self):
        while not self.stopped.is_set():
            try:
                report = self.step()
            except Exception as exc:  # the thread keeps running; the failure is recorded
                self._event('ram_signature_error', error=type(exc).__name__ + ': ' + str(exc)[:300])
                report = None
            self.stopped.wait(0.05 if report is not None else 1.0)
        self.runtime.close()

    def start(self):
        self.thread = threading.Thread(target=self.run, daemon=True, name='satsuma-ram-v2')
        self.thread.start()
        return self

    def close(self):
        self.stopped.set()
        if self.thread is not None:
            self.thread.join(timeout=10)
        else:
            self.runtime.close()
