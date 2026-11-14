"""Windows memory protection: reads every process's memory map and stops what the shared memory rules stop.

For each process the service opens one handle and, through it, walks the
memory map with VirtualQueryEx and reads the program path, whether a debugger
is attached and whether Windows marks the process critical. What it finds is
named with the same indicator words as on Linux:

* anonymous_rwx (SATSUMA-RAM-001): committed memory that is writable and
  executable at once and backed by no file, private (VirtualAlloc) or shared
  (a pagefile-backed section mapped writable and executable). Injected
  shellcode lives there, but so does every .NET program's JIT code (proven
  on GitHub's Windows server). Owner's decision 2026-11-11: stopped when a
  thread of the process was started from fileless executable memory
  (NtQueryInformationThread start address), or when the program file is
  outside the Windows folder and Program Files; otherwise recorded.
* writable_dir_code_mapping (SATSUMA-RAM-008): executable image (exe or DLL)
  loaded from a folder anyone can write: C:\\Windows\\Temp, a user's
  AppData\\Local\\Temp, C:\\Users\\Public. Owner's decision 2026-11-11:
  stopped when unsigned; recorded only when every such file has a valid
  publisher signature (WinVerifyTrust), or when the process (or its parent)
  is a Satsuma setup whose SHA-256 was approved with the administrator
  password and has not expired.
* deleted_executable (SATSUMA-RAM-004): the program file of a running process
  is gone (process ghosting, herpaderping).
* process_traced (SATSUMA-RAM-009): a debugger is attached to the process.

Which rule an indicator matches and whether the process is stopped is decided
by satsuma.memory_decision, the same code and the same rule files as on Linux.
A process to stop is terminated through the same handle it was read with,
after its creation time is compared again, so a reused process id can never
stop another program. Never stopped, only recorded: Windows critical processes
(stopping one crashes Windows), the service itself and the PowerShell it
starts, remote support (TeamViewer, AnyDesk) and the desktop, each only from
its system or Program Files location. Processes protected by Windows (PPL)
cannot be opened; they are counted, not hidden.

Windows bellek koruması: her sürecin bellek haritasını okur ve ortak bellek
kurallarının durdurduğunu durdurur. Hizmet her süreç için bir tutamaç açar;
VirtualQueryEx ile bellek haritasını gezer, program yolunu, hata ayıklayıcı
bağlı olup olmadığını ve Windows'un süreci kritik sayıp saymadığını okur.
Bulduklarını Linux'takiyle aynı gösterge adlarıyla adlandırır: dosyasız
yazılabilir+çalıştırılabilir bellek (RAM-001; her .NET programında da
bulunur, sahibinin kararı 2026-11-11: bir iş parçacığı dosyasız
bellekten başlatılmışsa ya da program Windows klasörü ve Program Files
dışındaysa durdurulur, değilse kaydedilir), herkesin yazabildiği klasörden
yüklenen exe/DLL (RAM-008; sahibinin kararı 2026-11-11: imzasızsa
durdurulur, her dosyası geçerli yayıncı imzalıysa ya da süreç veya üst
süreci yönetici parolasıyla onaylanmış, süresi dolmamış bir Satsuma
kurulumuysa yalnızca kaydedilir), dosyası silinmiş çalışan program (RAM-004), hata
ayıklayıcı bağlı süreç (RAM-009). Hangi kurala uyduğuna ve sürecin durdurulup
durdurulmayacağına Linux'la aynı kod ve aynı kural dosyaları karar verir
(satsuma.memory_decision). Durdurulacak süreç, okunduğu tutamaçla ve oluşturma
zamanı yeniden karşılaştırıldıktan sonra sonlandırılır; yeniden kullanılan
bir süreç numarası başka bir programı durduramaz. Durdurulmaz, yalnızca
kaydedilir: Windows'un kritik süreçleri (durdurmak Windows'u çökertir),
hizmetin kendisi ve başlattığı PowerShell, uzak destek ve masaüstü; her biri
yalnızca sistem ya da Program Files konumundan. Windows'un koruduğu (PPL)
süreçler açılamaz; sayılır, gizlenmez.
"""
import hashlib
import json
import os
import re
import time
from pathlib import Path

MEM_COMMIT = 0x1000
MEM_PRIVATE, MEM_MAPPED, MEM_IMAGE = 0x20000, 0x40000, 0x1000000
PAGE_EXECUTE, PAGE_EXECUTE_READ = 0x10, 0x20
PAGE_EXECUTE_READWRITE, PAGE_EXECUTE_WRITECOPY = 0x40, 0x80
EXECUTABLE = (PAGE_EXECUTE, PAGE_EXECUTE_READ, PAGE_EXECUTE_READWRITE, PAGE_EXECUTE_WRITECOPY)
WRITABLE_EXECUTABLE = (PAGE_EXECUTE_READWRITE, PAGE_EXECUTE_WRITECOPY)

WRITABLE_DIRS = (re.compile(r'^[a-z]:\\windows\\temp\\'),
                 re.compile(r'^[a-z]:\\users\\[^\\]+\\appdata\\local\\temp\\'),
                 re.compile(r'^[a-z]:\\users\\public\\'))

# 2.2.38 (owner, 2026-11-13): no program is spared by its name. Code a remote-support
# peer sends through TeamViewer or AnyDesk, or malware inside explorer, Defender or
# Sysmon, is stopped. Satsuma's own clamd and freshclam are spared only as the
# service's own children from its ClamAV folder (a clamd elsewhere is scanned and
# stopped like any program).
# 2.2.38 (sahibi, 2026-11-13): hiçbir program adıyla esirgenmez; Satsuma'nın clamd ve
# freshclam'ı yalnızca hizmetin kendi alt süreci olarak, kendi ClamAV klasöründen esirgenir.
SATSUMA_CLAMAV = ('clamd.exe', 'freshclam.exe')
SATSUMA_EXE = 'satsuma-core-windows.exe'
SATSUMA_POWERSHELL = r'\windows\system32\windowspowershell\v1.0\powershell.exe'


def _lower(path):
    return str(path or '').replace('/', '\\').lower()


def writable_dir(path):
    path = _lower(path)
    return any(pattern.match(path) for pattern in WRITABLE_DIRS)


def trusted_location(path, environ=os.environ):
    path = _lower(path)
    roots = [environ.get('SystemRoot', r'C:\Windows'), environ.get('ProgramFiles', r'C:\Program Files'),
             environ.get('ProgramFiles(x86)', r'C:\Program Files (x86)')]
    return any(root and path.startswith(_lower(root).rstrip('\\') + '\\') for root in roots)


def region_indicators(region):
    """Indicators of one committed memory region (a dict from the reader)."""
    if region.get('state') != MEM_COMMIT:
        return []
    protect = region.get('protect', 0) & 0xFF
    kind, backing = region.get('type'), region.get('file')
    found = []
    if protect in WRITABLE_EXECUTABLE and (kind == MEM_PRIVATE or (kind == MEM_MAPPED and not backing)):
        found.append('anonymous_rwx')
    if protect in EXECUTABLE and kind == MEM_IMAGE and backing and writable_dir(backing):
        found.append('writable_dir_code_mapping')
    return found


def fileless_executable(region):
    """Executable memory with no file behind it: private, or a pagefile-backed section."""
    return (region.get('state') == MEM_COMMIT and (region.get('protect', 0) & 0xFF) in EXECUTABLE
            and (region.get('type') == MEM_PRIVATE or (region.get('type') == MEM_MAPPED and not region.get('file'))))


def executing_from_fileless(info):
    """Start addresses of threads that began in fileless executable memory."""
    regions = [r for r in info.get('regions') or () if fileless_executable(r)]
    return sorted({address for address in info.get('thread_starts') or ()
                   if any(r['base'] <= address < r['base'] + r['size'] for r in regions)})


def temp_files(info):
    """Every executable file of the process that lies in a folder anyone can write."""
    files = set()
    if info.get('image') and writable_dir(info['image']):
        files.add(info['image'])
    for region in info.get('regions') or ():
        if 'writable_dir_code_mapping' in region_indicators(region):
            files.add(region['file'])
    return files


APPROVALS = 'approved-setup.json'


def _approval_text(sha256, expires):
    return ('satsuma-setup-approval:%s:%d' % (sha256, int(expires))).encode('ascii')


def load_approvals(directory, key, clock=time.time):
    """SHA-256 of Satsuma setups approved with the administrator password, signed by this machine's key, unexpired.

    An approval without a valid signature of the machine key (satsuma_win.machine_key)
    approves nothing. Makine anahtarının geçerli imzası olmayan onay hiçbir şeyi onaylamaz.
    """
    if key is None:
        return frozenset()
    try:
        rows = json.loads((directory / APPROVALS).read_text(encoding='utf-8'))
    except (OSError, ValueError):
        return frozenset()
    now = clock()
    return frozenset(str(row['sha256']).lower() for row in rows if isinstance(row, dict)
                     and re.fullmatch(r'[0-9a-f]{64}', str(row.get('sha256', '')))
                     and isinstance(row.get('expires'), (int, float)) and row['expires'] > now
                     and key.verify(_approval_text(row['sha256'], row['expires']), row.get('signature', '')))


def approve_setup(directory, sha256, key, minutes=30, clock=time.time):
    """Record one approved setup for ``minutes``, signed with the machine key.

    Called by the service when the owner approves an update in the panel with the
    administrator password. Sahibi panelde yönetici parolasıyla onayladığında hizmet çağırır.
    """
    if not re.fullmatch(r'[0-9a-fA-F]{64}', str(sha256)) or not 1 <= minutes <= 120:
        raise ValueError('invalid setup approval')
    try:
        rows = json.loads((directory / APPROVALS).read_text(encoding='utf-8'))
    except (OSError, ValueError):
        rows = []
    now = clock()
    rows = [r for r in rows if isinstance(r, dict) and isinstance(r.get('expires'), (int, float)) and r['expires'] > now]
    expires = int(now + minutes * 60)
    rows.append({'sha256': sha256.lower(), 'expires': expires,
                 'signature': key.sign(_approval_text(sha256.lower(), expires))})
    temporary = directory / (APPROVALS + '.tmp')
    temporary.write_text(json.dumps(rows), encoding='utf-8')
    os.replace(temporary, directory / APPROVALS)
    return rows


LOCATIONS = 'approved-locations.json'
PENDING = 'pending-approvals.json'


def _folder(path):
    folder = _lower(path).rstrip('\\')
    if not re.fullmatch(r'[a-z]:\\[^*?"<>|]+', folder):
        raise ValueError('not an absolute folder: ' + str(path))
    return folder + '\\'


def _location_text(folder):
    return ('satsuma-approved-location:' + folder).encode('utf-8')


def approve_location(directory, folder, key):
    """Approve one folder as an expected program location, signed with the machine key.

    Owner's decision 2026-11-11 (weakens protection, only for folders the owner
    approves with the administrator password: at installation in the wizard,
    later in the panel). A thread started from fileless memory is still stopped
    there. Sahibinin kararı: yalnızca yönetici parolasıyla onaylanan klasörler.
    """
    folder = _folder(folder)
    try:
        rows = json.loads((Path(directory) / LOCATIONS).read_text(encoding='utf-8'))
    except (OSError, ValueError):
        rows = []
    rows = [r for r in rows if isinstance(r, dict) and r.get('folder') != folder]
    rows.append({'folder': folder, 'signature': key.sign(_location_text(folder))})
    temporary = Path(directory) / (LOCATIONS + '.tmp')
    temporary.write_text(json.dumps(rows), encoding='utf-8')
    os.replace(temporary, Path(directory) / LOCATIONS)
    return folder


def load_locations(directory, key):
    """Approved folders whose signature of the machine key verifies; anything else is ignored."""
    if key is None:
        return ()
    try:
        rows = json.loads((Path(directory) / LOCATIONS).read_text(encoding='utf-8'))
    except (OSError, ValueError):
        return ()
    found = []
    for row in rows if isinstance(rows, list) else ():
        try:
            folder = _folder(row['folder'])
        except (KeyError, TypeError, ValueError):
            continue
        if folder == row['folder'] and key.verify(_location_text(folder), row.get('signature', '')):
            found.append(folder)
    return tuple(found)


def expected_location(image, approved=()):
    """The program file lies under the Windows folder, Program Files or an approved folder."""
    if not image:
        return False
    return trusted_location(image) or any(_lower(image).startswith(folder) for folder in approved)


def apply_install_approvals(directory, key, created):
    """Sign the approvals the installer wrote, only on the first start that created the machine key.

    The wizard writes them after the administrator password; later approvals come
    from the panel. On a later start the file is ignored and removed. Sihirbaz
    yönetici parolasından sonra yazar; yalnızca anahtarı oluşturan ilk açılışta imzalanır.
    """
    pending = Path(directory) / PENDING
    if not pending.exists():
        return None
    try:
        request = json.loads(pending.read_text(encoding='utf-8'))
    except (OSError, ValueError):
        request = {}
    done = {'locations': [], 'setups': [], 'owner': None, 'ignored': not created}
    if created and isinstance(request, dict):
        if request.get('owner'):
            from .accounts import approve_owner
            done['owner'] = approve_owner(directory, request['owner'], key)
        for folder in request.get('locations') or ():
            done['locations'].append(approve_location(directory, folder, key))
        for digest in request.get('setups') or ():
            approve_setup(Path(directory), str(digest), key, minutes=int(request.get('minutes', 30)))
            done['setups'].append(str(digest).lower())
    pending.unlink()
    return done


def indicators(info):
    """Every indicator of one process read by the reader, sorted and without repeats."""
    found = []
    for region in info.get('regions') or ():
        found.extend(region_indicators(region))
    image = info.get('image')
    if image and writable_dir(image):
        found.append('writable_dir_code_mapping')
    if image and info.get('image_exists') is False:
        found.append('deleted_executable')
    if info.get('debugged'):
        found.append('process_traced')
    return sorted(set(found))


def _own_clamav(image, environ=os.environ):
    folder = _lower(os.path.join(environ.get('ProgramFiles', r'C:\Program Files'), 'Satsuma', 'ClamAV')) + '\\'
    return image.startswith(folder) and image[len(folder):] in SATSUMA_CLAMAV


def exemption(info, own_pid, satsuma_exe=None):
    """Why this process cannot be stopped, or None.

    A Windows critical process (stopping it crashes Windows, like PID 1 on Linux;
    the finding carries a critical alarm instead), the service itself, its own
    PowerShell and its own ClamAV children. Nothing else, whatever its name.

    Durdurulamayacak sürecin nedeni ya da None: Windows kritik süreci (durdurulursa
    Windows çöker; bulgu kritik alarm taşır), hizmetin kendisi, kendi PowerShell'i
    ve kendi ClamAV alt süreçleri. Adı ne olursa olsun başka hiçbir şey.
    """
    pid, image = info.get('pid'), _lower(info.get('image'))
    name = image.rsplit('\\', 1)[-1]
    if pid in (0, 4) or info.get('critical'):
        return 'windows_critical_process'
    if pid == own_pid or (satsuma_exe and image == _lower(satsuma_exe)):
        return 'satsuma_service'
    # The one-file exe runs as two processes (launcher and Python); both are this program.
    # Tek dosyalık exe iki süreç olarak çalışır (başlatıcı ve Python); ikisi de bu programdır.
    if name == SATSUMA_EXE and pid == os.getppid():
        return 'satsuma_service'
    if info.get('parent') == own_pid and image.endswith(SATSUMA_POWERSHELL):
        return 'satsuma_powershell'
    if info.get('parent') == own_pid and _own_clamav(image):
        return 'satsuma_clamav'
    return None


def evidence(info, indicator, limit=4):
    """A few regions behind the indicator, for the record. Kayıt için göstergenin arkasındaki birkaç bölge."""
    rows = []
    for region in info.get('regions') or ():
        if indicator in region_indicators(region):
            rows.append({'address': hex(region.get('base') or 0), 'size': region.get('size'),
                         'protect': hex(region.get('protect') or 0), 'type': hex(region.get('type') or 0),
                         'file': region.get('file')})
            if len(rows) >= limit:
                break
    return rows


class Scanner:
    """Reads processes, decides with the shared rules, stops through the read handle and records."""

    def __init__(self, rules, reader, record, own_pid=None, satsuma_exe=None, enforce=True,
                 approvals=lambda: frozenset(), locations=lambda: ()):
        from satsuma import memory_decision
        self.decide = lambda indicator, **facts: memory_decision.decide(indicator, rules, **facts)
        self.approvals, self.locations = approvals, locations
        self.reader, self.record, self.enforce = reader, record, enforce
        self.own_pid = os.getpid() if own_pid is None else own_pid
        long_path = getattr(reader, 'long_path', None)
        self.satsuma_exe = long_path(satsuma_exe) if (satsuma_exe and long_path) else satsuma_exe
        self.seen = set()
        self.counts = {'scanned': 0, 'unreadable': 0, 'stopped': 0, 'stop_failed': 0, 'recorded': 0, 'exempt': 0}

    def scan(self, pids=None):
        results = []
        for pid in (self.reader.pids() if pids is None else pids):
            if pid == self.own_pid:
                continue
            with self.reader.open(pid) as process:
                if process is None:
                    self.counts['unreadable'] += 1
                    continue
                try:
                    info = process.read()
                except OSError:
                    self.counts['unreadable'] += 1
                    continue
                self.counts['scanned'] += 1
                results.extend(self._handle(process, info))
        return results

    def _handle(self, process, info):
        found = indicators(info)
        if not found:
            return []
        approved = self.approvals()
        facts = {'signed': info.get('temp_signed') is True,
                 'executing': (bool(executing_from_fileless(info)) if 'thread_starts' in info else None),
                 'expected_location': expected_location(info.get('image'), self.locations()),
                 'approved_setup': bool(approved) and bool({info.get('image_sha256'), info.get('parent_sha256')}
                                                           & approved)}
        decisions = [d for d in (self.decide(i, **facts) for i in found) if d]
        if not decisions:
            return []
        key = (info['pid'], info.get('created'), tuple(d['indicator'] for d in decisions))
        if key in self.seen:
            return []
        self.seen.add(key)
        reason = exemption(info, self.own_pid, self.satsuma_exe)
        stop = any(d['stop'] for d in decisions) and self.enforce and not reason
        outcome, error = ('recorded', None)
        if reason and any(d['stop'] for d in decisions):
            outcome = 'exempt'
        if stop:
            try:
                process.terminate(info.get('created'))
                outcome = 'stopped'
            except OSError as exc:
                outcome, error = 'stop_failed', str(exc)[:300]
        self.counts[outcome] += 1
        events = []
        for decision in decisions:
            fields = {'pid': info['pid'], 'image': info.get('image'), 'parent': info.get('parent'),
                      'rule_id': decision['rule_id'], 'rule': decision['name'], 'indicator': decision['indicator'],
                      'rule_stops': decision['stop'], 'outcome': outcome,
                      'regions': evidence(info, decision['indicator'])}
            if decision.get('kept'):
                fields['kept'] = decision['kept']
            if decision.get('stop_reason'):
                fields['stop_reason'] = decision['stop_reason']
            starts = executing_from_fileless(info)
            if starts and decision['indicator'] == 'anonymous_rwx':
                fields['thread_starts'] = [hex(a) for a in starts[:8]]
            if reason:
                fields['exempt'] = reason
                if reason == 'windows_critical_process' and decision['stop']:
                    # It cannot be stopped: a critical alarm, never a silent record.
                    fields['alarm'] = 'critical'
            if error:
                fields['error'] = error
            events.append(self.record('memory_finding', **fields))
        return events


class Win32Reader:
    """The Windows side: process list, one handle per process, memory map, termination."""

    def __init__(self):
        import ctypes
        from ctypes import wintypes
        self.ctypes, self.wintypes = ctypes, wintypes
        self.kernel32 = ctypes.WinDLL('kernel32', use_last_error=True)
        self.advapi32 = ctypes.WinDLL('advapi32', use_last_error=True)

        class MBI(ctypes.Structure):
            _fields_ = [('BaseAddress', ctypes.c_void_p), ('AllocationBase', ctypes.c_void_p),
                        ('AllocationProtect', wintypes.DWORD), ('PartitionId', wintypes.WORD),
                        ('RegionSize', ctypes.c_size_t), ('State', wintypes.DWORD),
                        ('Protect', wintypes.DWORD), ('Type', wintypes.DWORD)]
        self.MBI = MBI
        k = self.kernel32
        k.OpenProcess.restype = wintypes.HANDLE
        k.OpenProcess.argtypes = (wintypes.DWORD, wintypes.BOOL, wintypes.DWORD)
        k.CloseHandle.argtypes = (wintypes.HANDLE,)
        k.VirtualQueryEx.restype = ctypes.c_size_t
        k.VirtualQueryEx.argtypes = (wintypes.HANDLE, ctypes.c_void_p, ctypes.POINTER(MBI), ctypes.c_size_t)
        k.K32GetMappedFileNameW.restype = wintypes.DWORD
        k.K32GetMappedFileNameW.argtypes = (wintypes.HANDLE, ctypes.c_void_p, wintypes.LPWSTR, wintypes.DWORD)
        k.QueryFullProcessImageNameW.argtypes = (wintypes.HANDLE, wintypes.DWORD, wintypes.LPWSTR,
                                                 ctypes.POINTER(wintypes.DWORD))
        k.CheckRemoteDebuggerPresent.argtypes = (wintypes.HANDLE, ctypes.POINTER(wintypes.BOOL))
        k.IsProcessCritical.argtypes = (wintypes.HANDLE, ctypes.POINTER(wintypes.BOOL))
        k.GetProcessTimes.argtypes = (wintypes.HANDLE,) + (ctypes.POINTER(wintypes.FILETIME),) * 4
        k.TerminateProcess.argtypes = (wintypes.HANDLE, wintypes.UINT)
        k.GetLongPathNameW.restype = wintypes.DWORD
        k.QueryDosDeviceW.argtypes = (wintypes.LPCWSTR, wintypes.LPWSTR, wintypes.DWORD)
        k.GetLongPathNameW.argtypes = (wintypes.LPCWSTR, wintypes.LPWSTR, wintypes.DWORD)
        self.wintrust = ctypes.WinDLL('wintrust')
        self.ntdll = ctypes.WinDLL('ntdll')
        self.ntdll.NtQueryInformationThread.restype = ctypes.c_long
        self.ntdll.NtQueryInformationThread.argtypes = (wintypes.HANDLE, ctypes.c_int, ctypes.c_void_p,
                                                        wintypes.ULONG, ctypes.POINTER(wintypes.ULONG))
        k.OpenThread.restype = wintypes.HANDLE
        k.OpenThread.argtypes = (wintypes.DWORD, wintypes.BOOL, wintypes.DWORD)
        k.CreateToolhelp32Snapshot.restype = wintypes.HANDLE
        k.CreateToolhelp32Snapshot.argtypes = (wintypes.DWORD, wintypes.DWORD)

        class THREADENTRY32(ctypes.Structure):
            _fields_ = [('dwSize', wintypes.DWORD), ('cntUsage', wintypes.DWORD), ('th32ThreadID', wintypes.DWORD),
                        ('th32OwnerProcessID', wintypes.DWORD), ('tpBasePri', wintypes.LONG),
                        ('tpDeltaPri', wintypes.LONG), ('dwFlags', wintypes.DWORD)]
        self.THREADENTRY32 = THREADENTRY32
        k.Thread32First.argtypes = (wintypes.HANDLE, ctypes.POINTER(THREADENTRY32))
        k.Thread32Next.argtypes = (wintypes.HANDLE, ctypes.POINTER(THREADENTRY32))
        self.trust_cache, self.hash_cache = {}, {}
        self.devices = self._devices()
        self.debug_privilege = self._enable_debug_privilege()

    def _devices(self):
        """\\Device\\HarddiskVolumeN -> C: for every drive letter."""
        result, buffer = {}, self.ctypes.create_unicode_buffer(1024)
        for letter in 'ABCDEFGHIJKLMNOPQRSTUVWXYZ':
            if self.kernel32.QueryDosDeviceW(letter + ':', buffer, 1024):
                result[buffer.value.lower()] = letter + ':'
        return result

    def dos_path(self, device_path):
        lowered = device_path.lower()
        for device, drive in self.devices.items():
            if lowered.startswith(device + '\\'):
                return self.long_path(drive + device_path[len(device):])
        return device_path

    def long_path(self, path):
        """The long form of a path: a short 8.3 name (APPDAT~1) must not hide a Temp folder.

        Yolun uzun biçimi: kısa 8.3 adı (APPDAT~1) bir Temp klasörünü gizleyemez.
        """
        if not path or '~' not in path:
            return path
        buffer = self.ctypes.create_unicode_buffer(32768)
        return buffer.value if self.kernel32.GetLongPathNameW(path, buffer, 32768) else path

    def _enable_debug_privilege(self):
        ctypes, wintypes, advapi = self.ctypes, self.wintypes, self.advapi32

        class LUID(ctypes.Structure):
            _fields_ = [('LowPart', wintypes.DWORD), ('HighPart', wintypes.LONG)]

        class PRIVILEGES(ctypes.Structure):
            _fields_ = [('PrivilegeCount', wintypes.DWORD), ('Luid', LUID), ('Attributes', wintypes.DWORD)]
        token = wintypes.HANDLE()
        self.kernel32.GetCurrentProcess.restype = wintypes.HANDLE
        self.kernel32.GetCurrentProcess.argtypes = ()
        advapi.OpenProcessToken.argtypes = (wintypes.HANDLE, wintypes.DWORD, ctypes.POINTER(wintypes.HANDLE))
        advapi.LookupPrivilegeValueW.argtypes = (wintypes.LPCWSTR, wintypes.LPCWSTR, ctypes.POINTER(LUID))
        advapi.AdjustTokenPrivileges.argtypes = (wintypes.HANDLE, wintypes.BOOL, ctypes.POINTER(PRIVILEGES),
                                                 wintypes.DWORD, ctypes.c_void_p, ctypes.c_void_p)
        if not advapi.OpenProcessToken(self.kernel32.GetCurrentProcess(), 0x0020 | 0x0008, ctypes.byref(token)):
            return False
        try:
            luid = LUID()
            if not advapi.LookupPrivilegeValueW(None, 'SeDebugPrivilege', ctypes.byref(luid)):
                return False
            privileges = PRIVILEGES(1, luid, 0x2)
            advapi.AdjustTokenPrivileges(token, False, ctypes.byref(privileges), 0, None, None)
            return ctypes.get_last_error() == 0
        finally:
            self.kernel32.CloseHandle(token)

    def _key(self, path):
        stat = os.stat(path)
        return (path.lower(), stat.st_mtime_ns, stat.st_size)

    def signed(self, path):
        """True when the file carries a valid publisher signature (WinVerifyTrust, no network)."""
        try:
            key = self._key(path)
        except OSError:
            return False
        if key not in self.trust_cache:
            self.trust_cache[key] = self._verify_trust(path)
        return self.trust_cache[key]

    def _verify_trust(self, path):
        ctypes, w = self.ctypes, self.wintypes

        class GUID(ctypes.Structure):
            _fields_ = [('Data1', w.DWORD), ('Data2', w.WORD), ('Data3', w.WORD), ('Data4', w.BYTE * 8)]

        class FILE_INFO(ctypes.Structure):
            _fields_ = [('cbStruct', w.DWORD), ('pcwszFilePath', w.LPCWSTR), ('hFile', w.HANDLE),
                        ('pgKnownSubject', ctypes.c_void_p)]

        class TRUST_DATA(ctypes.Structure):
            _fields_ = [('cbStruct', w.DWORD), ('pPolicyCallbackData', ctypes.c_void_p),
                        ('pSIPClientData', ctypes.c_void_p), ('dwUIChoice', w.DWORD),
                        ('fdwRevocationChecks', w.DWORD), ('dwUnionChoice', w.DWORD),
                        ('pFile', ctypes.POINTER(FILE_INFO)), ('dwStateAction', w.DWORD),
                        ('hWVTStateData', w.HANDLE), ('pwszURLReference', w.LPCWSTR),
                        ('dwProvFlags', w.DWORD), ('dwUIContext', w.DWORD), ('pSignatureSettings', ctypes.c_void_p)]
        action = GUID(0x00AAC56B, 0xCD44, 0x11D0, (w.BYTE * 8)(*[b - 256 if b > 127 else b for b in
                                                                (0x8C, 0xC2, 0x00, 0xC0, 0x4F, 0xC2, 0x95, 0xEE)]))
        file_info = FILE_INFO(ctypes.sizeof(FILE_INFO), path, None, None)
        data = TRUST_DATA()
        data.cbStruct = ctypes.sizeof(TRUST_DATA)
        data.dwUIChoice, data.fdwRevocationChecks, data.dwUnionChoice = 2, 0, 1   # no UI, file
        data.pFile = ctypes.pointer(file_info)
        data.dwStateAction = 1                                                    # verify
        data.dwProvFlags = 0x1000                                                 # cache only, no network
        verify = self.wintrust.WinVerifyTrust
        verify.restype = w.LONG
        verify.argtypes = (w.HWND, ctypes.POINTER(GUID), ctypes.c_void_p)
        result = verify(None, ctypes.byref(action), ctypes.byref(data))
        data.dwStateAction = 2                                                    # close
        verify(None, ctypes.byref(action), ctypes.byref(data))
        return result == 0

    def sha256(self, path):
        try:
            key = self._key(path)
        except OSError:
            return None
        if key not in self.hash_cache:
            digest = hashlib.sha256()
            try:
                with open(path, 'rb') as stream:
                    for block in iter(lambda: stream.read(1 << 20), b''):
                        digest.update(block)
            except OSError:
                return None
            self.hash_cache[key] = digest.hexdigest()
        return self.hash_cache[key]

    def thread_starts(self, pid):
        """Start address of every thread of ``pid`` (ThreadQuerySetWin32StartAddress)."""
        ctypes, w, k = self.ctypes, self.wintypes, self.kernel32
        snapshot = k.CreateToolhelp32Snapshot(0x4, 0)                      # TH32CS_SNAPTHREAD
        if not snapshot or snapshot == w.HANDLE(-1).value:
            raise OSError(ctypes.get_last_error(), 'CreateToolhelp32Snapshot')
        starts = []
        try:
            entry = self.THREADENTRY32()
            entry.dwSize = ctypes.sizeof(entry)
            more = k.Thread32First(snapshot, ctypes.byref(entry))
            while more:
                if entry.th32OwnerProcessID == pid:
                    thread = k.OpenThread(0x0040, False, entry.th32ThreadID)  # THREAD_QUERY_INFORMATION
                    if thread:
                        try:
                            address = ctypes.c_void_p()
                            if self.ntdll.NtQueryInformationThread(thread, 9, ctypes.byref(address),
                                                                   ctypes.sizeof(address), None) == 0:
                                starts.append(address.value or 0)
                        finally:
                            k.CloseHandle(thread)
                more = k.Thread32Next(snapshot, ctypes.byref(entry))
        finally:
            k.CloseHandle(snapshot)
        return starts

    def stop_if_image(self, pid, image):
        """Stop ``pid`` only if its program file is still ``image``; returns 'stopped', 'gone' or 'changed'."""
        k, ctypes, w = self.kernel32, self.ctypes, self.wintypes
        handle = k.OpenProcess(0x1000 | 0x0001, False, pid)   # query limited information, terminate
        if not handle:
            error = ctypes.get_last_error()
            if error == 87:                                    # ERROR_INVALID_PARAMETER: no such process
                return 'gone'
            raise OSError(error, 'OpenProcess')
        try:
            size, buffer = w.DWORD(32768), ctypes.create_unicode_buffer(32768)
            if not k.QueryFullProcessImageNameW(handle, 0, buffer, ctypes.byref(size)):
                return 'gone'
            if _lower(self.long_path(buffer.value)) != _lower(self.long_path(image)):
                return 'changed'
            if not k.TerminateProcess(handle, 0xC5A75B):
                raise OSError(ctypes.get_last_error(), 'TerminateProcess')
            return 'stopped'
        finally:
            k.CloseHandle(handle)

    def pids(self):
        import psutil
        return psutil.pids()

    def open(self, pid):
        return _Win32Process(self, pid)


class _Win32Process:
    FULL = 0x0400 | 0x0010 | 0x0001 | 0x00100000      # query, read, terminate, synchronize
    READ_ONLY = 0x0400 | 0x0010

    def __init__(self, reader, pid):
        self.reader, self.pid, self.handle = reader, pid, None

    def __enter__(self):
        k = self.reader.kernel32
        self.handle = k.OpenProcess(self.FULL, False, self.pid) or k.OpenProcess(self.READ_ONLY, False, self.pid)
        return self if self.handle else None

    def __exit__(self, *exc):
        if self.handle:
            self.reader.kernel32.CloseHandle(self.handle)
        return False

    def _created(self):
        w, k = self.reader.wintypes, self.reader.kernel32
        times = [w.FILETIME() for _ in range(4)]
        if not k.GetProcessTimes(self.handle, *(self.reader.ctypes.byref(t) for t in times)):
            raise OSError(self.reader.ctypes.get_last_error(), 'GetProcessTimes')
        return (times[0].dwHighDateTime << 32) | times[0].dwLowDateTime

    def read(self):
        ctypes, w, k = self.reader.ctypes, self.reader.wintypes, self.reader.kernel32
        size, buffer = w.DWORD(32768), ctypes.create_unicode_buffer(32768)
        image = (self.reader.long_path(buffer.value)
                 if k.QueryFullProcessImageNameW(self.handle, 0, buffer, ctypes.byref(size)) else None)
        flag = w.BOOL()
        debugged = bool(k.CheckRemoteDebuggerPresent(self.handle, ctypes.byref(flag)) and flag.value)
        critical_flag = w.BOOL()
        critical = bool(k.IsProcessCritical(self.handle, ctypes.byref(critical_flag)) and critical_flag.value)
        try:
            import psutil
            parent = psutil.Process(self.pid).ppid()
        except Exception:  # the parent is context for the record and the setup approval
            parent = None
        regions, address, mbi, name = [], 0, self.reader.MBI(), ctypes.create_unicode_buffer(1024)
        while len(regions) < 200000 and k.VirtualQueryEx(self.handle, ctypes.c_void_p(address),
                                                         ctypes.byref(mbi), ctypes.sizeof(mbi)):
            base, length = mbi.BaseAddress or 0, mbi.RegionSize
            if mbi.State == MEM_COMMIT and (mbi.Protect & 0xFF) in EXECUTABLE:
                backing = None
                if mbi.Type in (MEM_MAPPED, MEM_IMAGE) and k.K32GetMappedFileNameW(
                        self.handle, ctypes.c_void_p(base), name, 1024):
                    backing = self.reader.dos_path(name.value)
                regions.append({'base': base, 'size': length, 'state': mbi.State, 'protect': mbi.Protect,
                                'type': mbi.Type, 'file': backing})
            if not length:
                break
            address = base + length
        info = {'pid': self.pid, 'created': self._created(), 'image': image,
                'thread_starts': self.reader.thread_starts(self.pid),
                'image_exists': os.path.exists(image) if image else None,
                'debugged': debugged, 'critical': critical, 'parent': parent, 'regions': regions}
        files = temp_files(info)
        if files:
            # Only for code in a writable folder: signatures and the setup approval decide there.
            info['temp_signed'] = all(self.reader.signed(path) for path in files)
            info['image_sha256'] = self.reader.sha256(image) if image else None
            try:
                import psutil
                parent_image = psutil.Process(parent).exe() if parent else None
            except Exception:  # an exited or unreadable parent cannot approve anything
                parent_image = None
            info['parent_image'] = parent_image
            info['parent_sha256'] = self.reader.sha256(parent_image) if parent_image else None
        return info

    def terminate(self, created):
        """Stop the process read through this handle, only if it is still the same process."""
        if self._created() != created:
            raise OSError('process identity changed')
        if not self.reader.kernel32.TerminateProcess(self.handle, 0xC5A75A):
            raise OSError(self.reader.ctypes.get_last_error(), 'TerminateProcess')
