"""Keep the memory scanner able to see: ptrace_scope must be exactly 2.

Owner's decision 2026-11-10: ptrace_scope stays 2, because 3 blinds the RAM
scanner. Owner's report 2026-11-12: attackers keep blocking the RAM module.
Until 2.2.36 a value of 3 was accepted as "stronger": a single line in any
sysctl file sorting after 90-satsuma-memory.conf (or a sysctl.* argument on
the kernel command line) left the scanner BLOCKED on every boot, and
Satsuma reported it as a normal state.

The kernel refuses to lower 3 while running, so this module does what can
be done and says what cannot:

* sources(): every sysctl file and boot argument that sets
  kernel.yama.ptrace_scope to anything but 2 (Satsuma's own file excluded);
* neutralize(): the offending line is commented out in place, after the
  whole original file is copied to the evidence folder. Files are never
  deleted and no other line is changed, so the next boot comes up with 2;
* boot arguments are removed from every installed kernel by
  satsuma-kernel-profile (kernel_profile.apply_boot), the unit that may
  write /boot; the kernel guard only starts it.

Bellek tarayıcısının görebilmesi için ptrace_scope tam olarak 2 olmalıdır.

Sahibinin kararı 2026-11-10: ptrace_scope 2 kalır; 3 RAM tarayıcısını kör
eder. Sahibinin bildirimi 2026-11-12: saldırganlar RAM modülünü sürekli
engelliyor. 2.2.36'ya kadar 3 "daha sıkı" sayılıp kabul ediliyordu:
90-satsuma-memory.conf'tan sonra sıralanan herhangi bir sysctl dosyasındaki
tek satır (ya da çekirdek komut satırındaki sysctl.* bağımsız değişkeni)
tarayıcıyı her açılışta BLOCKED bırakıyor, Satsuma bunu olağan durum diye
gösteriyordu. Çekirdek çalışırken 3'ü düşürmeye izin vermez; bu modül
yapılabileni yapar, yapılamayanı söyler: kaynağı bulur, dosyanın tamamını
kanıt klasörüne kopyalar, yalnızca o satırı yorum satırına çevirir (dosya
silinmez, başka satıra dokunulmaz) ve açılış bağımsız değişkenini grubby
ile bütün çekirdeklerden kaldırır. Böylece sonraki açılış 2 ile gelir.
"""
import os
import re
import shutil
import stat
import time
from pathlib import Path

REQUIRED = '2'
KEY = 'kernel/yama/ptrace_scope'
OWN_FILE = Path('/usr/lib/sysctl.d/90-satsuma-memory.conf')
# systemd-sysctl's search path, plus the legacy file Fedora links into it.
SYSCTL_DIRS = (Path('/etc/sysctl.d'), Path('/run/sysctl.d'), Path('/usr/local/lib/sysctl.d'),
               Path('/usr/lib/sysctl.d'), Path('/lib/sysctl.d'))
LEGACY_FILES = (Path('/etc/sysctl.conf'),)
EVIDENCE = Path('/var/lib/satsuma-core/kernel-guard/ptrace-sources')
MARK = '# satsuma 2.2.37: ptrace_scope must stay 2 (RAM scanner); original kept in ' + str(EVIDENCE) + ': '
# "kernel.yama.ptrace_scope = 3", "-kernel/yama/ptrace_scope=3", spaces optional.
_LINE = re.compile(r'^\s*-?\s*kernel[./]yama[./]ptrace_scope\s*=\s*(\S*)\s*$')
_ARG = re.compile(r'^sysctl\.kernel[./]yama[./]ptrace_scope=(.*)$')


def _files(dirs=SYSCTL_DIRS):
    """basename -> the file systemd-sysctl reads for it (first directory wins)."""
    chosen = {}
    for directory in dirs:
        try:
            names = sorted(os.listdir(directory))
        except OSError:
            continue
        for name in names:
            if name.endswith('.conf') and name not in chosen:
                chosen[name] = Path(directory, name)
    return chosen


def _settings(path):
    try:
        text = path.read_text(errors='replace')
    except OSError:
        return []
    return [(number, match[1], line.strip()[:200]) for number, line in enumerate(text.splitlines(), 1)
            for match in [_LINE.match(line)] if match]


def sources(dirs=SYSCTL_DIRS, legacy=LEGACY_FILES, own=OWN_FILE, cmdline='/proc/cmdline', entries=None):
    """Every place that would leave ptrace_scope away from 2 after boot.

    * 3 anywhere: once written the kernel never lowers it, whatever comes later;
    * any other value only where it wins over Satsuma's file: a file sorting
      after it, the legacy /etc/sysctl.conf, or a file with the same name that
      replaces it. Fedora's 10-default-yama-scope.conf (0) sorts before and is
      overridden, so it is left alone;
    * boot arguments: 3 only, because systemd-sysctl writes 2 over 0 or 1.
    entries: kernel -> words of its boot line (kernel_profile.boot_entries), so an
    argument added for the next boot is found before that boot.

    Açılıştan sonra ptrace_scope'u 2'den başka bırakacak her yer: 3 her yerde
    (bir kez yazılınca çekirdek düşürmez); başka değerler yalnızca Satsuma'nın
    dosyasını geçtiği yerde; açılış bağımsız değişkeninde yalnızca 3.
    """
    found = []
    files = _files(dirs)
    own_path = files.get(own.name)
    if own_path is not None and own_path != own:
        found.append({'kind': 'shadowing_file', 'path': str(own_path), 'shadows': str(own)})
    for name, path in sorted(files.items()):
        if path == own or name == own.name:
            continue
        wins = name > own.name
        for number, value, text in _settings(path):
            if value != REQUIRED and (value == '3' or wins):
                found.append({'kind': 'sysctl_file', 'path': str(path), 'line': number, 'value': value, 'text': text})
    for path in legacy:
        # Fedora links /etc/sysctl.d/99-sysctl.conf to it: one file, reported once.
        if any(os.path.realpath(path) == os.path.realpath(item['path']) for item in found if 'path' in item):
            continue
        for number, value, text in _settings(path):
            if value != REQUIRED:
                found.append({'kind': 'sysctl_file', 'path': str(path), 'line': number, 'value': value, 'text': text})
    try:
        arguments = Path(cmdline).read_text().split()
    except OSError:
        arguments = []
    for words in (entries or {}).values():
        arguments += sorted(words)
    for argument in dict.fromkeys(arguments):
        match = _ARG.match(argument)
        if match and match[1] == '3':
            found.append({'kind': 'boot_argument', 'argument': argument[:200], 'value': match[1]})
    return found


def _neutralize_file(path, lines, evidence, clock):
    """Copy the original aside, then comment out only the offending lines."""
    real = Path(os.path.realpath(path))
    info = real.lstat()
    if not stat.S_ISREG(info.st_mode):
        raise PermissionError('not_a_regular_file')
    evidence.mkdir(parents=True, exist_ok=True, mode=0o700)
    os.chmod(evidence, 0o700)
    copy = evidence / f'{int(clock())}-{str(real).strip("/").replace("/", "_")}'
    shutil.copy2(real, copy)
    os.chmod(copy, 0o600)
    original = real.read_text(errors='replace').splitlines(keepends=True)
    for number in lines:
        line = original[number - 1]
        if _LINE.match(line.rstrip('\n')):
            original[number - 1] = MARK + line.lstrip()
            if not original[number - 1].endswith('\n'):
                original[number - 1] += '\n'
    temporary = real.with_name('.' + real.name + '.satsuma-tmp')
    try:
        os.unlink(temporary)
    except FileNotFoundError:
        pass
    fd = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, stat.S_IMODE(info.st_mode))
    try:
        os.write(fd, ''.join(original).encode())
        os.fsync(fd)
        os.close(fd)
        fd = None
        # The rewritten file belongs to root: whoever owned the original no
        # longer controls it. Yeniden yazılan dosya root'a aittir.
        os.replace(temporary, real)
    finally:
        if fd is not None:
            os.close(fd)
        if os.path.lexists(temporary):
            os.unlink(temporary)
    return str(copy)


def boot_arguments(found):
    """The boot arguments among the sources, for kernel_profile.apply_boot to remove."""
    return [item['argument'] for item in found if item['kind'] == 'boot_argument']


def neutralize(found, evidence=EVIDENCE, clock=time.time):
    """Undo every sysctl file found; report each one as done or failed, never silently.

    Boot arguments are only reported here (needs_boot_unit): /boot is written by
    satsuma-kernel-profile, never by the kernel guard.
    """
    results = []
    by_file = {}
    for item in found:
        if item['kind'] == 'sysctl_file':
            by_file.setdefault(item['path'], []).append(item)
    for path, items in by_file.items():
        try:
            copy = _neutralize_file(path, [i['line'] for i in items], Path(evidence), clock)
            results += [{**i, 'neutralized': True, 'evidence': copy} for i in items]
        except OSError as exc:
            results += [{**i, 'neutralized': False, 'error': exc.strerror or str(exc)} for i in items]
    for item in found:
        if item['kind'] != 'shadowing_file':
            continue
        # A file named like Satsuma's replaces it entirely: moved to evidence, not deleted.
        # Satsuma'nın dosyasıyla aynı adlı dosya onu tamamen gölgeler: kanıta taşınır, silinmez.
        try:
            target = Path(evidence)
            target.mkdir(parents=True, exist_ok=True, mode=0o700)
            moved = target / f'{int(clock())}-{item["path"].strip("/").replace("/", "_")}'
            shutil.move(item['path'], moved)
            os.chmod(moved, 0o600)
            results.append({**item, 'neutralized': True, 'evidence': str(moved)})
        except OSError as exc:
            results.append({**item, 'neutralized': False, 'error': exc.strerror or str(exc)})
    results += [{**item, 'neutralized': False, 'needs_boot_unit': True, 'reboot_needed': True}
                for item in found if item['kind'] == 'boot_argument']
    return results
