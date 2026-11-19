"""The strictest kernel profile, its saved pattern, and putting it back after a change.

The user's decision (2026-11-10): the kernel runs with the strictest settings,
the pattern of those settings is recorded in Satsuma, and whenever the kernel
changes (a setting at run time, the boot command line, a new kernel package)
the same picture is put back. The values live here, in code; the saved
pattern (/var/lib/satsuma-core/kernel-guard/profile.json) is a record and a
tamper check, never a source: a file cannot weaken the profile.

* Run-time settings (sysctl): shipped in 93-satsuma-strict.conf for the boot,
  and the kernel guard writes back every one that is weakened, every second.
  ptrace_scope stays 2 (user decision 2026-11-10: 3 would blind the memory
  scan).
* kernel.modules_disabled=1 is applied late, by satsuma-module-lock after its
  preload, never by the boot sysctl file: drivers are still loading then.
* Boot command line: lockdown=integrity (the running kernel cannot be
  modified; reading kernel memory is left to privileged processes, which the
  sysctl table already limits to root), memory wiping and layout options.
  Added to every installed kernel with grubby, so a newly installed kernel
  gets them too. lockdown=integrity refuses unsigned modules; while one is
  loaded it is not added and the reason is reported, so the next boot does not
  lose that driver silently.

En sıkı çekirdek profili, kayıtlı deseni ve değişiklikten sonra geri konması.

Kullanıcının kararı (2026-11-10): çekirdek en sıkı ayarlarla çalışır, bu
ayarların deseni Satsuma'ya kaydedilir ve çekirdek her değiştiğinde (çalışma
anında bir ayar, açılış komut satırı, yeni çekirdek paketi) aynı görüntü geri
konur. Değerler burada, kodun içindedir; kayıtlı desen bir kayıt ve kurcalama
denetimidir, kaynak değildir: bir dosya profili gevşetemez. ptrace_scope 2
kalır (3 bellek taramasını kör ederdi). kernel.modules_disabled=1 açılışta
değil, satsuma-module-lock tarafından sonradan uygulanır. Açılış komut satırı
grubby ile kurulu her çekirdeğe eklenir; lockdown=integrity imzasız modülü
reddettiği için böyle bir modül yüklüyken eklenmez ve nedeni bildirilir.
"""
import hashlib
import json
import os
import re
import subprocess
import sys
from pathlib import Path

PROC_SYS = Path('/proc/sys')
PROFILE_FILE = Path('/var/lib/satsuma-core/kernel-guard/profile.json')
GRUBBY = '/usr/sbin/grubby'

# Run-time settings beyond the network (kernel_net), memory (memory_access) and
# IPv6 tables the guard already keeps.
STRICT = {
    'kernel/kexec_load_disabled': '1',
    'kernel/sysrq': '0',
    'kernel/unprivileged_bpf_disabled': '1',
    # 2.2.56: io_uring bypasses syscall auditing (reads, writes, connects never reach auditd).
    'kernel/io_uring_disabled': '2',
    'net/core/bpf_jit_harden': '2',
    'kernel/perf_event_paranoid': '3',
    'kernel/randomize_va_space': '2',
    'fs/protected_hardlinks': '1',
    'fs/protected_symlinks': '1',
    'fs/protected_fifos': '2',
    'fs/protected_regular': '2',
    'dev/tty/ldisc_autoload': '0',
    'vm/unprivileged_userfaultfd': '0',
    'user/max_user_namespaces': '0',
    'net/ipv4/tcp_rfc1337': '1',
    'net/ipv4/icmp_ignore_bogus_error_responses': '1',
}
# A larger number is stricter for these (unprivileged_bpf_disabled 2 is also off).
AT_LEAST = {'kernel/unprivileged_bpf_disabled': 1, 'kernel/perf_event_paranoid': 3, 'kernel/io_uring_disabled': 2}
# Applied after boot by satsuma-module-lock; one way until reboot.
LATE = {'kernel/modules_disabled': '1'}
MODULE_LOCK_UNIT = 'satsuma-module-lock.service'
MODULE_LOCK_AFTER = 300.0   # seconds of uptime; the timer runs at three minutes

LOCKDOWN = 'lockdown=integrity'
CMDLINE = (LOCKDOWN, 'init_on_alloc=1', 'init_on_free=1', 'slab_nomerge', 'page_alloc.shuffle=1',
           'randomize_kstack_offset=on', 'vsyscall=none', 'debugfs=off')
SYSCTL_FILE = 'usr/lib/sysctl.d/93-satsuma-strict.conf'


def acceptable(key, actual, required):
    if key in AT_LEAST:
        try:
            return int(actual) >= AT_LEAST[key]
        except (TypeError, ValueError):
            return False
    return actual == required


def pattern():
    """The profile as a record: what the kernel must look like."""
    body = {'schema': 1, 'sysctl': dict(sorted(STRICT.items())), 'late': dict(LATE),
            'cmdline': list(CMDLINE), 'ptrace_scope': '2'}
    body['sha256'] = hashlib.sha256(json.dumps(body, sort_keys=True).encode()).hexdigest()
    return body


def save_pattern(path=PROFILE_FILE):
    """Write the pattern; return 'saved', 'unchanged' or 'rewritten' (the file had been changed)."""
    path = Path(path)
    wanted = pattern()
    try:
        current = json.loads(path.read_text())
    except (OSError, ValueError):
        current = None
    if current == wanted:
        return 'unchanged'
    path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    temporary = path.with_suffix('.tmp')
    temporary.write_text(json.dumps(wanted, ensure_ascii=False, sort_keys=True, indent=1) + '\n')
    os.chmod(temporary, 0o600)
    os.replace(temporary, path)
    return 'saved' if current is None else 'rewritten'


def sysctl_text():
    """Contents of 93-satsuma-strict.conf, generated from STRICT."""
    lines = ['# Satsuma strictest kernel profile (satsuma.kernel_profile). Generated; do not edit.',
             '# Satsuma en sıkı çekirdek profili. Üretilmiş dosya; elle değiştirmeyin.',
             '# kernel.modules_disabled is applied after boot by satsuma-module-lock.']
    lines += [key.replace('/', '.') + ' = ' + value for key, value in sorted(STRICT.items())]
    return '\n'.join(lines) + '\n'


# -- boot command line ----------------------------------------------------
def unsigned_modules(path='/proc/modules'):
    """Loaded modules the kernel marks unsigned ("E"); lockdown=integrity would refuse them."""
    found = []
    try:
        text = Path(path).read_text()
    except OSError:
        return None
    for line in text.splitlines():
        match = re.search(r'\(([A-Z+-]+)\)\s*$', line)
        if match and 'E' in match.group(1):
            found.append(line.split()[0])
    return sorted(found)


def wanted_args(unsigned):
    """Command-line words to require; lockdown waits while an unsigned module is loaded."""
    return [arg for arg in CMDLINE if not (arg == LOCKDOWN and unsigned)]


def boot_entries(runner=subprocess.run):
    """kernel path -> set of words on its command line (grubby; rpm-ostree kargs on ostree, 2.2.38)."""
    from . import ostree
    return ostree.boot_entries(runner)


def boot_drift(entries, args):
    """kernel -> missing words."""
    return {kernel: [a for a in args if a not in words] for kernel, words in entries.items()
            if any(a not in words for a in args)}


def running_missing(args, path='/proc/cmdline'):
    try:
        words = set(Path(path).read_text().split())
    except OSError:
        return None
    return [a for a in args if a not in words]


def apply_boot(runner=subprocess.run, modules_path='/proc/modules'):
    """Add the profile's words to every installed kernel; report what still waits for a reboot."""
    unsigned = unsigned_modules(modules_path)
    args = wanted_args(unsigned or [])
    entries = boot_entries(runner)
    # 2.2.37: a sysctl.kernel.yama.ptrace_scope argument other than 2 blinds the
    # RAM scanner from the next boot on; it is removed from every kernel.
    # 2'den farklı ptrace_scope açılış bağımsız değişkeni RAM tarayıcısını kör eder; kaldırılır.
    from .ptrace_guard import sources as ptrace_sources, boot_arguments
    blinding = boot_arguments(ptrace_sources(dirs=(), legacy=(), cmdline='/nonexistent', entries=entries))
    from . import ostree
    if blinding:
        result = ostree.update_args(remove=blinding, runner=runner)
        if result.returncode != 0:
            raise RuntimeError(ostree.tool_name() + ' --remove-args failed: ' + (result.stderr or '')[:200])
        entries = boot_entries(runner)
        left = boot_arguments(ptrace_sources(dirs=(), legacy=(), cmdline='/nonexistent', entries=entries))
        if left:
            raise RuntimeError('Boot entries still set ptrace_scope: ' + ' '.join(left))
    missing = boot_drift(entries, args)
    if missing:
        result = ostree.update_args(add=args, runner=runner)
        if result.returncode != 0:
            raise RuntimeError(ostree.tool_name() + ' --update-kernel=ALL failed: ' + (result.stderr or '')[:200])
        left = boot_drift(boot_entries(runner), args)
        if left:
            raise RuntimeError('Boot entries still miss: ' + json.dumps(left))
    return {'ok': True, 'updated_kernels': sorted(missing), 'args': args, 'removed_ptrace_args': blinding,
            'lockdown_waiting_for': unsigned or [],
            'reboot_needed_for': running_missing(args) or []}


def main(argv=None):
    args = list(sys.argv[1:] if argv is None else argv)
    if '--sysctl-file' in args:
        sys.stdout.write(sysctl_text())
        return 0
    if '--pattern' in args:
        print(json.dumps(pattern(), ensure_ascii=False, indent=1, sort_keys=True))
        return 0
    if '--apply-boot' in args:
        if os.geteuid() != 0:
            print('Root yetkisi gerekli.', file=sys.stderr)
            return 1
        result = apply_boot()
        result['pattern'] = save_pattern()
        print(json.dumps(result, ensure_ascii=False, sort_keys=True))
        if result['lockdown_waiting_for']:
            print('lockdown=integrity eklenmedi: imzasız modül yüklü: ' + ', '.join(result['lockdown_waiting_for']),
                  file=sys.stderr)
        return 0
    print('Kullanım: python3 -m satsuma.kernel_profile --apply-boot | --pattern | --sysctl-file', file=sys.stderr)
    return 2


if __name__ == '__main__':
    raise SystemExit(main())
