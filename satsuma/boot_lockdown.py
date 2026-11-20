"""Closed at boot: radios off, USB modem, PPP and tuned masked.

User decision 2026-10-27. Runs early in every boot, before the network:

- Wi-Fi, Bluetooth and every other radio are soft-blocked through the
  kernel's /dev/rfkill (one RFKILL_OP_CHANGE_ALL event), not through the
  ``rfkill`` program. The kernel applies the same state to radios whose
  driver loads later. systemd-rfkill would restore the last saved state, so
  its saved files are set to "blocked" too. The user can turn a radio on
  afterwards.
- ModemManager (USB modems), tuned and tuned-ppd are masked and stopped.
  PPP's kernel modules cannot be loaded (modprobe ``install ... /bin/false``)
  and are unloaded if present. tuned is a power and performance tuning
  service, not a network; masking it only removes GNOME's power mode choice.
- The system is not trusted: every boot checks again and repairs what was
  undone. The report says what was found changed.

Açılışta kapalı: radyolar kapalı; USB modem, PPP ve tuned maskeli.

Kullanıcı kararı 2026-10-27. Her açılışta, ağdan önce çalışır:

- Wi-Fi, Bluetooth ve diğer bütün radyolar ``rfkill`` programıyla değil,
  çekirdeğin /dev/rfkill aygıtıyla (tek bir RFKILL_OP_CHANGE_ALL olayı)
  yazılımsal olarak kapatılır. Çekirdek aynı durumu sürücüsü sonradan
  yüklenen radyolara da uygular. systemd-rfkill son kaydedilen durumu geri
  yükleyeceği için onun kayıt dosyaları da "kapalı" yapılır. Kullanıcı bir
  radyoyu sonradan açabilir.
- ModemManager (USB modemler), tuned ve tuned-ppd maskelenir ve durdurulur.
  PPP'nin çekirdek modülleri yüklenemez (modprobe ``install ... /bin/false``)
  ve yüklüyse kaldırılır. tuned bir ağ değil, güç ve performans ayar
  servisidir; maskelenmesi yalnızca GNOME'daki güç modu seçimini kaldırır.
- Sisteme güvenilmez: her açılışta yeniden denetlenir ve geri alınan
  onarılır. Rapor neyin değiştirilmiş bulunduğunu söyler.
"""
import json
import os
import struct
import subprocess
import sys
import time
from pathlib import Path

RFKILL_DEV = Path('/dev/rfkill')
RFKILL_SAVED = Path('/var/lib/systemd/rfkill')
RFKILL_TYPE_ALL = 0
RFKILL_OP_CHANGE_ALL = 3
# struct rfkill_event { __u32 idx; __u8 type; __u8 op; __u8 soft; __u8 hard; }
RFKILL_EVENT = struct.Struct('=IBBBB')

MASKED_UNITS = ('ModemManager.service', 'tuned.service', 'tuned-ppd.service')
# Owner 2026-11-20 ("kalıcı yasak"): packages removed from the image stay banned; if an update brings
# one back its service never starts (teams also raises SATSUMA-BANNED-PKG-001, GAP-077 stops it).
BANNED_UNITS = ('avahi-daemon.service', 'avahi-daemon.socket', 'brltty.service', 'ipp-usb.service',
                'gssproxy.service', 'systemd-resolved.service')
# rkhunter's own daily cron mailed its report through s-nail (owner: "s-nail mail atmış"). Satsuma runs
# rkhunter itself; the package's cron job is switched off (not executable, run-parts skips it).
CRON_OFF = (Path('/etc/cron.daily/rkhunter'),)


def cron_off(paths=CRON_OFF):
    changed = []
    for path in paths:
        try:
            mode = path.stat().st_mode
        except FileNotFoundError:
            continue
        if mode & 0o111:
            try:
                os.chmod(path, mode & ~0o111)
            except OSError as exc:
                # 2.2.66 (field 2026-11-20): this step failed and took the whole unit down with it.
                return {'cron_jobs_switched_off': changed, 'cron_error': f'{path}: {exc}'[:300]}
            changed.append(str(path))
    return {'cron_jobs_switched_off': changed}
PPP_MODULES = ('ppp_generic', 'ppp_async', 'ppp_synctty', 'ppp_deflate', 'ppp_mppe', 'bsd_comp',
               'pppoe', 'pppox', 'pptp', 'l2tp_ppp')
MODPROBE_FILE = Path('/etc/modprobe.d/satsuma-no-ppp.conf')
# 2.2.54 (field 2026-11-19): with /bin/false a module listed in modules-load.d made
# systemd-modules-load.service fail at every boot. /bin/true keeps the module out just
# the same (modprobe runs the command instead of loading it) without the boot failure.
# 2.2.54: /bin/false her açılışta systemd-modules-load'u düşürüyordu; /bin/true modülü
# yine yüklemez, yalnızca hata vermez.
MODPROBE_TEXT = ('# Satsuma: PPP is not allowed on this computer (user decision 2026-10-27).\n'
                 + ''.join(f'install {m} /bin/true\n' for m in PPP_MODULES))

# Owner decision 2026-11-20 from the machine's inventory: loaded, used by nothing, no device
# for them (lsmod "used by" 0). Order: users before what they use, for unloading.
# Envanterden sahip kararı: yüklü ama hiçbir şeyin kullanmadığı modüller yüklenemez.
UNUSED_MODULES = ('amdgpu', 'amdxcp', 'drm_buddy', 'gpu_sched', 'drm_panel_backlight_quirks',
                  'uinput', 'slhc', 'nf_conntrack_netlink',
                  'iptable_filter', 'ip_tables', 'ip6table_filter', 'ip6_tables', 'arp_tables',
                  # bridge/stp/llc are not here: the owner's virtual machines use a bridged network
                  # (2026-11-20, "bridge bağlantı aktif kalacak"). br_netfilter is not needed for it.
                  'br_netfilter', 'joydev', 'pcspkr',
                  # Owner 2026-11-20: boot-time loads made void; fwupd asked for these two.
                  'msr', 'i2c_dev')
# fwupd's /usr/lib/modules-load.d entries, overridden by empty files of the same name in /etc
# (systemd reads the /etc copy instead). Açılışta fwupd'nin yüklettiği modüller geçersiz.
MODULES_LOAD_OVERRIDES = ('fwupd-msr.conf', 'fwupd-i2c.conf')
# open-vm-tools (owner 2026-11-20, "open-vm-tools'u engelle"): its modules-load file only loads
# fuse (already loaded by fuse-overlayfs), so it is not voided. The guest packages are removed from
# the image by the owner (rpm-ostree override remove); should they come back, their services stay
# masked. KVM / GNOME Boxes are untouched ("sanal makineyi maskeleme").
# open-vm-tools servisleri maskeli kalır; KVM/Boxes'a dokunulmaz.
OPEN_VM_TOOLS_UNITS = ('vmtoolsd.service', 'vgauthd.service')
MODULES_LOAD_ETC = Path('/etc/modules-load.d')
OVERRIDE_TEXT = '# Satsuma: boot-time module load voided (owner decision 2026-11-20).\n'
UNUSED_FILE = Path('/etc/modprobe.d/satsuma-unused-modules.conf')
UNUSED_TEXT = ('# Satsuma: modules this computer does not use (owner decision 2026-11-20, inventory).\n'
               + ''.join(f'install {m} /bin/true\n' for m in UNUSED_MODULES))
SYSTEMD_ETC = Path('/etc/systemd/system')
REPORT_FILE = Path('/var/lib/satsuma-core/boot-lockdown.json')


def run(args, runner=subprocess.run):
    return runner(args, capture_output=True, text=True, timeout=60)


def block_radios(device=RFKILL_DEV, saved=RFKILL_SAVED):
    report = {}
    try:
        fd = os.open(device, os.O_WRONLY | os.O_CLOEXEC)
        try:
            os.write(fd, RFKILL_EVENT.pack(0, RFKILL_TYPE_ALL, RFKILL_OP_CHANGE_ALL, 1, 0))
        finally:
            os.close(fd)
        report['radios'] = 'blocked'
    except OSError as exc:
        report['radios'] = 'failed'
        report['radios_error'] = f'{device}: {exc.strerror}'
    restored = []
    try:
        for path in sorted(Path(saved).iterdir()):
            if path.is_file() and not path.is_symlink() and path.read_text().strip() != '1':
                path.write_text('1\n')
                restored.append(path.name)
    except OSError:
        pass
    report['saved_states_set_blocked'] = restored
    return report


def mask_units(units=MASKED_UNITS, etc=SYSTEMD_ETC, runner=subprocess.run):
    """Units that were not masked when checked; each is masked and stopped now."""
    found = []
    for unit in units:
        link = Path(etc) / unit
        if link.is_symlink() and os.readlink(link) == '/dev/null':
            continue
        found.append(unit)
        run(['/usr/bin/systemctl', 'mask', '--now', '--no-block', unit], runner)
    return found


def _block(path, text, modules, modules_file, runner, order):
    report = {'modprobe_file_repaired': False, 'modules_unloaded': []}
    try:
        current = Path(path).read_text()
    except OSError:
        current = None
    if current != text:
        Path(path).parent.mkdir(parents=True, exist_ok=True)
        Path(path).write_text(text)
        os.chmod(path, 0o644)
        report['modprobe_file_repaired'] = True
    try:
        loaded = {line.split()[0] for line in Path(modules_file).read_text().splitlines() if line.strip()}
    except OSError:
        loaded = set()
    for module in order(modules):
        if module in loaded:
            run(['/usr/sbin/modprobe', '-r', module], runner)
            report['modules_unloaded'].append(module)
    return report


def block_ppp(path=MODPROBE_FILE, modules_file=Path('/proc/modules'), runner=subprocess.run):
    # Users of a module first (pppoe uses pppox uses ppp_generic).
    return _block(path, MODPROBE_TEXT, PPP_MODULES, modules_file, runner, lambda m: reversed(m))


def void_boot_loads(etc=MODULES_LOAD_ETC, names=MODULES_LOAD_OVERRIDES):
    written = []
    for name in names:
        target = Path(etc) / name
        try:
            if target.read_text() == OVERRIDE_TEXT:
                continue
        except OSError:
            pass
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(OVERRIDE_TEXT)
        os.chmod(target, 0o644)
        written.append(name)
    return {'boot_loads_voided': written}


# Module allowlist (owner 2026-11-20, "saldırı yüzeyim çok geniş": 4850 modules installed, ~100
# used). Only modules this computer itself loaded may load; every other module of the running
# kernel gets "install X /bin/true". The list is learned when the module lock closes (two minutes
# after boot, from /proc/modules) and enforced from the next boot. Under enforcement nothing outside
# the list can load, so the list never grows by itself. On a new kernel, modules whose names did
# not exist in the recorded kernel (renamed drivers) are allowed for that one boot so the screen,
# sound and network still come up; then the list is recorded for the new kernel.
# Yalnız bu bilgisayarın yüklediği modüller yüklenebilir; geri kalan her modül engellenir.
ALLOWLIST_RECORD = Path('/var/lib/satsuma-core/module-allowlist.json')
ALLOWLIST_FILE = Path('/etc/modprobe.d/satsuma-module-allowlist.conf')
MODULES_ROOT = Path('/lib/modules')


def _norm(name):
    name = Path(str(name)).name
    for suffix in ('.xz', '.zst', '.gz'):
        name = name.removesuffix(suffix)
    return name.removesuffix('.ko').replace('-', '_')


# Kept loadable even when not loaded (owner 2026-11-20: "bluetooth maskeleme, sadece kapalı kalsın"):
# Bluetooth stays off through rfkill at every boot (block_radios), but is not taken away.
# Bluetooth kapalı kalır (rfkill) ama modülleri engellenmez.
ALWAYS_LOADABLE_DIRS = ('kernel/net/bluetooth/', 'kernel/drivers/bluetooth/')
# Bridged virtual machine network (owner 2026-11-20); also loaded before the module lock.
ALWAYS_LOADABLE_NAMES = frozenset({'bridge', 'stp', 'llc', 'tun'})


def _module_paths(kernel=None, root=MODULES_ROOT):
    kernel = kernel or os.uname().release
    paths = {}
    try:
        for line in (Path(root) / kernel / 'modules.dep').read_text().splitlines():
            if ':' in line:
                path = line.split(':', 1)[0]
                paths[_norm(path)] = path
    except OSError:
        return {}
    return paths


def available_modules(kernel=None, root=MODULES_ROOT):
    return set(_module_paths(kernel, root))


def always_loadable(kernel=None, root=MODULES_ROOT):
    return {name for name, path in _module_paths(kernel, root).items()
            if path.startswith(ALWAYS_LOADABLE_DIRS) or name in ALWAYS_LOADABLE_NAMES}


def loaded_modules(modules_file=Path('/proc/modules')):
    try:
        return {line.split()[0] for line in Path(modules_file).read_text().splitlines() if line.strip()}
    except OSError:
        return set()


def _read_record(record):
    try:
        data = json.loads(Path(record).read_text())
    except (OSError, ValueError):
        return None
    if not isinstance(data, dict) or not isinstance(data.get('allowed'), list):
        return None
    return data


def record_allowlist(record=ALLOWLIST_RECORD, modules_file=Path('/proc/modules'), kernel=None, root=MODULES_ROOT):
    """Called after the module lock: what this boot loaded becomes (part of) the allowlist."""
    from .module_lock import PRELOAD
    kernel = kernel or os.uname().release
    old = _read_record(record) or {}
    loaded = loaded_modules(modules_file)
    allowed = (set(old.get('allowed') or ()) if old.get('kernel') == kernel else set()) | loaded | set(PRELOAD)
    allowed -= set(UNUSED_MODULES)
    data = {'kernel': kernel, 'recorded_at': time.time(), 'allowed': sorted(allowed),
            'available': sorted(available_modules(kernel, root))}
    record = Path(record)
    record.parent.mkdir(parents=True, exist_ok=True)
    tmp = record.with_suffix('.tmp')
    fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC | os.O_CLOEXEC, 0o600)
    with os.fdopen(fd, 'w') as fh:
        json.dump(data, fh, sort_keys=True)
    os.replace(tmp, record)
    return {'status': 'RECORDED', 'kernel': kernel, 'allowed': len(data['allowed']), 'available': len(data['available'])}


def allow_only(path=ALLOWLIST_FILE, record=ALLOWLIST_RECORD, kernel=None, root=MODULES_ROOT):
    from .module_lock import PRELOAD
    kernel = kernel or os.uname().release
    data = _read_record(record)
    available = available_modules(kernel, root)
    if not data or not available:
        # Nothing learned yet (first boot with 2.2.62): the module lock and the unused list apply.
        return {'module_allowlist': 'learning', 'modules_blocked': 0}
    allowed = set(data['allowed']) | set(PRELOAD) | always_loadable(kernel, root)
    state = 'enforced'
    if data.get('kernel') != kernel:
        allowed |= available - set(data.get('available') or ())
        state = 'enforced_new_kernel'
    allowed -= set(UNUSED_MODULES)
    blocked = sorted(available - allowed)
    text = ('# Satsuma: only modules this computer loads may load (owner decision 2026-11-20).\n'
            f'# kernel {kernel}: {len(allowed & available)} allowed, {len(blocked)} blocked.\n'
            + ''.join(f'install {m} /bin/true\n' for m in blocked))
    path = Path(path)
    try:
        current = path.read_text()
    except OSError:
        current = None
    if current != text:
        path.parent.mkdir(parents=True, exist_ok=True)
        tmp = path.with_suffix('.tmp')
        tmp.write_text(text)
        os.chmod(tmp, 0o644)
        os.replace(tmp, path)
    return {'module_allowlist': state, 'modules_blocked': len(blocked)}


# The initramfs is a system of its own (owner 2026-11-20): Fedora's generic image carries 835
# modules and its own modules-load.d (fwupd msr/i2c, open-vm-tools), read before /etc exists.
# rpm-ostree initramfs-etc adds these /etc files to it, so the allowlist and the voided loads
# hold from the first moment. Fedora's signed image is kept (no local rebuild); the change takes
# effect at the next boot as a new deployment, and the previous one stays in the boot menu.
# İlk açılış görüntüsü (initramfs) de aynı kurallarla açılır.
INITRAMFS_STATE = Path('/var/lib/satsuma-core/initramfs-etc.json')


def initramfs_files(etc_modprobe=Path('/etc/modprobe.d'), etc_load=MODULES_LOAD_ETC):
    names = [ALLOWLIST_FILE.name, UNUSED_FILE.name, MODPROBE_FILE.name]
    files = [Path(etc_modprobe) / n for n in names]
    files += [Path(etc_load) / n for n in MODULES_LOAD_OVERRIDES]
    return [f for f in files if f.is_file()]


def sync_initramfs(runner=subprocess.run, state=INITRAMFS_STATE, files=None):
    import hashlib
    files = initramfs_files() if files is None else files
    digest = {str(f): hashlib.sha256(Path(f).read_bytes()).hexdigest() for f in files}
    try:
        recorded = json.loads(Path(state).read_text())
    except (OSError, ValueError):
        recorded = None
    if recorded == digest:
        return {'initramfs': 'in_sync', 'tracked': len(digest)}
    cmd = ['/usr/bin/rpm-ostree', 'initramfs-etc', '--force-sync'] + [f'--track={f}' for f in digest]
    try:
        done = runner(cmd, capture_output=True, text=True, timeout=900)
    except (OSError, subprocess.SubprocessError) as exc:
        return {'initramfs': 'error', 'error': str(exc)[:300]}
    if done.returncode != 0:
        # rpm-ostree busy (an update in progress) or refused: tried again at the next boot.
        return {'initramfs': 'error', 'error': (done.stderr or done.stdout or '')[-300:]}
    Path(state).parent.mkdir(parents=True, exist_ok=True)
    Path(state).write_text(json.dumps(digest, sort_keys=True))
    return {'initramfs': 'synced_takes_effect_next_boot', 'tracked': len(digest)}


def block_unused(path=UNUSED_FILE, modules_file=Path('/proc/modules'), runner=subprocess.run):
    report = _block(path, UNUSED_TEXT, UNUSED_MODULES, modules_file, runner, lambda m: m)
    return {'unused_file_repaired': report['modprobe_file_repaired'], 'unused_unloaded': report['modules_unloaded']}


def apply(runner=subprocess.run, device=RFKILL_DEV, saved=RFKILL_SAVED, etc=SYSTEMD_ETC,
          modprobe=MODPROBE_FILE, modules_file=Path('/proc/modules'), unused=UNUSED_FILE,
          modules_load_etc=MODULES_LOAD_ETC, allowlist=ALLOWLIST_FILE, allowlist_record=ALLOWLIST_RECORD,
          cron_paths=CRON_OFF):
    report = {'updated_at': time.time()}
    report.update(block_radios(device, saved))
    report['units_found_unmasked'] = mask_units(MASKED_UNITS, etc, runner)
    report.update(block_ppp(modprobe, modules_file, runner))
    report.update(block_unused(unused, modules_file, runner))
    report.update(void_boot_loads(modules_load_etc))
    report['open_vm_tools_found_unmasked'] = mask_units(OPEN_VM_TOOLS_UNITS, etc, runner)
    report['banned_found_unmasked'] = mask_units(BANNED_UNITS, etc, runner)
    report.update(cron_off(cron_paths))
    report.update(allow_only(allowlist, allowlist_record))
    report['status'] = 'APPLIED' if report['radios'] == 'blocked' else 'RADIOS_NOT_BLOCKED'
    return report


def main():
    report = apply()
    try:
        REPORT_FILE.parent.mkdir(parents=True, exist_ok=True)
        REPORT_FILE.write_text(json.dumps(report, sort_keys=True))
    except OSError as exc:
        print(f'boot-lockdown report not written: {exc}', file=sys.stderr)
    print(json.dumps(report, sort_keys=True))
    return 0 if report['status'] == 'APPLIED' else 1


if __name__ == '__main__':
    raise SystemExit(main())
