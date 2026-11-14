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
PPP_MODULES = ('ppp_generic', 'ppp_async', 'ppp_synctty', 'ppp_deflate', 'ppp_mppe', 'bsd_comp',
               'pppoe', 'pppox', 'pptp', 'l2tp_ppp')
MODPROBE_FILE = Path('/etc/modprobe.d/satsuma-no-ppp.conf')
MODPROBE_TEXT = ('# Satsuma: PPP is not allowed on this computer (user decision 2026-10-27).\n'
                 + ''.join(f'install {m} /bin/false\n' for m in PPP_MODULES))
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


def block_ppp(path=MODPROBE_FILE, modules_file=Path('/proc/modules'), runner=subprocess.run):
    report = {'modprobe_file_repaired': False, 'modules_unloaded': []}
    try:
        current = Path(path).read_text()
    except OSError:
        current = None
    if current != MODPROBE_TEXT:
        Path(path).parent.mkdir(parents=True, exist_ok=True)
        Path(path).write_text(MODPROBE_TEXT)
        os.chmod(path, 0o644)
        report['modprobe_file_repaired'] = True
    try:
        loaded = {line.split()[0] for line in Path(modules_file).read_text().splitlines() if line.strip()}
    except OSError:
        loaded = set()
    # Users of a module first (pppoe uses pppox uses ppp_generic).
    for module in reversed(PPP_MODULES):
        if module in loaded:
            run(['/usr/sbin/modprobe', '-r', module], runner)
            report['modules_unloaded'].append(module)
    return report


def apply(runner=subprocess.run, device=RFKILL_DEV, saved=RFKILL_SAVED, etc=SYSTEMD_ETC,
          modprobe=MODPROBE_FILE, modules_file=Path('/proc/modules')):
    report = {'updated_at': time.time()}
    report.update(block_radios(device, saved))
    report['units_found_unmasked'] = mask_units(MASKED_UNITS, etc, runner)
    report.update(block_ppp(modprobe, modules_file, runner))
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
