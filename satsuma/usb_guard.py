"""USBGuard from the first instant of boot.

USBGuard starts late in boot; until then the kernel authorises every USB
device. The kernel parameter ``usbcore.authorized_default=2`` (documented
in the kernel's admin guide: authorise only devices on internal ports) closes
that window: an external device stays unauthorised until USBGuard applies
its policy. Satsuma sets it with Fedora's grubby, and configures USBGuard
with the documented options ImplicitPolicyTarget=block,
PresentDevicePolicy=apply-policy, InsertedDevicePolicy=apply-policy and
AuthorizedDefault=none. The policy allows only keyboards, mice and other
HID devices and the hubs they sit on (user decision 2026-10-27): USB disks,
modems, network adapters, cameras and phones stay unauthorised, also when
they were plugged in at install time. A device that mixes HID with any
other interface (a "keyboard" that is also a disk or a network card) is
refused. The policy that was there before is kept aside and restored on
removal.

The kernel parameter is not set when it would lock the user out: when a
disk is unlocked at boot (crypttab) and a keyboard sits on an external
port, or when the root filesystem lives on USB. The report says why.

USBGuard, açılışın ilk anından itibaren.

USBGuard açılışta geç başlar; o zamana kadar çekirdek her USB aygıtına
izin verir. ``usbcore.authorized_default=2`` çekirdek parametresi
(çekirdeğin yönetici kılavuzunda: yalnızca dahili portlardaki aygıtlara
izin ver) bu boşluğu kapatır: haricî aygıt USBGuard politikasını uygulayana
kadar yetkisiz kalır. Satsuma bunu Fedora'nın grubby aracıyla ayarlar ve
USBGuard'ı belgelenmiş ImplicitPolicyTarget=block,
PresentDevicePolicy=apply-policy, InsertedDevicePolicy=apply-policy ve
AuthorizedDefault=none seçenekleriyle yapılandırır. Politika yalnızca
klavyelere, farelere, diğer HID aygıtlarına ve bunların bağlı olduğu
hub'lara izin verir (kullanıcı kararı 2026-10-27): USB disk, modem, ağ
kartı, kamera ve telefon, kurulum anında takılı olsalar da yetkisiz kalır.
HID'i başka bir arayüzle birleştiren aygıt (aynı zamanda disk ya da ağ
kartı olan bir "klavye") reddedilir. Önceki politika saklanır ve kaldırmada
geri konur.

Çekirdek parametresi, kullanıcıyı dışarıda bırakacaksa ayarlanmaz: açılışta
bir disk kilidi açılıyorsa (crypttab) ve klavye haricî bir portta ise, ya da
kök dosya sistemi USB üzerindeyse. Rapor nedenini söyler.

Satsuma kaldırılırken ``restore`` USB girişini hemen ve kalıcı olarak geri
verir: çekirdek parametresi silinir, aygıtlar o an yetkilendirilir, USBGuard
ayarları ve servis durumu kurulumdan önceki hâline döner.

On removal ``restore`` gives USB input back at once and for good: the kernel
argument is removed, devices are authorised immediately, and USBGuard's
options and service state return to what they were before installation.
"""
import json
import os
import subprocess
import time
from pathlib import Path

KERNEL_ARG = 'usbcore.authorized_default=2'
DAEMON_CONF = Path('/etc/usbguard/usbguard-daemon.conf')
RULES = Path('/etc/usbguard/rules.conf')
STATUS_FILE = Path('/var/lib/satsuma-core/usbguard.json')
# What the system looked like before Satsuma touched USBGuard; restored on removal.
ORIGINAL_FILE = Path('/var/lib/satsuma-core/usbguard-original.json')
# Only keyboards, mice (HID, class 03) and hubs (class 09). match-all: every
# interface of the device must match, so a HID device that is also storage,
# network or a modem is refused. Checked with usbguard-rule-parser 1.1.2.
POLICY = ('# Satsuma: only keyboards, mice and the hubs they sit on (2026-10-27).\n'
          'allow with-interface match-all { 09:*:* }\n'
          'allow with-interface match-all { 03:*:* }\n')
DAEMON_SETTINGS = {
    'ImplicitPolicyTarget': 'block',
    'PresentDevicePolicy': 'apply-policy',
    'InsertedDevicePolicy': 'apply-policy',
    'AuthorizedDefault': 'none',
}


def run(args, runner=subprocess.run, timeout=60):
    return runner(args, capture_output=True, text=True, timeout=timeout)


def read(path, default=''):
    try:
        return Path(path).read_text()
    except OSError:
        return default


def usb_devices(sysfs=Path('/sys/bus/usb/devices')):
    """Each USB device with whether it is on an external port and is a keyboard."""
    devices = []
    for dev in sorted(sysfs.glob('*')):
        if ':' in dev.name or not (dev / 'idVendor').exists():
            continue
        keyboard = False
        for interface in dev.glob(dev.name + ':*'):
            # HID boot keyboard: class 03, subclass 01, protocol 01.
            if (read(interface / 'bInterfaceClass').strip(), read(interface / 'bInterfaceProtocol').strip()) == ('03', '01'):
                keyboard = True
        # 'unknown' counts as external: that is how the kernel's mode 2 treats it.
        devices.append({'device': dev.name, 'external': read(dev / 'removable').strip() != 'fixed',
                        'keyboard': keyboard})
    return devices


def boot_unlocks_disk(crypttab='/etc/crypttab'):
    for line in read(crypttab).splitlines():
        words = line.split('#', 1)[0].split()
        if len(words) >= 2:
            return True
    return False


def root_on_usb(runner=subprocess.run):
    source = run(['/usr/bin/findmnt', '-n', '-o', 'SOURCE', '/'], runner).stdout.strip()
    if not source:
        return False
    tree = run(['/usr/bin/lsblk', '-s', '-n', '-o', 'TRAN', source], runner).stdout.split()
    return 'usb' in tree


def kernel_arg_blocker(devices, unlocks_disk, usb_root):
    if usb_root:
        return 'root_filesystem_on_usb'
    if unlocks_disk and any(d['keyboard'] and d['external'] for d in devices):
        return 'disk_passphrase_needs_external_usb_keyboard'
    return None


def daemon_conf(text):
    """Set Satsuma's four options, keep every other line."""
    seen, out = set(), []
    for line in text.splitlines():
        key = line.split('=', 1)[0].strip()
        if key in DAEMON_SETTINGS and not line.lstrip().startswith('#'):
            out.append(f'{key}={DAEMON_SETTINGS[key]}')
            seen.add(key)
        else:
            out.append(line)
    out += [f'{key}={value}' for key, value in DAEMON_SETTINGS.items() if key not in seen]
    return '\n'.join(out) + '\n'


def write(path, text, mode=0o600):
    tmp = path.with_name('.' + path.name + '.satsuma-tmp')
    fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC | os.O_NOFOLLOW, mode)
    with os.fdopen(fd, 'w') as fh:
        fh.write(text)
    os.replace(tmp, path)


def daemon_values(text):
    values = {}
    for line in text.splitlines():
        if line.lstrip().startswith('#') or '=' not in line:
            continue
        key, value = line.split('=', 1)
        if key.strip() in DAEMON_SETTINGS:
            values[key.strip()] = value.strip()
    return values


def remember_original(runner, conf, rules, original):
    """Record the pre-Satsuma state once; a later run never overwrites it."""
    if original.exists():
        return json.loads(original.read_text())
    enabled = run(['/usr/bin/systemctl', 'is-enabled', 'usbguard.service'], runner).stdout.strip()
    state = {'daemon_settings': {key: daemon_values(read(conf)).get(key) for key in DAEMON_SETTINGS},
             'service_was_enabled': enabled == 'enabled', 'rules_existed': bool(read(rules).strip()),
             'rules': read(rules)}
    original.parent.mkdir(parents=True, exist_ok=True)
    write(original, json.dumps(state, sort_keys=True))
    return state


def setup(runner=subprocess.run, sysfs=Path('/sys/bus/usb/devices'), crypttab='/etc/crypttab',
          conf=DAEMON_CONF, rules=RULES, cmdline=None, original=ORIGINAL_FILE):
    report = {'updated_at': time.time(), 'actions': []}
    remember_original(runner, conf, rules, original)
    policy_changed = read(rules) != POLICY
    if policy_changed:
        write(rules, POLICY)
        report['actions'].append('policy_keyboard_mouse_only')
    wanted = daemon_conf(read(conf))
    if read(conf) != wanted:
        write(conf, wanted)
        report['actions'].append('daemon_configured')
    enabled = run(['/usr/bin/systemctl', 'enable', '--now', 'usbguard.service'], runner)
    if enabled.returncode == 0 and policy_changed:
        # A running daemon reads its rule file only when it starts.
        enabled = run(['/usr/bin/systemctl', 'restart', 'usbguard.service'], runner)
    if enabled.returncode:
        report.update(status='SERVICE_FAILED', error=enabled.stderr[:300])
        return report

    devices = usb_devices(sysfs)
    blocker = kernel_arg_blocker(devices, boot_unlocks_disk(crypttab), root_on_usb(runner))
    cmdline = read('/proc/cmdline') if cmdline is None else cmdline
    from . import ostree
    if not blocker and ostree.booted() and KERNEL_ARG not in cmdline.split():
        # 2.2.38: on ostree the package's removal scripts run in rpm-ostree's
        # sandbox and cannot take the argument back, so after
        # "rpm-ostree uninstall" every USB keyboard and mouse would stay dead
        # (field report 2026-10-25 on normal Fedora). USBGuard still enforces
        # from the moment its service starts; only the early-boot window is open.
        # ostree'de kaldırma betiği parametreyi geri alamaz; kaldırmadan sonra
        # USB klavye/fare ölü kalırdı. USBGuard servis başlayınca yine korur.
        blocker = 'ostree_removal_cannot_undo_kernel_argument'
    if blocker:
        report.update(status='ACTIVE_WITHOUT_EARLY_BOOT', kernel_arg='not_set', reason=blocker)
    elif KERNEL_ARG in cmdline.split():
        report.update(status='ACTIVE_FROM_EARLY_BOOT', kernel_arg='active')
    else:
        grubby = ostree.update_args(add=[KERNEL_ARG], runner=runner)
        if grubby.returncode:
            report.update(status='ACTIVE_WITHOUT_EARLY_BOOT', kernel_arg='failed', reason=grubby.stderr[:300])
        else:
            report.update(status='REBOOT_REQUIRED', kernel_arg='set_for_next_boot')
            report['actions'].append('kernel_arg_set')
    report['devices'] = devices
    return report


def restore(runner=subprocess.run, sysfs=Path('/sys/bus/usb/devices'), conf=DAEMON_CONF,
            original=ORIGINAL_FILE, rules=RULES):
    """Give USB input back on package removal, at once and for the next boot.

    The kernel argument is removed with grubby; because it only goes away at
    the next boot, every controller's authorized_default is set back to 1
    and every deauthorised device is authorised now (the kernel's documented
    sysfs interface). The four daemon options get their original values back
    and USBGuard is disabled again if Satsuma enabled it. The rule file
    gets back what it held before Satsuma.

    Paket kaldırılırken USB girişini hem hemen hem bir sonraki açılış için
    geri verir: çekirdek parametresi kaldırılır, parametre ancak açılışta
    kalktığı için her denetleyicinin authorized_default'u 1 yapılır ve
    yetkisiz her aygıt hemen yetkilendirilir; dört ayar eski değerine döner,
    USBGuard'ı Satsuma açtıysa yeniden kapatılır. Kural dosyası Satsuma'dan
    önceki içeriğine döner.
    """
    report = {'updated_at': time.time(), 'actions': [], 'errors': []}
    from . import ostree
    grubby = ostree.update_args(remove=[KERNEL_ARG], runner=runner)
    (report['actions'] if grubby.returncode == 0 else report['errors']).append('kernel_arg_removed')
    for path in sorted(sysfs.glob('usb*/authorized_default')) + [
            d / 'authorized' for d in sorted(sysfs.glob('*')) if ':' not in d.name and read(d / 'authorized').strip() == '0']:
        try:
            path.write_text('1')
            report['actions'].append('authorized:' + path.parent.name + '/' + path.name)
        except OSError as exc:
            report['errors'].append(f'{path}: {exc.strerror}')
    try:
        state = json.loads(original.read_text())
    except (OSError, ValueError):
        state = None
    if state:
        lines, seen = [], set()
        for line in read(conf).splitlines():
            key = line.split('=', 1)[0].strip()
            if key in DAEMON_SETTINGS and not line.lstrip().startswith('#'):
                seen.add(key)
                if state['daemon_settings'].get(key) is None:
                    continue
                line = f"{key}={state['daemon_settings'][key]}"
            lines.append(line)
        if read(conf):
            write(conf, '\n'.join(lines) + '\n')
            report['actions'].append('daemon_settings_restored')
        if 'rules' in state and read(rules) == POLICY:
            write(rules, state['rules'])
            report['actions'].append('rules_restored')
        if not state.get('service_was_enabled'):
            run(['/usr/bin/systemctl', 'disable', '--now', 'usbguard.service'], runner)
            report['actions'].append('usbguard_disabled_again')
    report['status'] = 'RESTORED' if not report['errors'] else 'PARTIAL'
    return report


def restore_main():
    report = restore()
    print(json.dumps(report))
    return 0 if report['status'] == 'RESTORED' else 1


def main():
    report = setup()
    STATUS_FILE.parent.mkdir(parents=True, exist_ok=True)
    write(STATUS_FILE, json.dumps(report, sort_keys=True))
    print(json.dumps({'status': report['status']}))
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
