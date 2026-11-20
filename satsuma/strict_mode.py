"""Strictest mode: report-only rules that may stop (owner decision 2026-11-20).

Owner: "bu kuralların kayıt alanlarını ve durdurmayanları durdurana çevir". 110 of 306 rules
only reported. These rules now stop the process they match (classification raised to
suspicious, severity to at least high, log-only dropped); the original rule files stay
byte for byte. The rest stay reports, because each matches what the operating system or
the owner does every second: stopping it would stop the desktop, sudo, login or the
network, not an attacker (EXCLUDED says which and why). On by default; the owner can
switch it off with the admin password (satsuma-admin en-siki-mod).

En sıkı mod: yalnız bildiren kurallardan sistemi bozmayacak olanlar artık durdurur.
"""

import re

STORE_KEY = 'strict_mode'

STRICT_STOP = frozenset({
    'SATSUMA-BPF-CLI-001', 'SATSUMA-LINUX-CLI-001', 'SATSUMA-LINUX-CLI-002',
    'SATSUMA-COLL-001', 'SATSUMA-COLL-002', 'SATSUMA-COLL-003', 'SATSUMA-COLL-004', 'SATSUMA-COLL-009',
    'SATSUMA-COLL-010', 'SATSUMA-COLL-011', 'SATSUMA-COLL-012', 'SATSUMA-COLL-013', 'SATSUMA-COLL-014',
    'SATSUMA-C2-004',
    'SATSUMA-GAP-037', 'SATSUMA-GAP-052',
    'SATSUMA-SUDO-004', 'SATSUMA-PRIV-024', 'SATSUMA-PRIV-003',
    'SATSUMA-SUID-001', 'SATSUMA-SUID-002', 'SATSUMA-SUID-004', 'SATSUMA-PRIV-004', 'SATSUMA-PRIV-008',
    'SATSUMA-PRIV-009', 'SATSUMA-PRIV-010', 'SATSUMA-PRIV-015',
    'SATSUMA-EVAS-006', 'SATSUMA-EVAS-007', 'SATSUMA-EVAS-008', 'SATSUMA-EVAS-016', 'SATSUMA-EVAS-017',
    'SATSUMA-EVAS-019', 'SATSUMA-EVAS-020',
    'SATSUMA-DEV-001',
    'SATSUMA-EXEC-014',
    'SATSUMA-EXFIL-002', 'SATSUMA-EXFIL-003', 'SATSUMA-EXFIL-004', 'SATSUMA-EXFIL-007', 'SATSUMA-EXFIL-008',
    'SATSUMA-EXFIL-009', 'SATSUMA-EXFIL-012', 'SATSUMA-EXFIL-013', 'SATSUMA-EXFIL-014',
    'SATSUMA-EXFIL-015', 'SATSUMA-EXFIL-017', 'SATSUMA-EXFIL-018', 'SATSUMA-EXFIL-019', 'SATSUMA-EXFIL-020',
    'SATSUMA-IMP-001', 'SATSUMA-IMP-003', 'SATSUMA-IMP-005', 'SATSUMA-IMP-006',
    'SATSUMA-LAT-001', 'SATSUMA-LAT-002', 'SATSUMA-LAT-003', 'SATSUMA-LAT-004', 'SATSUMA-LAT-005',
    'SATSUMA-LAT-006',
    # 2.2.62, owner's inventory 2026-11-20: tools this computer does not use (ssh 1 hit, rsync,
    # mail client, kubectl/aws/docker, sudoedit, Steam/gamemode 0). Bu bilgisayarda kullanılmıyor.
    'SATSUMA-COLL-005', 'SATSUMA-COLL-008', 'SATSUMA-COLL-016', 'SATSUMA-COLL-018', 'SATSUMA-COLL-019',
    'SATSUMA-COLL-020', 'SATSUMA-EXFIL-005', 'SATSUMA-EXFIL-010', 'SATSUMA-SUDO-003', 'SATSUMA-EVAS-010',
    'SATSUMA-ROOT-002',
})

# Module loading (owner 2026-11-20): from user space, loading a module that is not loaded yet and
# every removal stop; the kernel's own request (parent kthreadd, PID 2) and a module already
# loaded (modprobe does nothing) do not. File and forced loads are SATSUMA-GAP-073.
# Kullanıcı alanından yüklü olmayan modülü yükleme ve her kaldırma durdurur; çekirdeğin isteği değil.
MODULE_RULES = frozenset({'SATSUMA-PRIV-017', 'SATSUMA-ROOT-001', 'SATSUMA-LNX-EVAS-005', 'SATSUMA-EVAS-014'})


def module_change_stops(event, sys_module='/sys/module'):
    import shlex
    from pathlib import Path
    if str(event.get('ppid') or '') == '2':
        return False
    try:
        tokens = shlex.split(str(event.get('cmd') or ''))
    except ValueError:
        tokens = str(event.get('cmd') or '').split()
    if not tokens:
        return False
    program = Path(tokens[0]).name
    args = tokens[1:]
    if program == 'kmod' and args:
        program, args = args[0], args[1:]
    if program == 'rmmod' or (program == 'modprobe' and any(a in ('-r', '--remove') for a in args)):
        return True
    names = [a for a in args if not a.startswith('-')]
    if program not in ('modprobe', 'insmod') or not names:
        return False
    # Satsuma's own preload before the module lock (satsuma.module_lock.PRELOAD), exact form only:
    # these modules are on the allowlist anyway, so the exception gives nothing new to anyone.
    from .module_lock import PRELOAD
    if tokens[0] == '/usr/sbin/modprobe' and args[:1] == ['-q'] and len(args) == 2 and args[1] in PRELOAD:
        return False
    name = Path(names[0]).name.split('.ko')[0].replace('-', '_')
    return not Path(sys_module, name).exists()

# Kept as reports: what each would stop is the machine or the owner, not an attacker.
EXCLUDED = {
    # 2.2.64 (field 2026-11-20): stopping these locked the owner out of his own computer: removing
    # or updating Satsuma, "rpm-ostree rollback", "override reset" and "reset" were all stopped,
    # and the panel was down too. The owner's way out never closes; the gate is the polkit password
    # rpm-ostree asks for (2.2.58), and Satsuma raises a critical alarm.
    # Sahibin kaldırma/güncelleme/geri dönüş yolu asla kapanmaz; kapı polkit parolasıdır, alarm verilir.
    'SATSUMA-GAP-036': 'Satsuma\'yı kaldırma ya da güncelleme: sahibin çıkış yolu kapanmaz (polkit parolası sorar)',
    'SATSUMA-GAP-075': 'rpm-ostree kaldırma, rollback, reset: sahibin geri dönüş yolu kapanmaz (polkit parolası sorar)',
    'SATSUMA-ROOT-003': 'Her program /dev/null ve terminaline yazar; her şey durdurulurdu.',
    'SATSUMA-COLL-015': 'Her oturum açma, ls ve sudo /etc/passwd okur.',
    'SATSUMA-SUDO-HARD-003': 'sudo her çalışmada /etc/sudoers okur; sudo durdurulurdu.',
    'SATSUMA-DEV-002': 'Masaüstü (cosmic-comp) klavye ve fareyi /dev/input üzerinden okur.',
    'SATSUMA-NET-203': 'NetworkManager resolv.conf yazar; internet giderdi.',
    'SATSUMA-NET-202': 'firewalld kendi yapılandırmasını yazar.',
    'SATSUMA-NET-201': 'Her yeni dinleyen uygulama (Steam, KDE Connect...) durdurulurdu.',
    'SATSUMA-COLL-006': 'Firefox kendi geçmişini okur.',
    'SATSUMA-COLL-007': 'Firefox kendi çerezlerini okur.',
    'SATSUMA-COLL-017': 'gpg-agent kendi anahtarlarını okur.',
    'SATSUMA-EVAS-015': 'systemd ve Satsuma açılışta sysctl yazar; çekirdek bekçisi her saniye geri yazar.',
    'SATSUMA-EVAS-013': 'Paket betikleri SELinux modülü kurar.',
    'SATSUMA-EVAS-011': 'Firefox (snap), Steam ve birçok uygulama LD_LIBRARY_PATH ayarlar.',
    'SATSUMA-EVAS-012': 'rkhunter, chkrootkit, unhide: güvenlik taramaları (Satsuma da unhide çalıştırır).',
    'SATSUMA-ROOT-004': 'rkhunter, chkrootkit, unhide: güvenlik taramaları.',
    'SATSUMA-GAP-025': 'Sahibin kararı (2026-11-19): chattr +i sıkılaştırma için elle yapılıyor.',
    'SATSUMA-LNX-EVAS-001': 'Sahip kilitli dosyayı düzenlemek için chattr -i kullanır.',
    'SATSUMA-EVAS-009': 'Sahip kilitli dosyayı düzenlemek için chattr -i kullanır.',
    'SATSUMA-PRIV-001': 'sudo -i / sudo su: sahibin root kabuğu.',
    'SATSUMA-PRIV-028': 'sudo -i / sudo bash: sahibin root kabuğu.',
    'SATSUMA-DISC-001': 'uname, whoami, id: gündelik komutlar.',
    'SATSUMA-DISC-002': 'ip addr, ifconfig: gündelik komutlar.',
    'SATSUMA-DISC-003': 'getent passwd: gündelik komut.',
    'SATSUMA-DISC-004': 'ps aux, top, htop: gündelik komutlar.',
    'SATSUMA-DISC-005': 'find, locate, ls -la /: gündelik komutlar.',
    'SATSUMA-DISC-006': 'systemctl list-units: gündelik komut.',
    'SATSUMA-EXEC-010': 'Kabuk betiklerinin çoğu eval kullanır.',
    'SATSUMA-EXFIL-001': 'dig +short gündelik bir DNS sorgusudur.',
    'SATSUMA-EXFIL-016': 'git clone/push (gh kullanıyorsunuz).',
    'SATSUMA-IMP-004': 'systemctl stop/disable sahibin servis yönetimidir.',
    'SATSUMA-LINUX-CLI-004': 'Yorumlayıcının kabuk açması paket betiklerinde olağandır.',
    'SATSUMA-DEV-003': 'Disk biçimlendirme (udisksd) ve ürün yazılımı güncellemesi (fwupd) ham diske yazar.',
    'SATSUMA-DEV-004': 'Süreç değil, aygıt izni bulgusudur; durdurulacak süreç yoktur.',
}

SEVERITY_FLOOR = {'info': 'high', 'low': 'high', 'medium': 'high'}


def enabled(store):
    value = store.get(STORE_KEY, None) if store is not None else None
    return not (isinstance(value, dict) and value.get('enabled') is False)


def apply(finding):
    """Raise a strict rule's finding so the ordinary stop path acts on it."""
    event = finding.get('event') if isinstance(finding.get('event'), dict) else {}
    if finding.get('rule_id') in MODULE_RULES:
        if not module_change_stops(event):
            return finding
    elif finding.get('rule_id') not in STRICT_STOP:
        return finding
    finding['owner_strict'] = True
    finding['log_only'] = False
    if str(finding.get('classification')).lower() in ('indicator', 'info', ''):
        finding['classification'] = 'suspicious'
    finding['severity'] = SEVERITY_FLOOR.get(str(finding.get('severity')).lower(), finding.get('severity'))
    finding['actions'] = [a for a in (finding.get('actions') or []) if a != 'log_only']
    return finding
