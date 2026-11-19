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
    'SATSUMA-GAP-036', 'SATSUMA-GAP-037', 'SATSUMA-GAP-052', 'SATSUMA-GAP-075',
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
})

# Kept as reports: what each would stop is the machine or the owner, not an attacker.
EXCLUDED = {
    'SATSUMA-ROOT-003': 'Her program /dev/null ve terminaline yazar; her şey durdurulurdu.',
    'SATSUMA-COLL-015': 'Her oturum açma, ls ve sudo /etc/passwd okur.',
    'SATSUMA-SUDO-HARD-003': 'sudo her çalışmada /etc/sudoers okur; sudo durdurulurdu.',
    'SATSUMA-DEV-002': 'Masaüstü (cosmic-comp) klavye ve fareyi /dev/input üzerinden okur.',
    'SATSUMA-NET-203': 'NetworkManager resolv.conf yazar; internet giderdi.',
    'SATSUMA-NET-202': 'firewalld kendi yapılandırmasını yazar.',
    'SATSUMA-NET-201': 'Her yeni dinleyen uygulama (Steam, KDE Connect...) durdurulurdu.',
    'SATSUMA-COLL-005': 'Thunderbird/Evolution kendi posta dosyalarını okur.',
    'SATSUMA-COLL-006': 'Firefox kendi geçmişini okur.',
    'SATSUMA-COLL-007': 'Firefox kendi çerezlerini okur.',
    'SATSUMA-COLL-008': 'ssh known_hosts ve config okur.',
    'SATSUMA-COLL-016': 'ssh kendi özel anahtarını okur.',
    'SATSUMA-COLL-017': 'gpg-agent kendi anahtarlarını okur.',
    'SATSUMA-COLL-018': 'kubectl kendi yapılandırmasını okur.',
    'SATSUMA-COLL-019': 'aws aracı kendi kimlik dosyasını okur.',
    'SATSUMA-COLL-020': 'docker/podman kendi yapılandırmasını okur.',
    'SATSUMA-PRIV-017': 'Açılışta sürücüleri modprobe yükler; dosyadan/zorla yükleme GAP-073 ile durdurulur.',
    'SATSUMA-ROOT-001': 'Açılışta sürücüleri modprobe yükler (GAP-073 durdurur).',
    'SATSUMA-LNX-EVAS-005': 'Açılışta sürücüleri modprobe yükler (GAP-073 durdurur).',
    'SATSUMA-EVAS-014': 'udev sürücü kaldırır.',
    'SATSUMA-EVAS-015': 'systemd ve Satsuma açılışta sysctl yazar; çekirdek bekçisi her saniye geri yazar.',
    'SATSUMA-EVAS-013': 'Paket betikleri SELinux modülü kurar.',
    'SATSUMA-EVAS-010': 'Steam, gamemode ve snap LD_PRELOAD kullanır; yazılabilir dizinden yükleme GAP-041 ile durdurulur.',
    'SATSUMA-ROOT-002': 'Steam, gamemode ve snap LD_PRELOAD kullanır (GAP-041 durdurur).',
    'SATSUMA-EVAS-011': 'Firefox (snap), Steam ve birçok uygulama LD_LIBRARY_PATH ayarlar.',
    'SATSUMA-EVAS-012': 'rkhunter, chkrootkit, unhide: güvenlik taramaları (Satsuma da unhide çalıştırır).',
    'SATSUMA-ROOT-004': 'rkhunter, chkrootkit, unhide: güvenlik taramaları.',
    'SATSUMA-GAP-025': 'Sahibin kararı (2026-11-19): chattr +i sıkılaştırma için elle yapılıyor.',
    'SATSUMA-LNX-EVAS-001': 'Sahip kilitli dosyayı düzenlemek için chattr -i kullanır.',
    'SATSUMA-EVAS-009': 'Sahip kilitli dosyayı düzenlemek için chattr -i kullanır.',
    'SATSUMA-SUDO-003': 'sudoedit sahibin dosya düzenleme aracıdır.',
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
    'SATSUMA-EXFIL-005': 'rsync -av /home yedek almanın olağan yoludur.',
    'SATSUMA-EXFIL-016': 'git clone/push (gh kullanıyorsunuz).',
    'SATSUMA-EXFIL-010': 'ssh -L sahibin kendi kullanımı (saha geçmişi); ters tünel ssh -R GAP-034 ile durdurulur.',
    'SATSUMA-IMP-004': 'systemctl stop/disable sahibin servis yönetimidir.',
    'SATSUMA-LINUX-CLI-004': 'Yorumlayıcının kabuk açması paket betiklerinde olağandır.',
    'SATSUMA-DEV-003': 'Disk biçimlendirme (udisksd) ve ürün yazılımı güncellemesi (fwupd) ham diske yazar.',
    'SATSUMA-DEV-004': 'Süreç değil, aygıt izni bulgusudur; durdurulacak süreç yoktur.',
}

SEVERITY_FLOOR = {'info': 'high', 'low': 'high', 'medium': 'high'}


def enabled(store):
    value = store.get(STORE_KEY, None) if store is not None else None
    return not (isinstance(value, dict) and value.get('enabled') is False)


# The owner upgrades with "rpm-ostree uninstall satsuma-core ... --install satsuma-core-X.rpm"
# (installing a local RPM needs the admin password since 2.2.58): an upgrade stays an alarm.
UPGRADE = re.compile(r'(?:--install(?:=|\s+)|\s-i\s+)\S*satsuma-core-\d+\.\d+\.\d+-\d+\.\w+\.\w+\.rpm(?:\s|$)')


def apply(finding):
    """Raise a strict rule's finding so the ordinary stop path acts on it."""
    if finding.get('rule_id') not in STRICT_STOP:
        return finding
    event = finding.get('event') if isinstance(finding.get('event'), dict) else {}
    if finding.get('rule_id') in ('SATSUMA-GAP-036', 'SATSUMA-GAP-075') and UPGRADE.search(str(event.get('cmd') or '')):
        return finding
    finding['owner_strict'] = True
    finding['log_only'] = False
    if str(finding.get('classification')).lower() in ('indicator', 'info', ''):
        finding['classification'] = 'suspicious'
    finding['severity'] = SEVERITY_FLOOR.get(str(finding.get('severity')).lower(), finding.get('severity'))
    finding['actions'] = [a for a in (finding.get('actions') or []) if a != 'log_only']
    return finding
