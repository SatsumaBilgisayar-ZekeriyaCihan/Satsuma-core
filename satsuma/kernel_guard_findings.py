"""Kernel guard events become findings (2.2.56).

satsuma-kernel-guard reads the protected /proc/sys settings every second and writes a
weakened value back; until 2.2.56 that only reached the journal and
/var/lib/satsuma-core/kernel-guard/events.jsonl, and the timer-based mitm_watch never saw
the change because the value was already put back. An attempt to loosen the kernel
through /proc/sys or /sys (SELinux to permissive, BPF or module loading opened, ptrace
blinding) now shows up in the dashboard like any other finding.

Çekirdek bekçisinin geri yazdığı her değişiklik artık panelde bulgu olarak görünür:
/proc/sys ya da /sys üzerinden korumayı gevşetme girişimi sessiz kalmaz.
"""
import hashlib
import json
import os
import time
from pathlib import Path

EVENTS = Path('/var/lib/satsuma-core/kernel-guard/events.jsonl')
STATE_KEY = 'kernel_guard_findings'
MAX_READ = 256 * 1024

TEXT = {
    'kernel_setting_changed': ('high', 'Çekirdek güvenlik ayarı gevşetildi',
                               'Bir program /proc/sys üzerinden çekirdek korumasını gevşetti. Satsuma değeri geri yazdı; '
                               'siz değiştirmediyseniz o anda çalışan süreçleri inceleyin.'),
    'selinux_permissive': ('critical', 'SELinux çalışırken kapatıldı (permissive)',
                           '/sys/fs/selinux/enforce 0 yapıldı. Satsuma enforcing durumuna geri aldı; '
                           'bunu yapan süreç root yetkisine sahip demektir.'),
    'ram_scanner_blinded': ('high', 'Bellek tarayıcısı kör edildi (ptrace_scope)',
                            'ptrace_scope 3 yapıldı; çekirdek yeniden başlatmaya kadar geri almaya izin vermez. Yeniden başlatın.'),
    'ram_scanner_blinding_source': ('high', 'ptrace_scope 3 kaynağı bulundu',
                                    'Bir sysctl dosyası ya da açılış satırı bellek tarayıcısını kör ediyor; Satsuma kaldırdı.'),
    'boot_cmdline_changed': ('high', 'Çekirdek açılış satırı değiştirildi',
                             'Güvenlik açılış argümanları (lockdown, init_on_free...) silinmiş; Satsuma geri ekledi.'),
    'mount_changed': ('high', 'Bellek ya da sistem bağlama seçenekleri değişti',
                      'noexec/nosuid gibi koruyucu bağlama seçenekleri kaldırılmış; Satsuma geri bağladı.'),
    'unit_changed': ('medium', 'Satsuma koruma birimi durduruldu ya da maskelendi',
                     'Bir koruma servisi devre dışı bırakıldı; Satsuma yeniden başlattı.'),
    'kernel_profile_pattern_changed': ('medium', 'Çekirdek profil kaydı değiştirildi',
                                       'Satsuma çekirdek profil kaydını yeniden yazdı.'),
}
SEVERITY_CLASS = {'critical': 'likely', 'high': 'suspicious', 'medium': 'indicator'}


def _read_new(path, state):
    """New lines since the last read; a replaced or truncated file is read from the start."""
    try:
        info = os.stat(path)
    except OSError:
        return [], state
    offset = int(state.get('offset') or 0)
    if state.get('inode') != info.st_ino or info.st_size < offset:
        offset = 0
    if info.st_size == offset:
        return [], {'inode': info.st_ino, 'offset': offset}
    with open(path, 'rb') as stream:
        stream.seek(offset)
        chunk = stream.read(MAX_READ)
    end = chunk.rfind(b'\n') + 1
    lines = []
    for raw in chunk[:end].splitlines():
        try:
            item = json.loads(raw)
        except ValueError:
            continue
        if isinstance(item, dict):
            lines.append(item)
    return lines, {'inode': info.st_ino, 'offset': offset + end}


def to_finding(event, now=None):
    kind = str(event.get('kind') or '')
    if kind not in TEXT:
        return None
    severity, title, advice = TEXT[kind]
    if event.get('restored') is False:
        reason = event.get('reason') or 'bilinmiyor'
        advice += f' Geri alınamadı ({reason}): sudo satsuma-admin tam-kontrol çalıştırın.'
        if severity == 'medium':
            severity = 'high'
    key = str(event.get('key') or '')
    digest = hashlib.sha256(json.dumps(event, sort_keys=True, default=str).encode()).hexdigest()[:16]
    detail = {k: v for k, v in event.items() if k not in ('kind', 'key', 'time')}
    return {'finding_id': f'SATSUMA-KGUARD-{kind.upper()}:{digest}', 'rule_id': 'SATSUMA-KGUARD-' + kind.upper(),
            'timestamp': float(event.get('time') or now or time.time()), 'severity': severity,
            'classification': SEVERITY_CLASS[severity], 'source': 'kernel_guard', 'title': f'{title}: {key}',
            'summary': ', '.join(f'{k}={v}' for k, v in sorted(detail.items()))[:400], 'advice': advice,
            'item': event, 'status': 'REVIEW', 'enforcement_eligible': False}


def collect(store, path=EVENTS):
    state = store.get(STATE_KEY, None) or {}
    first = not state
    events, state = _read_new(path, state)
    store.set(STATE_KEY, state)
    if first:
        # Installed or upgraded now: old guard history is not news.
        return []
    from .finding_store import record_finding
    found = []
    for finding in (to_finding(e) for e in events):
        # The same change again within a day raises the count, not a new alarm.
        if finding and record_finding(store, finding, 'kernel_guard').get('written'):
            found.append(finding)
    return found
