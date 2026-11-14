"""Tell Satsuma's own administrative actions apart from attacks, and date findings by the event.

Field log 2026-10-25: stopping a service from the dashboard ran
"systemctl stop satsuma-reader" under satsuma-operator, and SATSUMA-EVASION-002
reported it as a critical "security tool disabled" attack six minutes later;
the user took it for a live intrusion. A process whose parent runs in
satsuma-operator.service's cgroup was started by the authenticated operator
channel (cgroup membership can only be changed by root), so such a finding is
kept but marked origin=satsuma_operator, lowered to info/indicator and
labelled as an administrative action. Findings also take the event's own time;
when they were processed is kept as detected_at.

Satsuma'nın kendi yönetici işlemlerini saldırılardan ayırır ve bulgulara
olayın zamanını verir.

2026-10-25 saha kaydı: panelden bir servisi durdurmak satsuma-operator altında
"systemctl stop satsuma-reader" çalıştırdı; SATSUMA-EVASION-002 bunu altı
dakika sonra kritik bir "güvenlik aracı devre dışı" saldırısı olarak bildirdi,
kullanıcı da canlı bir saldırı sandı. Üst süreci satsuma-operator.service
cgroup'unda çalışan bir süreç kimliği doğrulanmış operatör kanalınca
başlatılmıştır (cgroup üyeliğini yalnızca root değiştirebilir); böyle bir bulgu
silinmez, origin=satsuma_operator olarak işaretlenir, info/indicator düzeyine
indirilir ve yönetici işlemi diye etiketlenir. Bulgular olayın kendi zamanını
alır; işlendikleri an detected_at olarak saklanır.
"""
import time
from datetime import datetime

from .process_identity import read_proc_cgroup
from .trusted_process import system_service

OPERATOR_UNIT = 'satsuma-operator.service'
MAX_EVENT_AGE = 30 * 86400


def started_by_operator(event, cgroup_of=read_proc_cgroup):
    for key in ('ppid', 'pid'):
        try:
            pid = int(event.get(key))
        except (TypeError, ValueError):
            continue
        if pid > 1 and system_service(cgroup_of(pid)) == OPERATOR_UNIT:
            return True
    return False


def event_epoch(value, now):
    if isinstance(value, (int, float)):
        epoch = float(value)
    elif isinstance(value, str) and value:
        try:
            epoch = datetime.fromisoformat(value.replace('Z', '+00:00')).timestamp()
        except ValueError:
            return None
    else:
        return None
    return epoch if now - MAX_EVENT_AGE <= epoch <= now + 60 else None


def annotate(finding, event, now=None, cgroup_of=read_proc_cgroup):
    now = time.time() if now is None else now
    finding['detected_at'] = int(now)
    when = event_epoch(event.get('timestamp'), now)
    if when is not None:
        finding['timestamp'] = int(when)
    if started_by_operator(event, cgroup_of):
        finding['origin'] = 'satsuma_operator'
        finding['original_severity'] = finding.get('severity')
        finding['severity'] = 'info'
        finding['classification'] = 'indicator'
        label = 'Panelden yönetici işlemi (satsuma-operator): '
        for key in ('summary', 'rule_name'):
            if finding.get(key) and not str(finding[key]).startswith(label):
                finding[key] = label + str(finding[key])
    return finding
