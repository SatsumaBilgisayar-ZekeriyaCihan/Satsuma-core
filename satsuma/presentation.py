"""Shared event/finding priority and process fields; never invent attribution.

Action outcomes say in plain Turkish what happened, including a stop that
was refused at the last check and at which stage. A refused automatic
action shows its reasons (2.2.11), and a plain activity indicator reads as
"only reported", not as a refusal.

Ortak olay/bulgu önceliği ve işlem alanları; asla atıf uydurulmaz. Eylem
sonuçları, son denetimde reddedilen bir durdurmayı ve hangi aşamada
reddedildiğini de sade Türkçeyle anlatır. Uygulanmayan otomatik eylem
sebeplerini gösterir (2.2.11); sıradan bir etkinlik göstergesi "reddedildi"
değil "yalnızca bildirildi" diye görünür.
"""
from datetime import datetime
import math

SEVERITY = {'critical': 0, 'high': 1, 'medium': 2, 'low': 3, 'info': 4}
CLASSIFICATION = {'confirmed': 0, 'likely': 1, 'suspicious': 2, 'indicator': 3}
CLASS_LABELS = {'confirmed': 'Doğrulanmış', 'likely': 'Olası', 'suspicious': 'Şüpheli', 'indicator': 'Gösterge'}
SEVERITY_LABELS = {'critical': 'Kritik', 'high': 'Yüksek', 'medium': 'Orta', 'low': 'Düşük', 'info': 'Bilgi'}


RECHECK_OUTCOMES = {
    'debugger_attached_review_required': 'işleme bir debugger bağlı; karar sizin',
    'debugger_state_unknown': 'debugger durumu okunamadı; karar sizin',
    'code_recheck_failed': 'son kontrolde bellek kodu farkı görülmedi',
    'identity_recheck_failed': 'işlemin kimliği değişti',
}
STAGES = {'before_sigterm': 'SIGTERM öncesi', 'before_sigkill': 'SIGKILL öncesi'}


REASONS = {
    'activity_indicator_reports_only': 'Sıradan etkinlik göstergesi; yalnızca bildirilir',
    'missing_event_process_identity': 'Olayda süreç kimliği (PID) yok',
    'historical_or_future_event': 'Olay zamanı güncel müdahale aralığı dışında (eski veya ileri tarihli)',
    'missing_or_invalid_event_time': 'Olay zamanı okunamadı',
    'automatic_process_response_disabled': 'Otomatik program durdurma kapalı',
    'response_disabled': 'Otomatik müdahale kapalı',
    'destructive_response_policy_disabled': 'Yıkıcı müdahale ilkesi kapalı',
    'destructive_action_not_in_policy': 'Eylem ilkede yok',
    'admin_session_required': 'Yönetici oturumu gerekli',
    'remote_advisory_only': 'Uzak güvenlik duvarı önerisi; yerelde uygulanmaz',
    'protected_pid': 'Korunan süreç (PID 1 ya da Satsuma)',
    'missing_or_invalid_pid': 'Süreç kimliği geçersiz',
    'finding_policy_denied': 'Bulgu müdahaleye izin vermiyor',
    'protected_target': 'Korunan adres',
    'protected_gateway_or_dns': 'Modem ya da DNS sunucusu; engellenmez',
}


def reason_text(item):
    reasons = item.get('reasons')
    if isinstance(reasons, (list, tuple)) and reasons:
        return ', '.join(REASONS.get(str(r), str(r)) for r in reasons)
    return None


def action_outcome(item):
    status, reason = item.get('status'), str(item.get('reason') or '')
    if status in RECHECK_OUTCOMES:
        prefix = ('SIGTERM gönderildi; SIGKILL uygulanmadı' if item.get('signal_sent') is True
                  else 'Sonlandırılmadı')
        stage = STAGES.get(item.get('stage'))
        return prefix + (' (' + stage + ')' if stage else '') + ': ' + RECHECK_OUTCOMES[status]
    if status == 'exempt':
        return 'Sonlandırılmadı: korunan program (' + str(item.get('exemption') or '') + ')'
    if status == 'terminated' and item.get('exit_verified') is True:
        return 'Süreç sonlandırıldı; çıkışı doğrulandı'
    if item.get('signal_sent') is True:
        return 'Sonlandırma sinyali gönderildi; çıkış doğrulanmadı'
    if status == 'evidence_recorded' and isinstance(item.get('process_response'),dict):
        return 'Süreç kararı: '+action_outcome(item['process_response'])+' · Ağ hedefi: '+('belirlendi' if item.get('target') else 'belirlenmedi')
    if status == 'identity_verification_failed':
        why = str(item.get('reason') or (item.get('identity') or {}).get('reason') or '')
        if why == 'live_process_not_found':
            return 'Durdurulmadı: süreç bundan önce kendiliğinden sonlanmıştı (yanlış hedef riski yok)'
        return 'Durdurulmadı: süreç kimliği son anda doğrulanamadı' + (' (' + why + ')' if why else '')
    if status == 'connection_terminated' and item.get('terminated') is True:
        return 'Bağlantı kesildi; doğrulandı' if item.get('verified') is True else 'Bağlantı kesildi; doğrulanmadı'
    outcomes = {
        'process_termination_authorized': 'Sonlandırma yetkilendirildi (ara adım); sonuç bir sonraki kayıtta',
        'policy_denied': 'Uygulanmadı: politika izin vermedi',
        'report_only': 'Süreç durdurulmadı; bulgu yalnızca bildirildi',
        'operator_paused': 'Uygulanmadı: operatör duraklattı',
        'response_disabled': 'Uygulanmadı: otomatik müdahale kapalı',
        'integrity_observe_only': 'Uygulanmadı: bütünlük kontrolü izin vermedi',
        'evidence_recorded': 'Kanıt kaydedildi',
        'recorded': 'Kayıt oluşturuldu',
        'correlation_requested': 'Korelasyon istendi',
        'rate_limited': 'Uygulanmadı: işlem sıklığı sınırı',
    }
    if status in outcomes:
        return outcomes[status]
    if item.get('source') == 'suricata_guard':
        if status == 'ACTION_UNSUPPORTED' and 'direction_unverified' in reason:
            return 'Algılandı, engellenmedi: bağlantı yönü doğrulanamadı'
        if status in ('ACTION_UNSUPPORTED','observe_only'):
            return 'Algılandı, engellenmedi: '+reason
        if status == 'ACTION_FAILED':
            return 'Algılandı, engellenmedi: ' + str(item.get('detail') or reason)
        if status == 'set_membership_confirmed':
            return ('Paket düşürme doğrulandı' if item.get('traffic_drop_verified') is True
                    else 'Engel kuralı doğrulandı; paket düşürme ölçülmedi')
        if status == 'suricata_alert':return 'Algılandı; engelleme sonucu bekleniyor'
    if item.get('traffic_drop_verified') is True:return 'Paket düşürme doğrulandı'
    if status in ('set_membership_confirmed','nft_element_restored','ip_blocked'):return 'Engel kuralı doğrulandı; paket düşürme ölçülmedi'
    return ''


def layers(item):
    result = [item]
    for key in ('raw', 'event', 'finding'):
        value = item.get(key)
        if isinstance(value, dict):
            result.extend(layers(value))
    meta = item.get('metadata') or {}
    if isinstance(meta, dict) and isinstance(meta.get('finding'), dict):
        result.extend(layers(meta['finding']))
    return result


def epoch(value):
    try:
        if isinstance(value, (float, int)):
            return float(value) if math.isfinite(float(value)) else 0.0
        return datetime.fromisoformat(str(value).replace('Z', '+00:00')).timestamp()
    except (ValueError, TypeError, OverflowError):
        return 0.0


def process_fields(item):
    names, pids = [], []
    for source in layers(item):
        ext = (source.get('metadata') or {}).get('extensions') or {}
        process = source.get('process') if isinstance(source.get('process'), dict) else {}
        actor = source.get('actor') if isinstance(source.get('actor'), dict) else {}
        actor_process = actor.get('process') if isinstance(actor.get('process'), dict) else {}
        for obj in (source, process, actor_process, ext):
            name = obj.get('process_name') or obj.get('comm') or obj.get('exe') or obj.get('host.comm') or obj.get('host.exe')
            if obj is process or obj is actor_process:
                name = name or obj.get('name')
            if not name:
                command = obj.get('cmd') or obj.get('host.cmd') or obj.get('command_line')
                if isinstance(command, str):
                    import shlex
                    try:
                        parts = shlex.split(command)
                        name = parts[0] if parts else None
                    except ValueError:
                        pass
            if name and str(name) not in names:
                names.append(str(name))
            pid = obj.get('pid') or obj.get('host.pid') or obj.get('process_pid')
            if pid is not None and str(pid).isdigit() and str(pid) not in pids:
                pids.append(str(pid))
    return ', '.join(names[:4]) or 'Bilinmiyor', ', '.join(pids[:4]) or 'Bilinmiyor'


def fields(item):
    sources = layers(item)
    severity = next((s.get('severity') or (s.get('alert') or {}).get('severity') for s in sources if s.get('severity') is not None or (s.get('alert') or {}).get('severity') is not None), None)
    if isinstance(severity, int):
        severity = {1: 'high', 2: 'medium', 3: 'low'}.get(severity)
    severity = str(severity or 'unknown').lower()
    classification = next((str(s['classification']).lower() for s in sources if s.get('classification')), 'unknown')
    stamp = next((s.get('timestamp') or s.get('_record_created') for s in sources if s.get('timestamp') or s.get('_record_created')), None)
    process_name, pid = process_fields(item)
    return {'severity': severity, 'classification': classification, 'timestamp': stamp,
            'action_outcome': action_outcome(item),
            'severity_label': SEVERITY_LABELS.get(severity, 'Bilinmiyor'),
            'classification_label': CLASS_LABELS.get(classification, 'Bilinmiyor'),
            'process_name': process_name, 'pid': pid,
            'time_label': datetime.fromtimestamp(epoch(stamp)).strftime('%d.%m.%Y %H:%M:%S') if epoch(stamp) else 'Bilinmiyor'}


def priority_key(item):
    view = fields(item)
    return (SEVERITY.get(view['severity'], 5), CLASSIFICATION.get(view['classification'], 4), -epoch(view['timestamp']))


AUDIT_LABELS={'USER_START':'Oturum açıldı','USER_END':'Oturum kapandı','USER_AUTH':'Kimlik doğrulama',
 'USER_LOGIN':'Kullanıcı girişi','USER_ACCT':'Hesap denetimi','CRED_ACQ':'Oturum yetkileri alındı',
 'CRED_DISP':'Oturum yetkileri bırakıldı','USER_CMD':'Kullanıcı komutu','SYSCALL':'Sistem çağrısı',
 'EXECVE':'Program çalıştırma','AVC':'SELinux erişim kararı'}

def audit_summary(item):
    types=item.get('types') or []
    text=', '.join(AUDIT_LABELS[t] for t in dict.fromkeys(types) if t in AUDIT_LABELS)
    return text or ', '.join(types) or 'Olay türü kayıtta belirtilmemiş'

def action_view(item):
    item=dict(item)
    item['timestamp']=item.get('timestamp') or item.get('_record_created')
    item['target']=item.get('target') or item.get('ip') or item.get('domain') or item.get('path')
    status=str(item.get('status') or '').upper()
    outcome=action_outcome(item)
    if not outcome:
        outcome=('Engellendi' if item.get('traffic_drop_verified') is True else
                 'Başarısız' if 'FAIL' in status else
                 'Onay bekliyor' if status in ('REQUESTED','PENDING','AWAITING_APPROVAL') else
                 'Algılandı; uygulama sonucu doğrulanmadı')
    item['outcome']=outcome
    item['reason']=item.get('reason') or reason_text(item) or item.get('detail') or item.get('title')
    item['internal']=item.get('action') in ('record','correlation_request')
    return item


def rule_behavior(actions):
    labels={'record':'Kaydet','notify':'Uyar','alert':'Uyar','ask':'Kullanıcıya sor',
            'block':'Engelle','block_ip':'Engelle','network.block':'Engelle',
            'evidence':'Kanıt topla','correlation_request':'İlişkilendirmeye gönder'}
    names=[a if isinstance(a,str) else a.get('type') or a.get('action') for a in actions if isinstance(a,(str,dict))]
    return ' / '.join(dict.fromkeys(labels.get(name,'Politika kapısına gönder: '+str(name)) for name in names)) or 'Davranış kayıtta belirtilmemiş'
