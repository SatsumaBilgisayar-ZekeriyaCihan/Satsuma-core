"""What the panel says to the user: verdict, what needs them, protection layers, what happened.

2.2.45 (owner, 2026-11-18: "the dashboard must be complete, usable and built
around the user"). The reader gathers evidence; this module turns it into the
few things a person needs: one verdict, the items that wait for them (each
with the action that resolves it), the state of each protection layer, and a
feed of what happened where repeats are folded into one line ("11 kez").
No Qt, no database: plain data in, plain data out, so every sentence is tested.

Panelin kullanıcıya söyledikleri: tek cümlelik durum, sizi bekleyenler (her
biri çözen eylemle), koruma katmanları ve olanlar; tekrarlar tek satırda.
"""
import time

SEVERITY_ORDER = {'critical': 0, 'high': 1, 'medium': 2, 'low': 3, 'info': 4}
SEVERITY_LABELS = {'critical': 'Kritik', 'high': 'Yüksek', 'medium': 'Orta', 'low': 'Düşük', 'info': 'Bilgi'}
TONE_ORDER = {'critical': 0, 'warning': 1, 'info': 2}

# What Satsuma did, as the user reads it. Satsuma'nın yaptığı, kullanıcı diliyle.
OUTCOMES = {
    'stopped': 'Durduruldu',
    'blocked': 'Engellendi',
    'cut': 'Bağlantı kesildi',
    'quarantined': 'Karantinada',
    'waiting': 'Onayınızı bekliyor',
    'not_stopped': 'Durdurulamadı',
    'reported': 'Bildirildi',
}
OUTCOME_RANK = {'stopped': 0, 'quarantined': 1, 'blocked': 2, 'cut': 3, 'waiting': 4, 'not_stopped': 5, 'reported': 6}
BLOCK_ACTIONS = ('suricata.network_block', 'otx.indicator_block', 'incoming_block', 'network.block', 'ip_block')


def _text(value, limit=200):
    if value is None or isinstance(value, (dict, list)):
        return ''
    text = ' '.join(str(value).split())
    return text if len(text) <= limit else text[:limit - 1] + '…'


def _num(value):
    try:
        return float(value)
    except (TypeError, ValueError):
        return 0.0


# ---------------------------------------------------------------- activity

def _event(finding):
    event = finding.get('event')
    return event if isinstance(event, dict) else {}


def subject(finding):
    """The thing a finding is about, in one short string: program, address, name or file."""
    event = _event(finding)
    for source in (finding, event):
        for key in ('exe', 'path', 'domain', 'query', 'dest_ip', 'ip', 'src_ip'):
            value = _text(source.get(key), 160)
            if value:
                return value
    extensions = ((event.get('metadata') or {}).get('extensions') or {}) if isinstance(event.get('metadata'), dict) else {}
    for key in ('host.exe', 'host.path', 'dns.query', 'dest_ip'):
        value = _text(extensions.get(key), 160)
        if value:
            return value
    return ''


def outcome(action):
    """One action record -> (outcome key, plain sentence)."""
    name = str(action.get('action') or '')
    status = str(action.get('status') or '')
    if name == 'process.terminate' or status in ('terminated', 'report_only', 'exempt', 'identity_verification_failed'):
        if status == 'terminated' and action.get('exit_verified') is True:
            return 'stopped', 'Program durduruldu; kapandığı doğrulandı.'
        if status == 'exempt':
            return 'not_stopped', 'Korunan bir program olduğu için durdurulmadı.'
        if status == 'report_only':
            return 'reported', 'Program durdurulmadı; yalnızca bildirildi.'
        if status == 'identity_verification_failed':
            return 'not_stopped', 'Program son anda doğrulanamadığı için durdurulmadı.'
        if status in ('awaiting_approval', 'approval_pending'):
            return 'waiting', 'Durdurmak için onayınız bekleniyor.'
        if action.get('signal_sent') is True:
            return 'stopped', 'Programa durma sinyali gönderildi.'
    if name == 'process.approval':
        return 'waiting', 'Durdurmak için onayınız bekleniyor.'
    if name in BLOCK_ACTIONS and status not in ('failed', 'ACTION_UNSUPPORTED', 'observe_only', 'policy_denied'):
        return 'blocked', 'Adres engellendi.'
    if name == 'network.connection_kill' and action.get('terminated') is True:
        return 'cut', 'Bağlantı kesildi.'
    if 'quarantin' in name or status == 'quarantined':
        return 'quarantined', 'Dosya karantinaya alındı.'
    return None, ''


def group_activity(findings, actions, limit=200):
    """Fold findings and actions into one feed; repeats become one row with a count.

    ``findings`` and ``actions`` are lists of (created, body) pairs. A row is
    keyed by rule, subject and outcome, so the same program reported every
    poll (field 2026-11-18: SATSUMA-FILELESS-002 every 3 s) is one line.
    """
    by_finding = {}
    for created, action in actions:
        if not isinstance(action, dict):
            continue
        key, sentence = outcome(action)
        if key is None:
            continue
        fid = action.get('finding_id')
        if fid:
            current = by_finding.get(str(fid))
            if current is None or OUTCOME_RANK[key] < OUTCOME_RANK[current[0]]:
                by_finding[str(fid)] = (key, sentence, action)
    groups = {}

    def add(key, row, stamp):
        group = groups.get(key)
        if group is None:
            groups[key] = {**row, 'count': 1, 'first_at': stamp, 'last_at': stamp}
            return
        group['count'] += 1
        if stamp >= group['last_at']:
            group['last_at'] = stamp
            for field in ('finding_id', 'detail', 'recommendation'):
                if row.get(field):
                    group[field] = row[field]
        group['first_at'] = min(group['first_at'], stamp)
        if SEVERITY_ORDER.get(row['severity'], 5) < SEVERITY_ORDER.get(group['severity'], 5):
            group['severity'] = row['severity']

    linked = set()
    for created, finding in findings:
        if not isinstance(finding, dict):
            continue
        fid = str(finding.get('finding_id') or '')
        rule = str(finding.get('rule_id') or (finding.get('matched_rules') or [''])[0] or '')
        what = subject(finding)
        severity = str(finding.get('severity') or 'medium').lower()
        result = by_finding.get(fid) if fid else None
        if result:
            linked.add(fid)
        key_outcome, sentence = (result[0], result[1]) if result else ('reported', 'Bildirildi; Satsuma bir işlem yapmadı.')
        stamp = _num(finding.get('timestamp')) or _num(created)
        title = _text(finding.get('rule_name') or finding.get('title') or finding.get('summary') or rule or 'Bulgu', 160)
        add(('f', rule, what, key_outcome), {
            'kind': 'finding', 'outcome': key_outcome, 'outcome_label': OUTCOMES[key_outcome],
            'title': title, 'subject': what, 'rule_id': rule or None, 'severity': severity,
            'severity_label': SEVERITY_LABELS.get(severity, severity), 'finding_id': fid or None,
            'what_happened': _text(finding.get('summary') or finding.get('rule_name') or title, 400),
            'what_satsuma_did': sentence,
            'recommendation': _text(finding.get('recommendation'), 400),
            'ip': _text(finding.get('dest_ip') or finding.get('ip') or _event(finding).get('dest_ip'), 64) or None,
            'domain': _text(finding.get('domain') or _event(finding).get('query'), 253) or None,
        }, stamp)
    for created, action in actions:
        if not isinstance(action, dict) or str(action.get('finding_id') or '') in linked:
            continue
        key, sentence = outcome(action)
        if key not in ('blocked', 'cut', 'quarantined'):
            continue
        target = _text(action.get('ip') or action.get('target') or action.get('path') or action.get('domain'), 160)
        stamp = _num(action.get('timestamp')) or _num(created)
        reason = _text(action.get('reason') or action.get('source'), 200)
        title = {'blocked': 'Şüpheli adres engellendi', 'cut': 'Şüpheli bağlantı kesildi',
                 'quarantined': 'Dosya karantinaya alındı'}[key]
        add(('a', str(action.get('action')), target, key), {
            'kind': 'action', 'outcome': key, 'outcome_label': OUTCOMES[key], 'title': title,
            'subject': target, 'rule_id': action.get('rule_id'), 'severity': 'medium', 'severity_label': 'Orta',
            'finding_id': None, 'what_happened': reason or title, 'what_satsuma_did': sentence,
            'recommendation': '', 'ip': _text(action.get('ip'), 64) or None, 'domain': _text(action.get('domain'), 253) or None,
        }, stamp)
    rows = sorted(groups.values(), key=lambda g: -g['last_at'])[:max(1, int(limit))]
    for row in rows:
        row['actions'] = available_actions(row)
        row['id'] = '|'.join(str(x) for x in (row['kind'], row.get('rule_id') or '', row['subject'], row['outcome']))
    return rows


def available_actions(row):
    """What the user can do about one feed row; operator methods, never shell."""
    actions = []
    if row.get('ip') and row['outcome'] == 'blocked':
        actions.append({'label': 'Engeli kaldır', 'method': 'unblock', 'params': {'ip': row['ip']}, 'weakens': True})
        actions.append({'label': 'Bu adrese hep izin ver', 'method': 'allow_ip', 'params': {'ip': row['ip']}, 'weakens': True})
    if row.get('domain'):
        actions.append({'label': 'Bu alan adına izin ver', 'method': 'allow_domain', 'params': {'domain': row['domain']}, 'weakens': True})
    if row['outcome'] == 'waiting':
        actions.append({'label': 'Onay bekleyenleri aç', 'open': 'protection:process'})
    if row.get('finding_id'):
        actions.append({'label': 'Teknik ayrıntı', 'open': 'expert:findings', 'finding_id': row['finding_id']})
    return actions


def activity_counts(rows, now=None, hours=24):
    now = time.time() if now is None else now
    recent = [r for r in rows if now - r['last_at'] <= hours * 3600]
    count = lambda key: sum(r['count'] for r in recent if r['outcome'] == key)
    return {'stopped': count('stopped'), 'blocked': count('blocked') + count('cut'), 'quarantined': count('quarantined'),
            'reported': count('reported') + count('not_stopped'), 'waiting': count('waiting'),
            'findings': sum(r['count'] for r in recent if r['kind'] == 'finding')}


# ---------------------------------------------------------------- layers

def _layer(key, title, state, label, detail, target):
    return {'id': key, 'title': title, 'state': state, 'label': label, 'detail': detail, 'target': target}


def layers(info):
    """State of each protection layer from the reader's evidence.

    ``info`` keys: enforcement, test_mode, health (self-health report),
    summary (status_view.health_summary), dns_policy, dns_health, app (app
    firewall status), otx (reader otx status), suricata (telemetry state).
    """
    health = info.get('health') or {}
    checks = health.get('checks') or {}
    fresh = health.get('status') not in ('STALE', 'UNAVAILABLE', 'NOT_RUN', None)

    def failed(*names):
        return fresh and any((checks.get(n) or {}).get('ok') is False for n in names)

    result = []
    enforcement = (info.get('enforcement') or {}).get('enabled', True)
    if info.get('test_mode') is True:
        result.append(_layer('process', 'Programlar ve bellek', 'on', 'Açık · durdurmadan önce sorar',
                             'Zararlı program bulunduğunda sizin onayınızla durdurulur.', 'protection:process'))
    elif enforcement:
        result.append(_layer('process', 'Programlar ve bellek', 'on', 'Açık · otomatik durdurur',
                             'Zararlı program bulunduğunda kendiliğinden durdurulur.', 'protection:process'))
    else:
        result.append(_layer('process', 'Programlar ve bellek', 'off', 'Kapalı · yalnızca bildirir',
                             'Zararlı programlar bildirilir ama durdurulmaz.', 'protection:process'))
    if failed('nfqueue_consumers', 'packet_drop', 'production_incoming_rules', 'subnet_protection'):
        result.append(_layer('network', 'Ağ ve trafik denetimi', 'problem', 'Sorunlu',
                             'Ağ denetiminin bir parçası çalışmıyor; Sağlık bölümünde onarabilirsiniz.', 'health'))
    elif fresh and checks:
        result.append(_layer('network', 'Ağ ve trafik denetimi', 'on', 'Açık',
                             'Tüm trafik Suricata denetiminden geçiyor; dışarıdan yeni bağlantı kabul edilmiyor.', 'protection:network'))
    else:
        result.append(_layer('network', 'Ağ ve trafik denetimi', 'unknown', 'Doğrulanmadı',
                             'Sağlık kontrolü güncel değil.', 'health'))
    dns_policy, dns_health = info.get('dns_policy') or {}, info.get('dns_health') or {}
    if not dns_policy.get('enabled'):
        result.append(_layer('dns', 'DNS filtresi', 'off', 'Kapalı', 'Zararlı alan adları engellenmiyor.', 'protection:dns'))
    elif failed('dns_filter') or dns_health.get('ok') is False:
        result.append(_layer('dns', 'DNS filtresi', 'problem', 'Sorunlu',
                             _text(dns_health.get('error'), 160) or 'Filtre yanıt vermiyor.', 'health'))
    else:
        count = dns_health.get('blocked_count')
        result.append(_layer('dns', 'DNS filtresi', 'on', 'Açık',
                             ('%s alan adı engelli.' % count) if count is not None else 'Zararlı alan adları engelleniyor.', 'protection:dns'))
    app = info.get('app') or {}
    pending = len(app.get('pending') or [])
    status = app.get('status')
    if status == 'ACTIVE':
        result.append(_layer('apps', 'Uygulama izinleri', 'on', 'Açık' + (' · %d bekliyor' % pending if pending else ''),
                             'Yeni bir uygulama internete çıkmadan önce size sorulur.', 'protection:apps'))
    elif status == 'HANDED_TO_OPENSNITCH':
        result.append(_layer('apps', 'Uygulama izinleri', 'on', 'OpenSnitch yönetiyor',
                             'Uygulama izinlerini OpenSnitch veriyor.', 'protection:apps'))
    elif status == 'DISABLED':
        result.append(_layer('apps', 'Uygulama izinleri', 'off', 'Kapalı',
                             'Uygulamalar izin sorulmadan internete çıkabilir.', 'protection:apps'))
    else:
        result.append(_layer('apps', 'Uygulama izinleri', 'problem' if status in ('STALE', 'NOT_RUNNING') else 'unknown',
                             'Çalışmıyor' if status in ('STALE', 'NOT_RUNNING') else 'Doğrulanmadı',
                             'Uygulama izin servisi durum bildirmiyor.', 'health'))
    summary = info.get('summary') or {}
    files = summary.get('files')
    if files == 'Sağlıklı':
        result.append(_layer('files', 'Dosyalar ve bütünlük', 'on', 'Açık',
                             'Satsuma dosyaları doğrulandı; dosyalar açılırken taranıyor.', 'protection:files'))
    elif files == 'Sorun var':
        result.append(_layer('files', 'Dosyalar ve bütünlük', 'problem', 'Sorun var',
                             'Uygulama dosyaları güvenilir referansla eşleşmiyor.', 'health'))
    else:
        result.append(_layer('files', 'Dosyalar ve bütünlük', 'unknown', 'Doğrulanmadı',
                             'Dosya doğrulaması henüz sonuç vermedi.', 'health'))
    otx = (info.get('otx') or {}).get('status')
    otx_map = {'ACTIVE': ('on', 'Açık', 'Bilinen saldırgan adresleri OTX ile denetleniyor.'),
               'CONFIGURED': ('on', 'Açık', 'Bilinen saldırgan adresleri OTX ile denetleniyor.'),
               'CONNECTING': ('on', 'Bağlanıyor', 'OTX kaynağına bağlanılıyor.'),
               'KEY_MISSING': ('off', 'Anahtar yok', 'OTX anahtarı girilmediği için bu katman kapalı.'),
               'DISABLED': ('off', 'Kapalı', 'OTX sorguları kapalı.'),
               'ERROR': ('problem', 'Bağlantı sorunu', 'OTX kaynağına ulaşılamıyor.')}
    state, label, detail = otx_map.get(otx, ('unknown', 'Doğrulanmadı', 'Tehdit istihbaratı durumu alınamadı.'))
    result.append(_layer('intel', 'Tehdit istihbaratı', state, label, detail, 'protection:intel'))
    return result


# ---------------------------------------------------------------- attention

def _item(key, tone, title, detail, actions):
    return {'id': key, 'tone': tone, 'title': title, 'detail': detail, 'actions': actions}


def attention(info):
    """Everything that waits for the user, most urgent first; each with what resolves it."""
    from .self_health import CHECK_LABELS
    items = []
    critical = info.get('critical_integrity') or {}
    if critical.get('status') == 'CRITICAL':
        items.append(_item('integrity', 'critical', 'Satsuma dosyaları doğrulanamadı',
                           _text(critical.get('reason') or critical.get('message'), 240) or
                           'Uygulama dosyaları güvenilir referansla eşleşmiyor; koruma kısıtlı çalışıyor.',
                           [{'label': 'Sağlığı aç', 'open': 'health'}]))
    health = info.get('health') or {}
    status = health.get('status')
    failed = [name for name, check in (health.get('checks') or {}).items()
              if isinstance(check, dict) and check.get('ok') is False]
    if status in ('DEGRADED', 'FAILED') and failed:
        names = [CHECK_LABELS.get(name, name) for name in failed]
        items.append(_item('health', 'warning',
                           ('%d sağlık kontrolü başarısız' % len(failed)) if len(failed) > 1 else names[0] + ' çalışmıyor',
                           ', '.join(names[:6]) + ('…' if len(names) > 6 else ''),
                           [{'label': 'Onar', 'method': 'repair', 'params': {}}, {'label': 'Ayrıntılar', 'open': 'health'}]))
    elif status in ('STALE', 'NOT_RUN', 'UNAVAILABLE'):
        items.append(_item('health', 'warning', 'Sağlık kontrolü güncel değil',
                           'Koruma son 15 dakikada doğrulanmadı.',
                           [{'label': 'Şimdi kontrol et', 'method': 'repair', 'params': {}}]))
    approvals = info.get('approvals') or {}
    if approvals.get('enabled') and (approvals.get('pending_count') or 0) > 0:
        count = approvals['pending_count']
        items.append(_item('approvals', 'warning', '%d program durdurulmak için onayınızı bekliyor' % count,
                           '"Durdurmadan önce bana sor" açık; siz karar verene kadar bu programlar çalışıyor.',
                           [{'label': 'İncele', 'open': 'protection:process'}]))
    for request in (info.get('app') or {}).get('pending') or []:
        application = request.get('application') or {}
        program = _text(application.get('executable'), 120) or 'Bir uygulama'
        name = program.rsplit('/', 1)[-1]
        count = request.get('connection_count') or 1
        items.append(_item('app:' + str(request.get('id')), 'warning', name + ' internete çıkmak istiyor',
                           program + ' → ' + _text(request.get('destination'), 80) + (' · %d bağlantı' % count if count > 1 else ''),
                           [{'label': 'İzin ver', 'method': 'application_control',
                             'params': {'action': 'decision', 'decision': 'allow', 'duration': 'application', 'request_id': request.get('id')}},
                            {'label': 'Engelle', 'method': 'application_control',
                             'params': {'action': 'decision', 'decision': 'deny', 'duration': 'application', 'request_id': request.get('id')}}]))
        if len([i for i in items if i['id'].startswith('app:')]) >= 3:
            break
    modem = info.get('network_identity') or {}
    if modem and modem.get('status') != 'MATCHED_USER_APPROVAL':
        items.append(_item('modem', 'warning', 'Modeminizi onaylayın',
                           'Satsuma, ağ geçidinin sizin modeminiz olduğunu bilmeden araya giren cihazları ayırt edemez.',
                           [{'label': 'Modemi onayla', 'open': 'settings:modem'}]))
    if info.get('admin_configured') is False:
        items.append(_item('admin', 'warning', 'Yönetici parolası belirlenmemiş',
                           'Ayarları değiştirmek için bir uçbirimde "sudo satsuma-kur" çalıştırın.', []))
    if (info.get('enforcement') or {}).get('enabled') is False and info.get('test_mode') is not True:
        items.append(_item('enforcement', 'info', 'Otomatik durdurma kapalı',
                           'Zararlı programlar bildiriliyor ama durdurulmuyor.',
                           [{'label': 'Aç', 'method': 'enforcement', 'params': {'enabled': True}}]))
    if (info.get('otx') or {}).get('status') == 'KEY_MISSING':
        items.append(_item('otx', 'info', 'Tehdit istihbaratı için OTX anahtarı ekleyin',
                           'Ücretsiz AlienVault OTX anahtarıyla bilinen saldırgan adresleri de engellenir.',
                           [{'label': 'Nasıl?', 'open': 'settings:keys'}]))
    items.sort(key=lambda i: TONE_ORDER[i['tone']])
    return items


def verdict(items, layer_list, reachable=True):
    if not reachable:
        return {'tone': 'unknown', 'title': 'Durum alınamıyor',
                'detail': 'Satsuma okuyucu servisine bağlanılamadı. Servis yeniden başlıyorsa birkaç saniye içinde düzelir.'}
    urgent = [i for i in items if i['tone'] in ('critical', 'warning')]
    problems = [l['title'] for l in layer_list if l['state'] == 'problem']
    off = [l['title'] for l in layer_list if l['state'] == 'off']
    if any(i['tone'] == 'critical' for i in items):
        return {'tone': 'critical', 'title': 'Müdahale gerekiyor', 'detail': items[0]['title'] + '.'}
    if urgent:
        title = ('%d konu sizi bekliyor' % len(urgent)) if len(urgent) > 1 else 'Bir konu sizi bekliyor'
        detail = ('Sorunlu: ' + ', '.join(problems) + '.') if problems else 'Koruma çalışıyor; aşağıdaki konular sizin kararınızı bekliyor.'
        return {'tone': 'attention', 'title': title, 'detail': detail}
    if problems:
        return {'tone': 'attention', 'title': 'Bir koruma katmanı sorunlu', 'detail': ', '.join(problems) + '.'}
    if all(l['state'] == 'unknown' for l in layer_list):
        return {'tone': 'unknown', 'title': 'Koruma doğrulanıyor', 'detail': 'İlk kontroller sürüyor; birkaç dakika içinde sonuç burada.'}
    detail = 'Tüm koruma katmanları açık.' if not off else 'Açık katmanlar çalışıyor. Kapalı: ' + ', '.join(off) + '.'
    return {'tone': 'ok', 'title': 'Korunuyorsunuz', 'detail': detail}


def home(info, findings=(), actions=(), now=None):
    """The whole home page in one structure (reader method ``home``)."""
    now = time.time() if now is None else now
    layer_list = layers(info)
    items = attention(info)
    rows = group_activity(list(findings), list(actions), limit=50)
    return {'verdict': verdict(items, layer_list, info.get('reachable', True)), 'attention': items,
            'layers': layer_list, 'counts': activity_counts(rows, now), 'recent': rows[:8],
            'checked_at': (info.get('health') or {}).get('updated_at'), 'generated_at': now}
