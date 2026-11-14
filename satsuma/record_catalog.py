"""Catalog of every record kind Satsuma stores, explained in plain Turkish.

Field report 2026-11-04: many warnings stored in the database never reached
the panel, because the panel read only the dozen kinds it knew. This module
names every kind that the code writes, says what it is and why it matters,
and turns one record into a plain sentence. Kinds found in the database but
missing here are shown as "Tanımsız tür", never hidden. A test fails when
code writes a kind this catalog does not list.

Satsuma'nın sakladığı her kayıt türünün sade Türkçe kataloğu. Saha bildirimi
2026-11-04: veritabanındaki birçok uyarı panele hiç yansımıyordu, çünkü
panel yalnızca tanıdığı on kadar türü okuyordu. Bu modül kodun yazdığı her
türü adlandırır, ne olduğunu ve neden önemli olduğunu söyler, tek bir kaydı
düz cümleye çevirir. Veritabanında olup burada olmayan türler gizlenmez,
"Tanımsız tür" olarak gösterilir. Kod bu katalogda olmayan bir tür yazarsa
test başarısız olur.
"""
import time

from .database_view import redact
from .presentation import SEVERITY_LABELS, action_outcome, audit_summary


def _k(name, short, what, why, db='core', group='other'):
    return {'name': name, 'short': short, 'what': what, 'why': why, 'db': db, 'group': group}


KINDS = {
    'aide_events': _k('AIDE değişiklikleri', 'Örnekten sapmalar',
        'Kurulumdan sonra alınan AIDE örneğiyle karşılaştırmada bulunan eklenen, silinen ya da değişen dosyalar ve geri alma yolu.',
        'Sizin yapmadığınız bir ayar değişikliği saldırının izi olabilir; onayınızla geri alınır.', group='protection'),
    'aide_restores': _k('AIDE geri almaları', 'Onayla geri alınanlar',
        'Onayınızla örneğe döndürülen dosyalar: kopyadan, bekletme klasörüne alınarak ya da paketten.',
        'Neyin, ne zaman, hangi yolla geri alındığının kaydıdır.', group='protection'),
    'actions': _k('Müdahaleler', 'Satsuma’nın yaptığı işler',
        'Bir bulgu üzerine yapılan ya da değerlendirilen her işlem: süreç durdurma, bağlantı kesme, adres engelleme ve sonucu.',
        'Korumanın gerçekten iş yapıp yapmadığını buradan görürsünüz.', group='protection'),
    'findings': _k('Bulgular', 'Kuralların yakaladıkları',
        'Bir güvenlik kuralının şüpheli bulduğu olaylar; önemi ve benzediği saldırı tekniğiyle.',
        'Asıl dikkat edilmesi gereken liste budur.', group='protection'),
    'safe_evidence': _k('Kanıtlar', 'Her bulgunun dosyası',
        'Her bulgu için saklanan kanıt: program, kullanıcı, komut, üst süreç. Bellek ya da parola dökümü saklanmaz.',
        'Bir bulguya itiraz ederken ya da bir programa güvenirken karar buna dayanır.', group='protection'),
    'process_evidence': _k('Süreç kanıtları', 'Durdurulan süreçlerin kimliği',
        'Durdurulmadan önce bir sürecin doğrulanan kimliği: PID, başlangıç zamanı, program dosyası.',
        'Yanlış sürecin durdurulmadığının kanıtıdır.', group='protection'),
    'quarantine_actions': _k('Karantina', 'Karantinaya alınan dosyalar',
        'Karantinaya alınan, geri bırakılan ya da silinen dosyalar.',
        'Bir dosyanın neden ortadan kalktığını buradan görürsünüz.', group='protection'),
    'temporary_scan_detection': _k('Tarayıcı bellek taraması bulguları', 'Geçici bellek taramasının yakaladıkları',
        'Tarayıcı ve benzeri programların belleğinde ClamAV taramasının bulduğu imzalar.',
        'Tarayıcı üzerinden gelen saldırılar burada görünür.', group='protection'),
    'temporary_scan_error': _k('Tarayıcı bellek taraması hataları', 'Taramanın yapılamadığı durumlar',
        'Geçici bellek taramasının okuyamadığı ya da tamamlayamadığı süreçler.',
        'Tekrarlıyorsa tarama o programı göremiyor demektir.', group='health'),
    'memory_anomalies': _k('Bellek anormallikleri', 'Bellekte olağan dışı alanlar',
        'Süreç belleğinde çalıştırılabilir anonim alan, silinmiş dosyadan çalışan kod gibi işaretler.',
        'Bellekte saklanan zararlı kodun izidir.', group='protection'),
    'security_scan': _k('Güvenlik taramaları', 'ClamAV, rkhunter, chkrootkit',
        'Yerel antivirüs ve rootkit taramalarının sonuçları.',
        'Diskte bulunan zararlı dosyalar burada görünür.', group='protection'),
    'events': _k('Ham olaylar', 'Bilgisayarda olan her şey',
        'Çekirdek, süreç izleyici ve audit’ten gelen her olay. Kurallar bunların içinden seçer.',
        'Bir şey olduysa izi burada kalır; disk doluluğu en çok bundan gelir.', group='raw'),
    'normalized': _k('Düzenlenmiş olaylar', 'Kurallar için ortak biçim',
        'Ham olayların kuralların okuyabileceği tek biçime çevrilmiş hali.',
        'Ham olaylarla neredeyse aynı sayıda olmalı.', group='raw'),
    'audit_raw': _k('Audit kayıtları', 'Çekirdek denetim satırları',
        'Linux audit sisteminin ham satırları.', 'Çekirdeğin kendi gözüyle ne olduğunu gösterir.', group='raw'),
    'audit': _k('Oturum ve yetki olayları', 'Giriş, çıkış, sudo',
        'Oturum açma-kapama, kimlik doğrulama ve yetki değişiklikleri.',
        'Bilgisayara kimin girdiğini gösterir.', db='host', group='raw'),
    'evidence': _k('Sistem kanıtları', 'Sistem denetimi kanıtları',
        'Sistem denetiminin topladığı kanıtlar.', 'Sistem dosyalarındaki değişikliklerin dayanağıdır.', db='host', group='protection'),
    'dns': _k('DNS sorguları', 'Açılan alan adları',
        'Sorulan alan adları ve DNS filtresinin kararı.',
        'Ortadaki adam saldırısı ya da zararlı siteye gidiş ilk burada görünür.', group='network'),
    'alerts': _k('Trafik uyarıları', 'Suricata’nın gördükleri',
        'Ağ trafiğini inceleyen Suricata’nın imza eşleşmeleri.',
        'Ağdan gelen saldırı girişimleri burada görünür.', group='network'),
    'otx': _k('OTX eşleşmeleri', 'Tehdit istihbaratı (adres)',
        'Bağlanılan adresin AlienVault OTX tehdit kayıtlarında geçmesi.',
        'Eşik aşılınca adres engellenir.', group='network'),
    'otx_domains': _k('OTX alan adları', 'Tehdit istihbaratı (alan adı)',
        'OTX kayıtlarında geçen alan adları.', 'DNS filtresi bunları engeller.', group='network'),
    'flow_guard': _k('Akış bekçisi', 'Olay akışındaki sorunlar',
        'Olay akışını izleyen bekçinin bildirdikleri: kural motoru sustu, olay gelmedi, olay kayboldu, motor yeniden başlatıldı.',
        'Ham olaylar artık diske yazılmadığı için akıştaki bir kopukluk yalnızca burada görünür.', group='health'),
    'network_device_alerts': _k('Ağ cihazı uyarıları', 'Modem ve ağdaki cihazlar',
        'Ağda yeni ya da değişmiş cihaz, modem kimliği değişikliği.',
        'Ortadaki adam saldırısının ilk işaretlerinden biridir.', group='network'),
    'subnet_decisions': _k('Yerel ağ kararları', 'Ağdaki adreslere verilen kararlar',
        'Yerel ağdan gelen bağlantılar için verilen izin ya da engel kararları.',
        'Aynı ağdaki bir cihazın size saldırıp saldırmadığını gösterir.', group='network'),
    'gateway': _k('Ağ geçidi', 'Modem doğrulaması',
        'Modemin ve varsayılan rotanın doğrulama sonuçları.', 'Rotanın değiştirilmesi MITM işaretidir.', group='network'),
    'vpn_proxy_actions': _k('VPN / Proxy işlemleri', 'VPN ve proxy değişiklikleri',
        'VPN ve proxy ayarlarına yapılan işlemler.', 'Trafiğin nereden çıktığını değiştirir.', group='network'),
    'opnsense_events': _k('OPNsense olayları', 'Ağ güvenlik duvarından gelenler',
        'Bağlıysa OPNsense güvenlik duvarının bildirdiği olaylar.', 'Ağ düzeyindeki saldırıları gösterir.', group='network'),
    'sentinel': _k('Nöbetçi gözlemleri', 'Arka plan bekçisi',
        'Satsuma’nın kendi bütünlüğünü izleyen nöbetçinin gözlemleri.',
        'Satsuma’ya müdahale girişimi burada görünür.', group='health'),
    'sentinel_decisions': _k('Nöbetçi kararları', 'Bekçinin verdiği kararlar',
        'Nöbetçinin gözlemleri üzerine verdiği kararlar.', 'Satsuma’nın kendini nasıl koruduğunu gösterir.', group='health'),
    'protection_changes': _k('Koruma değişiklikleri', 'Açılan, kapanan ayarlar',
        'Bir koruma katmanının açılması, kapanması ya da ayarının değişmesi.',
        'Korumayı sizin dışınızda biri kapatırsa burada görürsünüz.', group='health'),
    'policy_events': _k('Politika olayları', 'Kural ve politika değişiklikleri',
        'Güvenlik politikasının yüklenmesi ve değişmesi.', 'Beklenmedik değişiklik bir müdahale işaretidir.', group='health'),
    'privd_audit': _k('Yetkili işlemler', 'Root yetkisiyle yapılanlar',
        'Satsuma’nın root yetkisi gereken her işlemi.',
        'Satsuma’nın kendisinin ne yaptığının denetim izidir.', group='health'),
    'module_lock': _k('Çekirdek modülü kilidi', 'Modül yükleme kilidi',
        'Çekirdeğe yeni modül yüklenmesinin kilitlenmesi ve sonucu.', 'Rootkit’ler çekirdek modülüyle gelir.', group='health'),
    'errors': _k('Hatalar', 'Bileşen sorunları',
        'Satsuma bileşenlerinin karşılaştığı hatalar.',
        'Aynı hata tekrarlanıyorsa bir parça çalışmıyor demektir.', group='health'),
    'host_errors': _k('Sistem denetimi hataları', 'Denetim kaynağı sorunları',
        'Audit kaynağının okunamaması ya da kesilmesi gibi sorunlar.',
        'Denetim kör kalırsa saldırı izi kaçabilir.', db='host', group='health'),
}

GROUPS = (('protection', 'Koruma'), ('network', 'Ağ'), ('health', 'Satsuma’nın sağlığı'),
          ('raw', 'Ham kayıtlar'), ('other', 'Tanımsız'))

UNKNOWN = {'name': 'Tanımsız tür', 'short': 'Katalogda açıklaması yok',
           'what': 'Bu tür veritabanında var ama Satsuma’nın kataloğunda açıklaması yok. Kayıtlar ham haliyle gösterilir.',
           'why': 'Gizlenmez; hiçbir uyarı görünmeden kalmasın diye listelenir.', 'group': 'other'}


def describe(kind):
    """Catalog entry of ``kind``; unknown kinds get a visible placeholder."""
    entry = KINDS.get(kind)
    if entry:
        return {'kind': kind, 'known': True, **entry}
    return {'kind': kind, 'known': False, 'db': None, **UNKNOWN, 'name': UNKNOWN['name'] + ': ' + str(kind)}


def _text(value, limit=240):
    if value is None:
        return ''
    if isinstance(value, (dict, list)):
        return ''
    text = ' '.join(str(value).split())
    return text if len(text) <= limit else text[:limit - 1] + '…'


def _first(item, *keys):
    for key in keys:
        value = item.get(key)
        if value not in (None, '', [], {}):
            text = _text(value)
            if text:
                return text
    return ''


def _event(item):
    event = item.get('event')
    return event if isinstance(event, dict) else {}


def _target(item):
    parts = []
    for key, label in (('ip', ''), ('domain', ''), ('path', ''), ('exe', ''), ('pid', 'PID '), ('rule_id', '')):
        value = _text(item.get(key), 120)
        if value:
            parts.append(label + value)
    return ' · '.join(dict.fromkeys(parts))


ACTION_LABELS = {
    'process.terminate': 'Süreç durdurma', 'network.connection_kill': 'Bağlantı kesme',
    'suricata.network_block': 'Ağ engeli', 'otx.indicator_block': 'OTX engeli', 'evidence': 'Kanıt',
    'record': 'Kayıt', 'correlation_request': 'Korelasyon isteği',
}


def _tone(text):
    low = text.lower()
    if any(w in low for w in ('sonlandırıldı', 'kesildi', 'doğrulandı', 'engellendi')):
        return 'ok'
    if any(w in low for w in ('başarısız', 'hata', 'uygulanmadı')):
        return 'warn'
    return 'info'


def render(kind, body, created=None):
    """One record as {'text', 'detail', 'chip', 'tone', 'time'}; secrets are masked first."""
    item = redact(body) if isinstance(body, (dict, list, str)) else body
    if not isinstance(item, dict):
        return {'text': _text(item) or 'Okunamayan kayıt', 'detail': '', 'chip': '', 'tone': 'info', 'time': created}
    stamp = item.get('timestamp') or created
    if kind == 'actions':
        label = ACTION_LABELS.get(item.get('action'), _text(item.get('action')) or 'İşlem')
        outcome = action_outcome(item) or _first(item, 'status')
        return {'text': label + (': ' + _target(item) if _target(item) else ''),
                'detail': _first(item, 'reason', 'detail', 'rule_id'), 'chip': outcome, 'tone': _tone(outcome), 'time': stamp}
    if kind == 'findings' or kind == 'safe_evidence':
        finding = item.get('finding') if isinstance(item.get('finding'), dict) else item
        event = _event(finding)
        severity = SEVERITY_LABELS.get(str(finding.get('severity')), _text(finding.get('severity')))
        return {'text': _first(finding, 'rule_name', 'title', 'summary', 'rule_id') or 'Bulgu',
                'detail': ' · '.join(x for x in (_text(finding.get('rule_id')), _first(event, 'cmd', 'exe')) if x),
                'chip': severity, 'tone': 'crit' if finding.get('severity') in ('critical', 'high') else 'warn' if severity else 'info',
                'time': stamp}
    if kind in ('events', 'normalized', 'audit_raw'):
        event = item.get('event') if kind == 'normalized' and isinstance(item.get('event'), dict) else item
        raw = event.get('raw') if isinstance(event.get('raw'), dict) else {}
        data = raw.get('data') if isinstance(raw.get('data'), dict) else raw
        ext = ((data.get('metadata') or {}).get('extensions') or {}) if isinstance(data.get('metadata'), dict) else {}
        cmd = _first(event, 'cmd') or _text(ext.get('host.cmd')) or _first(data, 'cmd')
        exe = _first(event, 'exe') or _text(ext.get('host.exe')) or _first(data, 'exe')
        what = _first(event, 'action', 'kind') or _first(data, 'action', 'kind') or 'Olay'
        return {'text': what + (': ' + exe if exe else ''), 'detail': cmd, 'chip': _first(event, 'source') or _first(data, 'source'),
                'tone': 'info', 'time': stamp}
    if kind == 'audit':
        return {'text': audit_summary(item), 'detail': _first(item, 'acct', 'exe', 'terminal'), 'chip': 'Audit', 'tone': 'info', 'time': stamp}
    if kind == 'flow_guard':
        texts = {'engine_silent': 'Kural motoru sessiz', 'flow_silent': 'Akışa olay gelmiyor',
                 'receiver_dropped': 'Kural motoru olay düşürdü', 'sender_failed': 'Olay gönderilemedi',
                 'sender_dropped': 'Toplayıcı olay düşürdü', 'engine_restarted': 'Kural motoru yeniden başlatıldı'}
        code = str(item.get('code') or '')
        failed = code == 'engine_restarted' and item.get('ok') is False
        return {'text': texts.get(code, code or 'Akış bildirimi'), 'detail': str(item.get('detail') or ''),
                'chip': 'Başarısız' if failed else ('Yapıldı' if code == 'engine_restarted' else 'Uyarı'),
                'tone': 'crit' if failed else 'warn', 'time': stamp}
    if kind == 'dns':
        return {'text': (_first(item, 'domain', 'query', 'name') or 'Alan adı') + ' soruldu',
                'detail': _first(item, 'answer', 'client', 'upstream'), 'chip': _first(item, 'decision', 'status', 'action'),
                'tone': 'warn' if 'block' in str(item.get('decision') or item.get('status') or '').lower() else 'info', 'time': stamp}
    if kind == 'alerts':
        alert = item.get('alert') if isinstance(item.get('alert'), dict) else item
        flow = ' → '.join(x for x in (_first(item, 'src_ip'), _first(item, 'dest_ip')) if x)
        return {'text': _first(alert, 'signature', 'title', 'summary') or 'Trafik uyarısı', 'detail': flow,
                'chip': _first(alert, 'category', 'severity'), 'tone': 'warn', 'time': stamp}
    if kind in ('errors', 'host_errors', 'temporary_scan_error'):
        return {'text': _first(item, 'component', 'status', 'source') or 'Hata',
                'detail': _first(item, 'error', 'detail', 'reason', 'message'), 'chip': 'Hata', 'tone': 'crit', 'time': stamp}
    text = _first(item, 'summary', 'title', 'message', 'signature', 'reason', 'status', 'action', 'event', 'type')
    return {'text': text or describe(kind)['name'], 'detail': _target(item) or _first(item, 'detail', 'error', 'cmd'),
            'chip': _first(item, 'status', 'decision', 'verdict', 'severity'), 'tone': _tone(_first(item, 'status')), 'time': stamp}


def _window_start(db, cutoff):
    """Smallest record id created at or after ``cutoff`` (ids grow with time)."""
    low, high = db.execute('SELECT COALESCE(MIN(id),0), COALESCE(MAX(id),0) FROM records').fetchone()
    if not high:
        return 0
    while low < high:
        mid = (low + high) // 2
        row = db.execute('SELECT created FROM records WHERE id>=? ORDER BY id LIMIT 1', (mid,)).fetchone()
        if row is None or row[0] >= cutoff:
            high = mid
        else:
            low = mid + 1
    return low


def overview(connections, hours=24, now=None):
    """Every kind in every database with its count in the window; catalog kinds with zero records too."""
    now = time.time() if now is None else now
    cutoff = now - max(1, min(24 * 30, float(hours))) * 3600
    seen = {}
    errors = {}
    for db_name, connect in connections:
        try:
            with connect() as db:
                start = _window_start(db, cutoff)
                for kind, count, last in db.execute(
                        'SELECT kind, COUNT(*), MAX(created) FROM records WHERE id>=? AND created>=? GROUP BY kind',
                        (start, cutoff)):
                    seen[(db_name, kind)] = (count, last)
        except Exception as exc:
            errors[db_name] = str(exc)[:200]
    kinds = []
    for (db_name, kind), (count, last) in seen.items():
        kinds.append({**describe(kind), 'db': db_name, 'count': count, 'last_at': last})
    for kind, entry in KINDS.items():
        if (entry['db'], kind) not in seen and entry['db'] not in errors:
            kinds.append({**describe(kind), 'count': 0, 'last_at': None})
    order = {name: i for i, (name, _) in enumerate(GROUPS)}
    kinds.sort(key=lambda k: (order.get(k['group'], len(order)), -k['count'], k['name']))
    return {'window_hours': hours, 'total': sum(k['count'] for k in kinds), 'kinds': kinds,
            'unknown_kinds': [k['kind'] for k in kinds if not k['known']],
            'groups': [{'id': g, 'name': n} for g, n in GROUPS], 'errors': errors,
            'data_state': 'DEGRADED' if errors else 'OK'}


def explained(db, kind, offset=0, limit=50):
    """Newest records of ``kind`` as plain sentences, each with its masked raw body."""
    import json
    offset, limit = max(0, int(offset)), max(1, min(100, int(limit)))
    total = db.execute('SELECT COUNT(*) FROM records WHERE kind=?', (str(kind),)).fetchone()[0]
    items = []
    for rid, created, body in db.execute(
            'SELECT id, created, body FROM records WHERE kind=? ORDER BY id DESC LIMIT ? OFFSET ?',
            (str(kind), limit, offset)):
        try:
            decoded = json.loads(body)
        except (TypeError, ValueError):
            decoded = body
        items.append({'id': rid, 'created': created, **render(kind, decoded, created), 'raw': redact(decoded)})
    return {**describe(kind), 'count': total, 'offset': offset, 'limit': limit, 'items': items,
            'has_more': offset + len(items) < total, 'data_state': 'OK'}
