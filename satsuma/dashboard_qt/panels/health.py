"""Sağlık: is Satsuma itself working, and one button that repairs what is safe to repair (2.2.45).

Sağlık: Satsuma'nın kendisi çalışıyor mu; güvenle onarılabileni onaran tek düğme.
"""
from . import register
from ._userpage import UserPage
from ..qt import QHBoxLayout, QVBoxLayout, QGridLayout
from ..ui import label, button, clear, Card, Pill, Dot, Empty, section
from ...status_view import timestamp

UNIT_NAMES = {
    'satsuma-core.service': 'Çekirdek', 'satsuma-teams.service': 'Kural motoru', 'satsuma-reader.service': 'Panel okuyucusu',
    'satsuma-operator.service': 'Yönetim servisi', 'satsuma-app-control.service': 'Uygulama izinleri',
    'satsuma-network.service': 'Güvenlik duvarı', 'satsuma-suricata-ips.service': 'Suricata trafik denetimi',
    'satsuma-suricata-otx-guard.service': 'OTX adres engeli', 'satsuma-udev.service': 'Aygıt izleme',
    'satsuma-rescue.service': 'Kurtarma servisi', 'satsuma-core-dns.service': 'DNS filtresi',
    'satsuma-dns-netns.service': 'DNS filtresi ağ alanı', 'satsuma-core-subnet.service': 'Alt ağ koruması',
    'satsuma-core-gateway.service': 'Ağ geçidi izleme', 'satsuma-core-sentinel.service': 'Nöbetçi',
}
STATUS = {'PASSED': ('Tüm kontroller başarılı', 'ok'), 'DEGRADED': ('Bazı kontroller başarısız', 'warn'),
          'FAILED': ('Kontrol tamamlanamadı', 'crit'), 'STALE': ('Kontrol güncel değil', 'warn'),
          'RUNNING': ('Kontrol sürüyor', 'info'), 'NOT_RUN': ('Henüz kontrol edilmedi', 'unknown'),
          'UNAVAILABLE': ('Rapor okunamadı', 'warn')}


@register
class HealthPanel(UserPage):
    PANEL_ID = 'health'
    PANEL_TITLE = 'Sağlık'
    PANEL_ORDER = 3
    PAGE_TITLE = 'Sağlık'
    PAGE_SUBTITLE = 'Satsuma’nın kendi parçalarının durumu. Sorun varsa “Sorunları onar” güvenle onarılabilen her şeyi onarır.'
    REFRESH_MS = 6000

    def build(self, content):
        top = Card(name='hero', margins=(24, 20, 24, 20))
        row = QHBoxLayout()
        text = QVBoxLayout()
        text.setSpacing(6)
        self.badge = Pill('Durum alınıyor', 'unknown')
        badge_row = QHBoxLayout()
        badge_row.addWidget(self.badge)
        badge_row.addStretch()
        text.addLayout(badge_row)
        self.headline = label('Sağlık raporu okunuyor', 'heroTitle')
        text.addWidget(self.headline)
        self.subline = label('', 'heroText')
        text.addWidget(self.subline)
        row.addLayout(text, 1)
        buttons = QVBoxLayout()
        buttons.addWidget(button('Sorunları onar', lambda: self.act({'method': 'repair', 'params': {}}), 'primary',
                                 'Bakım kitini çalıştırır: durmuş servisleri başlatır, eksik ayarları geri yükler. Hiçbir şeyi silmez.'))
        buttons.addWidget(button('Dosyaları şimdi doğrula', lambda: self.act({'method': 'boot_check', 'params': {}})))
        buttons.addStretch()
        row.addLayout(buttons)
        top.body.addLayout(row)
        content.addWidget(top)

        content.addLayout(section('Başarısız kontroller'))
        self.failures = QVBoxLayout()
        self.failures.setSpacing(8)
        content.addLayout(self.failures)

        content.addLayout(section('Özet', 'Dosya bütünlüğü, yapılandırma ve işlev kontrollerinin son sonucu.'))
        self.summary = QGridLayout()
        self.summary.setHorizontalSpacing(12)
        self.summary.setVerticalSpacing(12)
        content.addLayout(self.summary)

        content.addLayout(section('Bileşenler', 'Satsuma servislerinin anlık durumu.'))
        self.units = Card(name='listCard', margins=(18, 12, 18, 12), spacing=8)
        content.addWidget(self.units)

        content.addLayout(section('Son bakım', 'Bakım kiti her açılıştan 15 dakika sonra ve altı saatte bir kendiliğinden çalışır.'))
        self.maintenance = Card(name='listCard', margins=(18, 12, 18, 12), spacing=6)
        content.addWidget(self.maintenance)

        links = QHBoxLayout()
        for text, target in (('Servisler', 'expert:services'), ('Arka plan bileşenleri', 'expert:workers'),
                             ('Dosya bütünlüğü', 'expert:integrity'), ('Hata kayıtları', 'expert:errors')):
            links.addWidget(button(text + '  →', lambda t=target: self.open(t), 'quiet'))
        links.addStretch()
        content.addLayout(links)
        content.addStretch()

    def refresh(self):
        report, error = self.fetch('self_health')
        summary, _ = self.fetch('health_summary')
        maintenance, _ = self.fetch('maintenance_report')
        if report is None:
            if error != 'loading':
                self.headline.setText('Sağlık raporu okunamadı')
                self.subline.setText(str(error))
            return
        if not self.changed('health', (report, summary, maintenance)):
            return
        from ...self_health import CHECK_LABELS
        status = report.get('status', 'UNAVAILABLE')
        text, tone = STATUS.get(status, ('Durum bilinmiyor', 'unknown'))
        self.badge.set(text, tone)
        checks = report.get('checks') or {}
        failed = [(name, check) for name, check in checks.items() if isinstance(check, dict) and check.get('ok') is False]
        self.headline.setText('Satsuma sağlıklı çalışıyor' if status == 'PASSED' else
                              ('%d kontrol başarısız' % len(failed)) if failed else text)
        self.subline.setText('Son kontrol: ' + timestamp(report.get('updated_at')) +
                             ('' if not report.get('repairs') else ' · Kendiliğinden yapılan onarım: %d' % len(report['repairs'])))
        clear(self.failures)
        if not failed:
            self.failures.addWidget(Empty('Başarısız kontrol yok', 'Son sağlık kontrolünde her şey beklendiği gibiydi.'))
        for name, check in failed:
            card = Card(name='actionRow', margins=(16, 12, 16, 12), spacing=2)
            card.body.addWidget(label(CHECK_LABELS.get(name, name), 'rowTitle'))
            detail = check.get('error') or check.get('state') or check.get('status') or ''
            if name.startswith('services'):
                down = [UNIT_NAMES.get(unit, unit) for unit, item in (check.get('states') or {}).items() if item.get('ActiveState') != 'active']
                detail = 'Çalışmayan: ' + ', '.join(down) if down else detail
            if detail:
                card.body.addWidget(label(str(detail)[:400], 'secondary', selectable=True))
            self.failures.addWidget(card)
        clear(self.summary)
        summary = summary or {}
        for index, (key, caption) in enumerate((('files', 'Uygulama dosyaları'), ('configuration', 'Yapılandırma'), ('protection', 'Koruma işlevleri'))):
            value = summary.get(key) or 'Durum alınamıyor'
            card = Card(name='metric', margins=(16, 12, 16, 12), spacing=4)
            card.body.addWidget(label(caption, 'secondary'))
            card.body.addWidget(Pill(value, 'ok' if value == 'Sağlıklı' else 'warn' if value == 'Sorun var' else 'unknown'))
            self.summary.addWidget(card, 0, index)
            self.summary.setColumnStretch(index, 1)
        clear(self.units.body)
        states = ((checks.get('services') or {}).get('states') or {})
        if not states:
            self.units.body.addWidget(label('Servis durumu raporda yok.', 'secondary'))
        for unit, item in sorted(states.items(), key=lambda kv: UNIT_NAMES.get(kv[0], kv[0])):
            line = QHBoxLayout()
            line.setSpacing(12)
            active = item.get('ActiveState')
            line.addWidget(Dot('ok' if active == 'active' else 'warn' if active in ('activating', 'reloading') else 'crit'))
            line.addWidget(label(UNIT_NAMES.get(unit, unit), 'rowTitle'), 1)
            line.addWidget(label({'active': 'Çalışıyor', 'inactive': 'Durmuş', 'failed': 'Hata verdi', 'activating': 'Başlıyor',
                                  'unhealthy': 'Çalışıyor ama yanıt vermiyor'}.get(active, str(active)), 'secondary', wrap=False))
            unit_label = label(unit, 'mono', wrap=False)
            unit_label.setMinimumWidth(260)
            line.addWidget(unit_label)
            self.units.body.addLayout(line)
        clear(self.maintenance.body)
        maintenance = maintenance or {}
        if maintenance.get('status') in ('NOT_RUN', 'UNAVAILABLE') or not maintenance.get('rows'):
            self.maintenance.body.addWidget(label('Bakım kiti henüz rapor yazmadı.' if maintenance.get('status') == 'NOT_RUN'
                                                  else 'Bakım raporu okunamadı.', 'secondary'))
            return
        bad = [r for r in maintenance.get('rows') or [] if not r.get('ok')]
        self.maintenance.body.addWidget(label('%s · %d satır denetlendi · %d onarıldı · %d sorun' % (
            timestamp(maintenance.get('updated_at')), len(maintenance.get('rows') or []), maintenance.get('repaired') or 0, len(bad)), 'body'))
        for item in bad[:10]:
            self.maintenance.body.addWidget(label('• ' + str(item.get('name')) + ': ' + str(item.get('detail') or ''), 'secondary', selectable=True))
