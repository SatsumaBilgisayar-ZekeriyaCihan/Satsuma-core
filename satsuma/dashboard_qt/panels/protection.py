"""Koruma: every protection switch with one sentence on what it changes (2.2.45).

Until 2.2.44 these were buttons on the "Yönetim" page behind a separate login.
Each switch now shows its real state while locked; changing it opens the lock,
and turning protection down asks the password again (audit K7).

Koruma: her anahtar ve neyi değiştirdiği. Kilitliyken de gerçek durum görünür;
değiştirmek kilidi açar, korumayı azaltmak parolayı yeniden sorar.
"""
from . import register
from ._userpage import UserPage
from ..qt import QHBoxLayout, QVBoxLayout, QLineEdit, QCheckBox, QFrame
from ..ui import label, button, clear, Card, SettingRow, section
from ...status_view import timestamp


def otx_dns_text(info):
    """OTX's share of the DNS filter: blocked names, checked names, last error (from the management page)."""
    if not isinstance(info, dict):
        return ''
    text = ' · OTX: ' + str(info.get('blocked', 0)) + ' alan adı engelli (' + str(info.get('checked', 0)) + ' denetlendi)'
    if info.get('status') == 'disabled':
        text += ', sorgular kapalı'
    elif info.get('status') == 'key_missing':
        text += ', API anahtarı yok'
    elif info.get('status') == 'error' and info.get('error'):
        text += ', hata: ' + str(info['error'])[:160]
    return text


def _card(content, key, title, hint, cards):
    card = Card(name='card', margins=(22, 18, 22, 18), spacing=4)
    card.body.addLayout(section(title, hint))
    content.addWidget(card)
    cards[key] = card
    return card


def _rule():
    line = QFrame()
    line.setObjectName('divider')
    line.setFixedHeight(1)
    return line


@register
class ProtectionPanel(UserPage):
    PANEL_ID = 'protection'
    PANEL_TITLE = 'Koruma'
    PANEL_ORDER = 2
    PAGE_TITLE = 'Koruma'
    PAGE_SUBTITLE = ('Zararlı programların durdurulması ve dosya taraması. Güvenlik duvarı, uygulama izinleri ve '
                     'antivirüs kendi bölümlerindedir. Kilit kapalıyken bir ayarı değiştirdiğinizde parola sorulur.')
    REFRESH_MS = 6000
    # 2.2.47: each area in its own section (owner request 2026-11-18).
    CARDS = ('process', 'files')

    def build(self, content):
        self.cards = {}
        self.switches = {}
        self.lock_note = label('', 'lockNote')
        content.addWidget(self.lock_note)

        if 'process' in self.CARDS:
            card = _card(content, 'process', 'Programlar ve bellek',
                         'Bellekte saldırı izi taşıyan ya da şüpheli yerden çalışan programlar.', self.cards)
            self._switch(card, 'enforcement', 'Zararlı programı otomatik durdur',
                         'Kapalıyken programlar yalnızca bildirilir. Satsuma, TeamViewer, AnyDesk, masaüstü ve paket yöneticisi hiç durdurulmaz.')
            self._switch(card, 'interactive_process_test_mode', 'Durdurmadan önce bana sor',
                         'Açıkken hiçbir program otomatik durdurulmaz; her biri sizin onayınızı bekler (test modu). '
                         'Kapalıyken yukarıdaki ayar geçerlidir.')
            self.approvals_box = QVBoxLayout()
            self.approvals_box.setSpacing(6)
            card.body.addLayout(self.approvals_box)

        if 'network' in self.CARDS:
            card = _card(content, 'network', 'Ağ', 'Bu bilgisayara gelen ve buradan giden bağlantılar. Tüm trafik Suricata denetiminden geçer.', self.cards)
            self._switch(card, 'auto_network', 'Saldırgan adresleri otomatik engelle',
                         'Taze ve en az iki bağımsız kaynakla doğrulanmış bulgularda adres engellenir. İzinli adreslere dokunulmaz.')
            self._switch(card, 'lan_access', 'Yerel ağdaki cihazlara erişim',
                         'Kapalıyken evdeki/ofisteki diğer cihazlarla bağlantı kesilir; internet ve DNS açık kalır.')
            self._switch(card, 'subnet_protection', 'Alt ağ koruması',
                         'Aynı alt ağda 10 farklı adres engellenirse alt ağın tamamı engellenir.')
            card.body.addWidget(_rule())
            card.body.addWidget(label('İnternete giden trafik', 'rowTitle'))
            self.egress_note = label('', 'secondary')
            card.body.addWidget(self.egress_note)
            self.egress_boxes = {}
            self.egress_layout = QVBoxLayout()
            self.egress_layout.setSpacing(2)
            card.body.addLayout(self.egress_layout)
            ports = QHBoxLayout()
            self.egress_tcp = QLineEdit()
            self.egress_tcp.setPlaceholderText('Özel TCP portları, ör. 8443, 9000')
            ports.addWidget(self.egress_tcp, 1)
            self.egress_udp = QLineEdit()
            self.egress_udp.setPlaceholderText('Özel UDP portları')
            ports.addWidget(self.egress_udp, 1)
            ports.addWidget(button('Seçimi uygula', self._apply_egress))
            card.body.addLayout(ports)
            self.egress_error = label('', 'errorText')
            card.body.addWidget(self.egress_error)
            card.body.addWidget(_rule())
            links = QHBoxLayout()
            links.addWidget(label('Adres ya da aralık engellemek, engelleri kaldırmak ve hep izin verilen adresler:', 'secondary'), 1)
            links.addWidget(button('Engeller sekmesi  →', lambda: self.open('blocks'), 'quiet'))
            card.body.addLayout(links)

        if 'dns' in self.CARDS:
            card = _card(content, 'dns', 'DNS filtresi',
                         'Zararlı alan adlarını adres çözülmeden engeller. Bütün sorgular Satsuma’nın kendi ağ alanındaki filtreden ve OpenDNS’ten geçer.',
                         self.cards)
            self._switch(card, 'dns_filter', 'Zararlı alan adlarını engelle',
                         'Kapalıyken bilinen zararlı alan adları da çözülür.')
            self.dns_state = label('', 'secondary')
            card.body.addWidget(self.dns_state)
            card.body.addWidget(_rule())
            card.body.addWidget(label('İzin verdiğiniz alan adları', 'rowTitle'))
            self.domains_box = QVBoxLayout()
            self.domains_box.setSpacing(4)
            card.body.addLayout(self.domains_box)
            domain_row = QHBoxLayout()
            self.domain = QLineEdit()
            self.domain.setPlaceholderText('Yanlışlıkla engellenen alan adı, ör. ornek.com')
            domain_row.addWidget(self.domain, 1)
            domain_row.addWidget(button('İzin ver', self._allow_domain, 'danger'))
            card.body.addLayout(domain_row)
            card.body.addWidget(_rule())
            card.body.addWidget(label('Kendi engel listeleriniz', 'rowTitle'))
            card.body.addWidget(label('Satsuma kendiliğinden liste indirmez. Eklediğiniz liste yalnızca siz eklediğinizde ya da '
                                      'güncellediğinizde bir kez indirilir, doğrulanır ve imzalı saklanır.', 'secondary'))
            self.lists_box = QVBoxLayout()
            self.lists_box.setSpacing(4)
            card.body.addLayout(self.lists_box)
            list_row = QHBoxLayout()
            self.list_url = QLineEdit()
            self.list_url.setPlaceholderText('https://… (alan adı, hosts ya da adblock biçimi)')
            list_row.addWidget(self.list_url, 1)
            list_row.addWidget(button('Listeyi ekle', self._add_list))
            card.body.addLayout(list_row)

        if 'intel' in self.CARDS:
            card = _card(content, 'intel', 'Tehdit istihbaratı',
                         'AlienVault OTX’teki bilinen saldırgan adresleri ve alan adları.', self.cards)
            self._switch(card, 'otx_enabled', 'OTX ile denetle', 'Bağlantı kurulan adresler OTX’te sorgulanır.')
            self._switch(card, 'otx_blocker', 'OTX eşik engeli',
                         'Yeterli sayıda OTX kaynağının işaretlediği adresler engellenir.')
            self.otx_dns = label('', 'secondary')
            card.body.addWidget(self.otx_dns)
            card.body.addWidget(label('OTX anahtarı uçbirimden girilir: sudo satsuma-admin set-otx-key', 'secondary', selectable=True))

        if 'files' in self.CARDS:
            card = _card(content, 'files', 'Dosyalar ve karantina',
                         'Dosyalar açılırken ClamAV ile taranır; Satsuma dosyaları imzalı referansla doğrulanır.', self.cards)
            files = QHBoxLayout()
            files.addWidget(button('Şimdi tam tarama yap', lambda: self.act({'method': 'security_scan', 'params': {}})))
            files.addWidget(button('Antivirüs → taramalar ve karantina  →', lambda: self.open('scanners'), 'quiet'))
            files.addStretch()
            card.body.addLayout(files)

        content.addStretch()
        self.pending_approvals = []

    def _switch(self, card, method, title, explanation):
        row = SettingRow(title, explanation)
        row.toggled.connect(lambda value, m=method, r=row: self._toggle(m, value, r))
        card.body.addWidget(row)
        self.switches[method] = row
        return row

    def _toggle(self, method, value, row):
        previous = not value
        row.set(previous)      # shown as it is until Satsuma confirms the change
        if method == 'application_control':
            action = {'method': method, 'params': {'action': 'enable' if value else 'disable'}}
        else:
            action = {'method': method, 'params': {'enabled': value}}
        self.act(action)

    def scroll_to(self, key):
        card = self.cards.get(key)
        if card is not None:
            self.page.scroll.ensureWidgetVisible(card, 0, 0)
            self.page.scroll.verticalScrollBar().setValue(card.y() - 12)

    # -- actions
    def _allow_domain(self):
        name = self.domain.text().strip()
        if name:
            self.act({'method': 'allow_domain', 'params': {'domain': name}})

    def _add_list(self):
        url = self.list_url.text().strip()
        if url:
            self.act({'method': 'custom_list_update', 'params': {'url': url}})

    def _apply_egress(self):
        addons = [key for key, box in self.egress_boxes.items() if box.isChecked()]
        try:
            custom = {proto: [int(x) for x in field.text().replace(' ', '').split(',') if x]
                      for proto, field in (('tcp', self.egress_tcp), ('udp', self.egress_udp))}
            if any(not 1 <= port <= 65535 for ports in custom.values() for port in ports):
                raise ValueError
        except ValueError:
            self.egress_error.setText('Özel portlar virgülle ayrılmış 1–65535 arası sayılar olmalı.')
            return
        self.egress_error.setText('')
        self.act({'method': 'egress_profile', 'params': {'action': 'set', 'selection': {'addons': addons, 'custom': custom}}})

    # -- data
    def refresh(self):
        session = self.session()
        unlocked = bool(session and session.unlocked())
        self.lock_note.setText('Kilit açık: değişiklikler hemen uygulanır.' if unlocked else
                               'Kilitli: durumları görebilirsiniz; bir ayarı değiştirdiğinizde yönetici parolası sorulur.')
        data, error = self.fetch('protection')
        if data is None:
            if error != 'loading':
                self.lock_note.setText('Koruma ayarları okunamadı: ' + str(error))
            return
        if unlocked and self.changed('unlocked', True):
            session.run('status', {}, self, then=self._operator_status)
        elif not unlocked:
            self._last.pop('unlocked', None)
            self.pending_approvals = []
        if not self.changed('protection', data):
            return
        for key in ('enforcement', 'auto_network', 'lan_access', 'subnet_protection', 'otx_enabled', 'otx_blocker', 'dns_filter'):
            if key in self.switches:
                self.switches[key].set(data.get(key))
        if 'process' in self.CARDS:
            self.switches['interactive_process_test_mode'].set(data.get('test_mode'))
            self._render_approvals(data.get('approvals') or {})
        if 'network' in self.CARDS:
            self._render_egress(data.get('egress') or {})
        if 'dns' in self.CARDS:
            self._render_dns(data)

    def _render_dns(self, data):
        health = data.get('dns_health') or {}
        if data.get('dns_filter'):
            self.dns_state.setText(('Filtre çalışıyor' if health.get('ok') else 'Filtre yanıt vermiyor: ' + str(health.get('error') or health.get('status') or 'bilinmiyor'))
                                   + (' · %s alan adı engelli' % health['blocked_count'] if health.get('blocked_count') is not None else '')
                                   + ' · Son kontrol: ' + timestamp(health.get('updated_at')))
        else:
            self.dns_state.setText('Filtre kapalı.')
        self._render_list(self.domains_box, data.get('allowed_domains') or [], 'Henüz izin verdiğiniz alan adı yok.',
                          lambda name: {'method': 'remove_allow_domain', 'params': {'domain': name}}, 'İzni kaldır')
        lists = (data.get('custom_lists') or {}).get('sources') or []
        clear(self.lists_box)
        if not lists:
            self.lists_box.addWidget(label('Eklenmiş liste yok.', 'secondary'))
        for item in lists:
            line = QHBoxLayout()
            line.addWidget(label(str(item.get('url')), 'mono', selectable=True), 1)
            line.addWidget(label('%s alan adı · %s' % (item.get('count', '?'), timestamp(item.get('updated_at'))), 'secondary', wrap=False))
            line.addWidget(button('Güncelle', lambda u=item.get('url'): self.act({'method': 'custom_list_update', 'params': {'url': u}})))
            line.addWidget(button('Kaldır', lambda u=item.get('url'): self.act({'method': 'custom_list_remove', 'params': {'url': u}})))
            self.lists_box.addLayout(line)

    def _render_list(self, box, values, empty, make_action, verb, notes=None):
        clear(box)
        if not values:
            box.addWidget(label(empty, 'secondary'))
            return
        for value in values:
            line = QHBoxLayout()
            line.addWidget(label(value, 'mono', wrap=False, selectable=True))
            note = (notes or {}).get(value)
            line.addWidget(label(note or '', 'secondary'), 1)
            line.addWidget(button(verb, lambda v=value: self.act(make_action(v)), 'danger' if verb != 'Engeli kaldır' else 'danger'))
            box.addLayout(line)

    def _render_egress(self, egress):
        if egress.get('error'):
            self.egress_note.setText('İnternet trafiği ayarı okunamadı: ' + egress['error'])
            return
        self.egress_note.setText((egress.get('base') or '') + ' ' + (egress.get('incoming') or ''))
        clear(self.egress_layout)
        self.egress_boxes = {}
        for addon in egress.get('addons') or []:
            box = QCheckBox(addon['title'])
            box.setToolTip(addon.get('explain') or '')
            box.setChecked(bool(addon.get('enabled')))
            self.egress_boxes[addon['id']] = box
            self.egress_layout.addWidget(box)
            hint = label(addon.get('explain') or '', 'hint')
            self.egress_layout.addWidget(hint)
        custom = (egress.get('selection') or {}).get('custom') or {}
        for proto, field in (('tcp', self.egress_tcp), ('udp', self.egress_udp)):
            if not field.hasFocus():
                field.setText(', '.join(map(str, custom.get(proto) or [])))

    def _render_approvals(self, notice):
        clear(self.approvals_box)
        count = notice.get('pending_count') or 0
        if not notice.get('enabled') or not count:
            return
        self.approvals_box.addWidget(label('%d program onayınızı bekliyor' % count, 'rowTitle'))
        if not self.pending_approvals:
            self.approvals_box.addWidget(label('Programları ve kararları görmek için kilidi açın.', 'secondary'))
            self.approvals_box.addWidget(button('Kilidi aç', lambda: self.session() and self.session().unlock(self, self.reload), 'primary'))
            return
        for request in self.pending_approvals:
            line = QHBoxLayout()
            line.addWidget(label('%s · PID %s · %s' % (request.get('rule_id') or 'Kural', request.get('pid'), timestamp(request.get('created_at'))), 'mono'), 1)
            for verb, decision, kind in (('Durdur', 'apply', 'primary'), ('Çalışmaya devam etsin', 'reject', None)):
                line.addWidget(button(verb, lambda d=decision, r=request: self.act(
                    {'method': 'process_approval_decide', 'params': {'request_id': r.get('id'), 'decision': d}}), kind))
            self.approvals_box.addLayout(line)

    def _operator_status(self, method, params, result):
        if isinstance(result, dict) and not result.get('error'):
            self.pending_approvals = result.get('process_approval_pending') or []
            if hasattr(self, 'otx_dns'):
                self.otx_dns.setText(otx_dns_text(result.get('otx_dns')).lstrip(' ·'))
            self._last.pop('protection', None)
            self.refresh()


@register
class FirewallSettingsPanel(ProtectionPanel):
    """Güvenlik duvarı → Ayarlar: inbound/outbound rules, DNS filter and threat intelligence (2.2.47)."""
    PANEL_ID = 'firewall_settings'
    PANEL_TITLE = 'Güvenlik duvarı'
    PANEL_ORDER = 3
    PAGE_TITLE = 'Güvenlik duvarı'
    PAGE_SUBTITLE = ('Gelen ve giden bağlantılar, internete çıkan portlar, DNS filtresi ve tehdit istihbaratı. '
                     'Adres ve aralık engelleri Engeller sekmesindedir.')
    CARDS = ('network', 'dns', 'intel')
