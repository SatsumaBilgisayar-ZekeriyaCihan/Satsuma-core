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
    PAGE_SUBTITLE = 'Koruma katmanlarını açıp kapatın. Kilit kapalıyken değişiklik yapmak istediğinizde parola sorulur.'
    REFRESH_MS = 6000

    def build(self, content):
        self.cards = {}
        self.switches = {}
        self.lock_note = label('', 'lockNote')
        content.addWidget(self.lock_note)

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
        apply_row = QHBoxLayout()
        apply_row.addStretch()
        apply_row.addWidget(button('Seçimi uygula', self._apply_egress))
        card.body.addLayout(apply_row)
        card.body.addWidget(_rule())
        card.body.addWidget(label('Engellenen adresler', 'rowTitle'))
        self.blocked_box = QVBoxLayout()
        self.blocked_box.setSpacing(4)
        card.body.addLayout(self.blocked_box)
        ip_row = QHBoxLayout()
        self.ip = QLineEdit()
        self.ip.setPlaceholderText('IP adresi, ör. 203.0.113.7')
        ip_row.addWidget(self.ip, 1)
        ip_row.addWidget(button('Engeli kaldır', lambda: self._ip('unblock'), 'danger'))
        ip_row.addWidget(button('Hep izin ver', lambda: self._ip('allow_ip'), 'danger'))
        ip_row.addWidget(button('İzni kaldır', lambda: self._ip('remove_allow_ip')))
        card.body.addLayout(ip_row)
        self.allow_ips = label('', 'secondary')
        card.body.addWidget(self.allow_ips)

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

        card = _card(content, 'intel', 'Tehdit istihbaratı',
                     'AlienVault OTX’teki bilinen saldırgan adresleri ve alan adları.', self.cards)
        self._switch(card, 'otx_enabled', 'OTX ile denetle', 'Bağlantı kurulan adresler OTX’te sorgulanır.')
        self._switch(card, 'otx_blocker', 'OTX eşik engeli',
                     'Yeterli sayıda OTX kaynağının işaretlediği adresler engellenir.')
        card.body.addWidget(label('OTX anahtarı uçbirimden girilir: sudo satsuma-admin set-otx-key', 'secondary', selectable=True))

        card = _card(content, 'apps', 'Uygulama izinleri',
                     'Yeni bir uygulama internete ilk kez çıkmak istediğinde size sorulur; cevap verene kadar bekletilir.', self.cards)
        self._switch(card, 'application_control', 'Uygulamalar için izin sor',
                     'Kapalıyken her uygulama izin sorulmadan internete çıkabilir.')
        self.app_state = label('', 'secondary')
        card.body.addWidget(self.app_state)
        self.app_box = QVBoxLayout()
        self.app_box.setSpacing(6)
        card.body.addLayout(self.app_box)
        more = QHBoxLayout()
        more.addStretch()
        more.addWidget(button('Kayıtlı kuralları düzenle  →', lambda: self.open('expert:admin', {'section': 'apps'}), 'quiet'))
        card.body.addLayout(more)

        card = _card(content, 'files', 'Dosyalar ve karantina',
                     'Dosyalar açılırken ClamAV ile taranır; Satsuma dosyaları imzalı referansla doğrulanır.', self.cards)
        files = QHBoxLayout()
        files.addWidget(button('Şimdi tam tarama yap', lambda: self.act({'method': 'security_scan', 'params': {}})))
        files.addWidget(button('Karantina ve tarama sonuçları  →', lambda: self.open('expert:scanners'), 'quiet'))
        files.addStretch()
        card.body.addLayout(files)

        card = _card(content, 'devices', 'Cihazlar', 'Ağdaki cihazlar, USB aygıtları ve VPN bağlantıları.', self.cards)
        devices = QHBoxLayout()
        devices.addWidget(button('Ağdaki cihazlar  →', lambda: self.open('expert:network_devices'), 'quiet'))
        devices.addWidget(button('VPN ve proxy  →', lambda: self.open('settings:vpn'), 'quiet'))
        devices.addStretch()
        card.body.addLayout(devices)
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
    def _ip(self, method):
        ip = self.ip.text().strip()
        if not ip:
            self.ip.setFocus()
            return
        self.act({'method': method, 'params': {'ip': ip}})

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
        selection = {'addons': addons, 'custom': (self._last.get('protection') or {}).get('egress', {}).get('selection', {}).get('custom', {'tcp': [], 'udp': []})}
        self.act({'method': 'egress_profile', 'params': {'action': 'set', 'selection': selection}})

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
            self.switches[key].set(data.get(key))
        self.switches['interactive_process_test_mode'].set(data.get('test_mode'))
        app = data.get('app') or {}
        status = app.get('status')
        self.switches['application_control'].set(True if status == 'ACTIVE' else False if status in ('DISABLED', 'HANDED_TO_OPENSNITCH') else None,
                                                 'OpenSnitch yönetiyor' if status == 'HANDED_TO_OPENSNITCH' else None)
        self.app_state.setText('%d kayıtlı kural · %d uygulama karar bekliyor' % (app.get('rule_count') or 0, len(app.get('pending') or [])))
        self._render_apps(app.get('pending') or [])
        self._render_approvals(data.get('approvals') or {})
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
        blocked = data.get('blocked_ips') or []
        self._render_list(self.blocked_box, [b.get('ip') for b in blocked[:12] if b.get('ip')], 'Şu an engellenen adres yok.',
                          lambda ip: {'method': 'unblock', 'params': {'ip': ip}}, 'Engeli kaldır',
                          notes={b.get('ip'): str(b.get('reason') or '') for b in blocked})
        if len(blocked) > 12:
            self.blocked_box.addWidget(button('Tüm engellenen adresler (%d)  →' % len(blocked), lambda: self.open('expert:network_response'), 'quiet'))
        allow = data.get('allow_ips') or []
        self.allow_ips.setText('Hep izin verilen adresler: ' + (', '.join(allow) if allow else 'yok'))
        self._render_egress(data.get('egress') or {})

    def _render_list(self, box, values, empty, make_action, verb, notes=None):
        clear(box)
        if not values:
            box.addWidget(label(empty, 'secondary'))
            return
        for value in values:
            line = QHBoxLayout()
            line.addWidget(label(value, 'mono', selectable=True))
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

    def _render_apps(self, pending):
        clear(self.app_box)
        for request in pending[:8]:
            app = request.get('application') or {}
            line = QHBoxLayout()
            text = QVBoxLayout()
            text.setSpacing(1)
            text.addWidget(label(str(app.get('executable') or 'Bilinmeyen uygulama').rsplit('/', 1)[-1] + ' internete çıkmak istiyor', 'rowTitle'))
            text.addWidget(label(str(app.get('executable') or '') + ' → ' + str(request.get('destination') or ''), 'mono'))
            line.addLayout(text, 1)
            for verb, decision, kind in (('İzin ver', 'allow', 'primary'), ('Engelle', 'deny', None)):
                line.addWidget(button(verb, lambda d=decision, r=request: self.act(
                    {'method': 'application_control', 'params': {'action': 'decision', 'decision': d,
                                                                'duration': 'application', 'request_id': r.get('id')}}), kind))
            self.app_box.addLayout(line)

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
            self._last.pop('protection', None)
            self.refresh()
