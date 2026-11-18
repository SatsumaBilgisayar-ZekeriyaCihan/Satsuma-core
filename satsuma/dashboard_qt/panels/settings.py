"""Ayarlar: administrator lock, modem approval, VPN, keys, view (2.2.45).

Ayarlar: yönetici kilidi, modem onayı, VPN, anahtarlar ve görünüm.
"""
from . import register
from ._userpage import UserPage
from ..qt import QHBoxLayout, QComboBox, QCheckBox, QLineEdit, QFileDialog, QSettings
from ..ui import label, button, Card, Pill, section


def _card(content, key, title, hint, cards):
    card = Card(name='card', margins=(22, 18, 22, 18), spacing=8)
    card.body.addLayout(section(title, hint))
    content.addWidget(card)
    cards[key] = card
    return card


@register
class SettingsPanel(UserPage):
    PANEL_ID = 'settings'
    PANEL_TITLE = 'Ayarlar'
    PANEL_ORDER = 4
    PAGE_TITLE = 'Ayarlar'
    PAGE_SUBTITLE = 'Yönetici kilidi, modem, VPN ve anahtarlar.'
    REFRESH_MS = 8000

    def build(self, content):
        self.cards = {}
        card = _card(content, 'lock', 'Yönetici kilidi',
                     'Ayar değiştirmek için kilidi açın; 30 dakika açık kalır. Korumayı azaltan işlemler parolayı yine sorar.', self.cards)
        row = QHBoxLayout()
        self.lock_state = Pill('Kilitli', 'unknown')
        row.addWidget(self.lock_state)
        row.addStretch()
        self.lock_button = button('Kilidi aç', self._toggle_lock, 'primary')
        row.addWidget(self.lock_button)
        card.body.addLayout(row)
        self.admin_note = label('', 'secondary')
        card.body.addWidget(self.admin_note)

        card = _card(content, 'modem', 'Modem onayı',
                     'Satsuma, ağ geçidinin sizin modeminiz olduğunu bilirse araya giren cihazları (ARP sahteciliği gibi) ayırt eder.', self.cards)
        self.modem_state = label('', 'body')
        card.body.addWidget(self.modem_state)
        find = QHBoxLayout()
        find.addWidget(button('Modemleri bul', self._find_modems))
        find.addStretch()
        card.body.addLayout(find)
        self.modem_choices = QComboBox()
        self.modem_choices.hide()
        card.body.addWidget(self.modem_choices)
        self.modem_confirm = QCheckBox('Seçtiğim cihazın kendi modemim olduğunu doğruladım.')
        self.modem_confirm.hide()
        card.body.addWidget(self.modem_confirm)
        self.modem_approve = button('Bu modemi onayla', self._approve_modem, 'primary')
        self.modem_approve.hide()
        card.body.addWidget(self.modem_approve)
        self.modem_result = label('', 'secondary')
        card.body.addWidget(self.modem_result)
        from ..qt import QPlainTextEdit
        self.modem_tables = QPlainTextEdit()
        self.modem_tables.setReadOnly(True)
        self.modem_tables.setObjectName('technical')
        self.modem_tables.setMaximumHeight(180)
        self.modem_tables.hide()
        self.modem_tables_button = button('Teknik ayrıntılar: yönlendirme tabloları', self._toggle_tables, 'quiet')
        self.modem_tables_button.hide()
        card.body.addWidget(self.modem_tables_button)
        card.body.addWidget(self.modem_tables)
        manual = QHBoxLayout()
        self.modem_mac = QLineEdit()
        self.modem_mac.setPlaceholderText('Ya da modemin MAC adresini yazın, ör. a8:9a:93:12:34:56')
        manual.addWidget(self.modem_mac, 1)
        manual.addWidget(button('MAC ile onayla', self._manual_modem))
        card.body.addLayout(manual)
        self._fingerprint = None

        card = _card(content, 'vpn', 'VPN',
                     'WireGuard profilleri. Profil etkinken Satsuma sunucunun portunu kendisi açar; dosyadaki DNS satırı uygulanmaz.', self.cards)
        self.vpn_state = label('Profilleri görmek için kilidi açın.', 'secondary')
        card.body.addWidget(self.vpn_state)
        self.vpn_profiles = QComboBox()
        self.vpn_profiles.hide()
        card.body.addWidget(self.vpn_profiles)
        vpn = QHBoxLayout()
        vpn.addWidget(button('Bağlan', lambda: self._wireguard('up')))
        vpn.addWidget(button('Bağlantıyı kes', lambda: self._wireguard('down')))
        vpn.addWidget(button('Profili sil', lambda: self._wireguard('remove'), 'danger'))
        vpn.addStretch()
        card.body.addLayout(vpn)
        imp = QHBoxLayout()
        self.vpn_name = QLineEdit()
        self.vpn_name.setPlaceholderText('Yeni profil adı, ör. ev-vpn')
        imp.addWidget(self.vpn_name, 1)
        imp.addWidget(button('Dosyadan içe aktar…', self._import_wireguard))
        card.body.addLayout(imp)
        card.body.addWidget(button('VPN ve proxy göstergeleri  →', lambda: self.open('vpn_proxy'), 'quiet'))

        card = _card(content, 'keys', 'Anahtarlar ve araştırma',
                     'Anahtarlar panelden değil, uçbirimden root olarak girilir; panele hiçbir zaman gelmezler.', self.cards)
        card.body.addWidget(label('OTX tehdit istihbaratı:  sudo satsuma-admin set-otx-key', 'mono', selectable=True))
        card.body.addWidget(label('Ücretsiz anahtar: otx.alienvault.com → hesap → API Integration.', 'secondary', selectable=True))
        card.body.addWidget(button('Araştırma stüdyosu (DeepSeek)  →', lambda: self.open('deepseek'), 'quiet'))

        card = _card(content, 'about', 'Hakkında', '', self.cards)
        self.about = label('', 'secondary', selectable=True)
        card.body.addWidget(self.about)
        content.addStretch()

    # -- lock
    def _toggle_lock(self):
        session = self.session()
        if session is None:
            return
        if session.unlocked():
            session.lock()
        else:
            session.unlock(self, self.reload)

    # -- modem
    def _find_modems(self):
        session = self.session()
        if session:
            session.run('modem_inventory', {}, self, then=self._modems)

    def _modems(self, method, params, result):
        data = (result or {}).get('modem_inventory') or {}
        self._fingerprint = data.get('route_fingerprint')
        from ..detail_sanitizer import detail_lines
        self.modem_tables.setPlainText(detail_lines({'tables': data.get('tables', []), 'routes': data.get('routes', []),
                                                     'rules': data.get('rules', [])}))
        self.modem_tables_button.show()
        self.modem_choices.clear()
        for item in data.get('candidates') or []:
            self.modem_choices.addItem('%s · ağ geçidi %s · MAC %s' % (item.get('interface'), item.get('gateway'), item.get('gateway_mac')), item.get('id'))
        found = self.modem_choices.count() > 0
        for widget in (self.modem_choices, self.modem_confirm, self.modem_approve):
            widget.setVisible(found)
        self.modem_confirm.setChecked(False)
        if found:
            self.modem_result.setText('Listeden kendi modeminizi seçip doğruladığınızı işaretleyin.')
        else:
            reasons = '; '.join('%s: %s' % (r.get('dev'), r.get('reason')) for r in data.get('rejected') or [])
            self.modem_result.setText('Modem bulunamadı. ' + (reasons or 'Bu bilgisayarda varsayılan rota yok.'))

    def _toggle_tables(self):
        self.modem_tables.setVisible(self.modem_tables.isHidden())

    def _approve_modem(self):
        if not self.modem_confirm.isChecked():
            self.modem_result.setText('Önce seçtiğiniz cihazın kendi modeminiz olduğunu işaretleyin.')
            return
        self.act({'method': 'modem_approve', 'params': {'candidate_id': self.modem_choices.currentData(), 'confirmed': True,
                                                        'route_fingerprint': self._fingerprint}})

    def _manual_modem(self):
        mac = self.modem_mac.text().strip()
        if not mac:
            self.modem_mac.setFocus()
            return
        self.act({'method': 'modem_manual', 'params': {'mac': mac, 'confirmed': True}})

    # -- VPN
    def _wireguard(self, action):
        name = self.vpn_profiles.currentData()
        if not name:
            self.vpn_state.setText('Önce bir profil seçin (profiller kilit açıkken görünür).')
            return
        self.act({'method': 'wireguard', 'params': {'action': action, 'name': name}})

    def _import_wireguard(self):
        name = self.vpn_name.text().strip()
        if not name:
            self.vpn_name.setFocus()
            self.vpn_state.setText('Önce yeni profil için bir ad yazın.')
            return
        path, _ = QFileDialog.getOpenFileName(self, 'WireGuard yapılandırması seç', '', 'WireGuard (*.conf);;Tüm dosyalar (*)')
        if not path:
            return
        try:
            with open(path, 'rb') as handle:
                data = handle.read(16 * 1024 + 1)
            if len(data) > 16 * 1024:
                raise ValueError('Dosya 16 KB’den büyük')
            text = data.decode('utf-8')
        except (OSError, ValueError, UnicodeDecodeError) as exc:
            self.vpn_state.setText('Dosya okunamadı: ' + str(exc))
            return
        self.act({'method': 'wireguard', 'params': {'action': 'import', 'name': name, 'text': text}})

    def _operator_status(self, method, params, result):
        if not isinstance(result, dict) or result.get('error'):
            return
        wg = result.get('wireguard') or {}
        current = self.vpn_profiles.currentData()
        self.vpn_profiles.clear()
        for item in wg.get('profiles') or []:
            self.vpn_profiles.addItem(item['name'] + (' · bağlı' if item.get('active') else ''), item['name'])
        self.vpn_profiles.setVisible(self.vpn_profiles.count() > 0)
        index = self.vpn_profiles.findData(current)
        if index >= 0:
            self.vpn_profiles.setCurrentIndex(index)
        self.vpn_state.setText('; '.join(item['name'] + (' bağlı' if item.get('active') else ' bağlı değil') for item in wg.get('profiles') or [])
                               or 'İçe aktarılmış profil yok.')

    def scroll_to(self, key):
        card = self.cards.get(key)
        if card is not None:
            self.page.scroll.verticalScrollBar().setValue(card.y() - 12)

    def refresh(self):
        session = self.session()
        unlocked = bool(session and session.unlocked())
        self.lock_state.set('Kilit açık' if unlocked else 'Kilitli', 'ok' if unlocked else 'unknown')
        self.lock_button.setText('Kilitle' if unlocked else 'Kilidi aç')
        if unlocked and self.changed('unlocked', True):
            session.run('status', {}, self, then=self._operator_status)
        elif not unlocked:
            self._last.pop('unlocked', None)
        home, _ = self.fetch('home')
        health, _ = self.fetch('system_health')
        if home is not None:
            modem = next((i for i in home.get('attention') or [] if i.get('id') == 'modem'), None)
            self.modem_state.setText('Modem onaylanmamış: ' + modem['detail'] if modem else 'Modeminiz onaylı.')
            self.about.setText('Satsuma Core ' + str(home.get('version') or '') + ' · Okuyucu bağlantısı etkin')
        if health is not None:
            configured = (health.get('admin_credential') or {}).get('configured')
            self.admin_note.setText('' if configured else 'Yönetici parolası belirlenmemiş. Bir uçbirimde "sudo satsuma-kur" çalıştırın.')
