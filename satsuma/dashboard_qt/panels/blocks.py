"""Güvenlik duvarı → Engeller: block an address or a whole range, see and lift blocks, keep addresses allowed (2.2.47).

Owner's request 2026-11-18: a field to block ranges such as 192.168.0.0/16.
One field takes a single address (stored as /32) or a range; a range that
would cut this machine off (its gateway, its own address, the DNS filter) is
refused by satsuma.net_blocks with the reason. Automatic blocks (Suricata,
OTX, subnet guard) are listed with "Engeli kaldır"; the full history is the
next tab.

Güvenlik duvarı → Engeller: tek adres ya da aralık engelleme (ör. 192.168.0.0/16), engelleri
görme ve kaldırma, hep izin verilen adresler.
"""
from . import register
from ._userpage import UserPage
from ..qt import QHBoxLayout, QVBoxLayout, QLineEdit, QFrame
from ..ui import label, button, clear, Card, section
from ...status_view import timestamp


def _rule():
    line = QFrame()
    line.setObjectName('divider')
    line.setFixedHeight(1)
    return line


@register
class BlocksPanel(UserPage):
    PANEL_ID = 'blocks'
    PANEL_TITLE = 'Engeller'
    PANEL_ORDER = 30
    PAGE_TITLE = 'Engeller'
    PAGE_SUBTITLE = 'Bir adresi ya da bütün bir aralığı engelleyin; engellenenleri görün ve kaldırın.'
    REFRESH_MS = 6000

    def build(self, content):
        card = Card(name='card', margins=(22, 18, 22, 18), spacing=8)
        card.body.addLayout(section('Adres ya da aralık engelle',
                                    'Tek adres (203.0.113.7) ya da aralık (192.168.0.0/16, 10.20.0.0/24). Engellenen adreslere giden '
                                    've onlardan gelen her bağlantı düşürülür. Modeminizi, bu bilgisayarın kendi adresini ya da DNS '
                                    'filtresini içeren aralık güvenlik için reddedilir.'))
        row = QHBoxLayout()
        self.network = QLineEdit()
        self.network.setPlaceholderText('192.168.0.0/16')
        self.network.setAccessibleName('Engellenecek adres ya da aralık')
        self.network.returnPressed.connect(self._block)
        row.addWidget(self.network, 2)
        self.reason = QLineEdit()
        self.reason.setPlaceholderText('Neden (isteğe bağlı)')
        row.addWidget(self.reason, 2)
        row.addWidget(button('Engelle', self._block, 'primary'))
        card.body.addLayout(row)
        self.hint = label('', 'secondary')
        card.body.addWidget(self.hint)
        card.body.addWidget(_rule())
        card.body.addWidget(label('Elle engellediğiniz adresler ve aralıklar', 'rowTitle'))
        self.ranges = QVBoxLayout()
        self.ranges.setSpacing(4)
        card.body.addLayout(self.ranges)
        content.addWidget(card)

        card = Card(name='card', margins=(22, 18, 22, 18), spacing=8)
        card.body.addLayout(section('Otomatik engellenen adresler',
                                    'Suricata, OTX ve alt ağ koruması tarafından engellenenler. Tüm geçmiş “Engel geçmişi” sekmesinde.'))
        self.automatic = QVBoxLayout()
        self.automatic.setSpacing(4)
        card.body.addLayout(self.automatic)
        more = QHBoxLayout()
        more.addStretch()
        more.addWidget(button('Engel geçmişi  →', lambda: self.open('network_response'), 'quiet'))
        card.body.addLayout(more)
        content.addWidget(card)

        card = Card(name='card', margins=(22, 18, 22, 18), spacing=8)
        card.body.addLayout(section('Hep izin verilen adresler ve aralıklar',
                                    'Bu adresler hiçbir otomatik korumayla engellenmez (bağlantı seli kuralı, OTX, Suricata, '
                                    'alt ağ sınırı). Bir VPN sağlayıcısının aralığı için kullanın. İzin korumayı azaltır; '
                                    'parola yeniden sorulur. Aralığın içinde engellenmiş adresler hemen açılır.'))
        self.allowed = QVBoxLayout()
        self.allowed.setSpacing(4)
        card.body.addLayout(self.allowed)
        row = QHBoxLayout()
        self.allow_ip = QLineEdit()
        self.allow_ip.setPlaceholderText('Adres ya da aralık, ör. 203.0.113.7 veya 77.111.244.0/22')
        row.addWidget(self.allow_ip, 1)
        self.allow_reason = QLineEdit()
        self.allow_reason.setPlaceholderText('Not (isteğe bağlı), ör. Opera VPN')
        row.addWidget(self.allow_reason, 1)
        row.addWidget(button('Hep izin ver', self._allow, 'danger'))
        row.addWidget(button('Engeli kaldır', self._unblock_typed, 'danger'))
        card.body.addLayout(row)
        self.allow_hint = label('', 'secondary')
        card.body.addWidget(self.allow_hint)
        content.addWidget(card)
        content.addStretch()

    # -- actions
    def _block(self):
        text = self.network.text().strip()
        if not text:
            self.network.setFocus()
            self.hint.setText('Bir adres ya da aralık yazın, ör. 192.168.0.0/16.')
            return
        try:
            from ...net_blocks import parse
            parse(text)
        except ValueError as exc:
            self.hint.setText(str(exc))
            return
        self.hint.setText('')
        self.act({'method': 'block_network', 'params': {'network': text, 'reason': self.reason.text().strip()}})
        self.network.clear()
        self.reason.clear()

    def _allow(self):
        text = self.allow_ip.text().strip()
        if not text:
            self.allow_ip.setFocus()
            self.allow_hint.setText('Bir adres ya da aralık yazın, ör. 77.111.244.0/22.')
            return
        try:
            from ...net_allow import parse
            network = parse(text)
        except ValueError as exc:
            self.allow_hint.setText(str(exc))
            return
        self.allow_hint.setText('')
        if '/' not in text:
            self.act({'method': 'allow_ip', 'params': {'ip': str(network.network_address)}})
        else:
            self.act({'method': 'allow_network', 'params': {'network': str(network), 'reason': self.allow_reason.text().strip()}})
        self.allow_ip.clear()
        self.allow_reason.clear()

    def _unblock_typed(self):
        ip = self.allow_ip.text().strip()
        if ip:
            self.act({'method': 'unblock', 'params': {'ip': ip}})

    # -- data
    def refresh(self):
        data, error = self.fetch('protection')
        if data is None:
            if error != 'loading':
                self.hint.setText('Engeller okunamadı: ' + str(error))
            return
        view = (data.get('network_blocks'), data.get('blocked_ips'), data.get('allow_ips'), data.get('allow_networks'))
        if not self.changed('blocks', view):
            return
        clear(self.ranges)
        rows = data.get('network_blocks') or []
        if not rows:
            self.ranges.addWidget(label('Elle engellenmiş adres ya da aralık yok.', 'secondary'))
        for row in rows:
            line = QHBoxLayout()
            line.addWidget(label(row.get('network', ''), 'mono', wrap=False, selectable=True))
            line.addWidget(label((row.get('reason') or '') + ' · ' + timestamp(row.get('added_at')), 'secondary'), 1)
            line.addWidget(button('Engeli kaldır', lambda n=row.get('network'): self.act(
                {'method': 'unblock_network', 'params': {'network': n}}), 'danger'))
            self.ranges.addLayout(line)
        clear(self.automatic)
        blocked = data.get('blocked_ips') or []
        if not blocked:
            self.automatic.addWidget(label('Şu an otomatik engellenen adres yok.', 'secondary'))
        for item in blocked[:15]:
            line = QHBoxLayout()
            line.addWidget(label(str(item.get('ip')), 'mono', wrap=False, selectable=True))
            line.addWidget(label(str(item.get('reason') or '')[:160], 'secondary'), 1)
            line.addWidget(button('Engeli kaldır', lambda ip=item.get('ip'): self.act({'method': 'unblock', 'params': {'ip': ip}}), 'danger'))
            self.automatic.addLayout(line)
        if len(blocked) > 15:
            self.automatic.addWidget(label('ve %d adres daha (Engel geçmişi sekmesinde).' % (len(blocked) - 15), 'secondary'))
        clear(self.allowed)
        allowed = data.get('allow_ips') or []
        ranges = data.get('allow_networks') or []
        if not allowed and not ranges:
            self.allowed.addWidget(label('Hep izin verilen adres ya da aralık yok.', 'secondary'))
        for row in ranges:
            line = QHBoxLayout()
            line.addWidget(label(row.get('network', ''), 'mono', wrap=False, selectable=True))
            line.addWidget(label((row.get('reason') or 'Aralık') + ' · ' + timestamp(row.get('added_at')), 'secondary'), 1)
            line.addWidget(button('İzni kaldır', lambda n=row.get('network'): self.act(
                {'method': 'unallow_network', 'params': {'network': n}})))
            self.allowed.addLayout(line)
        for ip in allowed:
            line = QHBoxLayout()
            line.addWidget(label(ip, 'mono', wrap=False, selectable=True), 1)
            line.addWidget(button('İzni kaldır', lambda value=ip: self.act({'method': 'remove_allow_ip', 'params': {'ip': value}})))
            self.allowed.addLayout(line)
