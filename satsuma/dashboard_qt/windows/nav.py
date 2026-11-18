"""Sidebar of the 2.2.45 panel: five user sections and an optional expert view.

Owner's decision 2026-11-18 ("Baştan tasarım", "kullanıcı tabanlı"): Durum,
Olanlar, Koruma, Sağlık and Ayarlar are the panel. Every technical table of
earlier versions stays reachable under "Uzman görünümü", which can be hidden.
Ctrl+1…5 open the sections.

2.2.45 kenar çubuğu: beş kullanıcı bölümü ve gizlenebilir uzman görünümü.
Önceki sürümlerin her teknik tablosu "Uzman görünümü" altında durur.
"""
from ..qt import (QFrame, QVBoxLayout, QHBoxLayout, QPushButton, QLabel, QListWidget, QListWidgetItem, QSize, QSettings,
                  pyqtSignal, USER_ROLE, NO_ITEM_FLAGS, POINTING)
from .. import panels as registry
from ..security_widgets import icon
from ..style.theme import Colors

PRIMARY = (('home', 'Durum', 'home'), ('activity', 'Olanlar', 'activity'), ('protection', 'Koruma', 'shield'),
           ('health', 'Sağlık', 'pulse'), ('settings', 'Ayarlar', 'settings'))
SECTIONS = (
    ('Kayıtlar', ('records', 'events', 'database')),
    ('Koruma ayrıntıları', ('findings', 'auto_actions', 'stopped_processes', 'process_approvals', 'investigation', 'rules',
                            'memory_defense', 'scanners', 'host_provenance', 'deepseek')),
    ('Ağ ayrıntıları', ('network_response', 'network_devices', 'network_defense', 'dns', 'suricata', 'otx', 'vpn_proxy')),
    ('Sistem ayrıntıları', ('system_health', 'services', 'workers', 'integrity', 'audit', 'errors')),
    ('Önceki görünüm', ('overview', 'welcome', 'admin')),
)
TITLES = {
    'home': 'Durum', 'activity': 'Olanlar', 'protection': 'Koruma', 'health': 'Sağlık', 'settings': 'Ayarlar',
    'overview': 'Eski güvenlik merkezi', 'records': 'Veritabanında ne var?', 'welcome': 'Kurulum ve hesap',
    'findings': 'Tehdit bulguları', 'scanners': 'Antivirüs ve rootkit taraması', 'network_devices': 'Ağ keşfi ve cihazlar',
    'auto_actions': 'Güvenlik aksiyonları', 'stopped_processes': 'Durdurulan işlemler', 'database': 'Sınıflandırılmış veriler',
    'events': 'Olay geçmişi', 'investigation': 'İnceleme', 'deepseek': 'DeepSeek araştırma stüdyosu', 'rules': 'Güvenlik kuralları',
    'memory_defense': 'Bellek savunması', 'network_response': 'Ağ koruması ve engeller', 'network_defense': 'Ağ etkinliği',
    'dns': 'DNS sorguları', 'suricata': 'Trafik analizi (Suricata)', 'otx': 'Tehdit istihbaratı (OTX)', 'vpn_proxy': 'VPN / proxy göstergeleri',
    'system_health': 'Ayrıntılı sistem sağlığı', 'services': 'Servisler', 'workers': 'Arka plan bileşenleri', 'audit': 'Sistem denetimi',
    'integrity': 'Dosya bütünlüğü', 'errors': 'Hata kayıtları', 'admin': 'Gelişmiş yönetim', 'process_approvals': 'Test modu onayları',
    'host_provenance': 'Paket kökeni ve risk',
}
SETTINGS = ('SatsumaBilgisayar', 'Satsuma Internet Security')


class NavigationBar(QFrame):
    panel_selected = pyqtSignal(str)

    def __init__(self, parent=None):
        super().__init__(parent)
        self.setObjectName('mainSidebar')
        self.setFixedWidth(236)
        layout = QVBoxLayout(self)
        layout.setContentsMargins(16, 22, 16, 16)
        layout.setSpacing(4)
        brand = QHBoxLayout()
        glyph = QLabel()
        glyph.setPixmap(icon('shield', Colors.ACCENT, 30).pixmap(QSize(30, 30)))
        brand.addWidget(glyph)
        names = QVBoxLayout()
        names.setSpacing(0)
        name = QLabel('SATSUMA')
        name.setObjectName('brandName')
        names.addWidget(name)
        sub = QLabel('INTERNET SECURITY')
        sub.setObjectName('brandSub')
        names.addWidget(sub)
        brand.addLayout(names)
        brand.addStretch()
        layout.addLayout(brand)
        layout.addSpacing(22)
        self._buttons = {}
        for index, (panel_id, title, symbol) in enumerate(PRIMARY):
            item = QPushButton('  ' + title)
            item.setObjectName('navPrimary')
            item.setCheckable(True)
            item.setCursor(POINTING)
            item.setIcon(icon(symbol))
            item.setIconSize(QSize(20, 20))
            item.setMinimumHeight(44)
            item.setAccessibleName(title)
            item.setToolTip('%s  (Ctrl+%d)' % (title, index + 1))
            item.clicked.connect(lambda checked=False, p=panel_id: self.select(p))
            layout.addWidget(item)
            self._buttons[panel_id] = item
        self.badge = {}
        layout.addSpacing(16)
        self.expert_button = QPushButton('  Uzman görünümü')
        self.expert_button.setObjectName('navExpert')
        self.expert_button.setCheckable(True)
        self.expert_button.setCursor(POINTING)
        self.expert_button.setIcon(icon('code'))
        self.expert_button.setIconSize(QSize(18, 18))
        self.expert_button.setToolTip('Teknik tablolar: bulgular, Suricata, DNS sorguları, denetim, kurallar…')
        self.expert_button.clicked.connect(lambda checked: self.set_expert(checked, remember=True))
        layout.addWidget(self.expert_button)
        self.tools = QListWidget()
        self.tools.setObjectName('navTools')
        self.tools.setWordWrap(True)
        self.tools.currentItemChanged.connect(self._tool_changed)
        layout.addWidget(self.tools, 1)
        self.spacer = QLabel('')
        layout.addWidget(self.spacer, 1)
        self.connection = QLabel('○  Okuyucu bekleniyor')
        self.connection.setObjectName('secondary')
        layout.addWidget(self.connection)
        self._current = None
        self._known = set()
        self._expert = False

    # -- construction
    def build(self):
        available = {c.PANEL_ID: c for c in registry.all_panels()}
        self._known = set(available)
        self.tools.blockSignals(True)
        self.tools.clear()
        listed = {p for p, _, _ in PRIMARY}
        groups = [(title, [p for p in ids if p in available]) for title, ids in SECTIONS]
        listed.update(p for _, ids in groups for p in ids)
        rest = sorted(p for p in available if p not in listed and p != 'tickets')
        if rest:
            groups.append(('Diğer', rest))
        for title, ids in groups:
            if not ids:
                continue
            header = QListWidgetItem(title.upper())
            header.setFlags(NO_ITEM_FLAGS)
            header.setData(USER_ROLE, None)
            self.tools.addItem(header)
            for panel_id in ids:
                item = QListWidgetItem(TITLES.get(panel_id, getattr(available[panel_id], 'PANEL_TITLE', panel_id)))
                item.setData(USER_ROLE, panel_id)
                self.tools.addItem(item)
        self.tools.blockSignals(False)
        for panel_id, item in self._buttons.items():
            item.setVisible(panel_id in available)
        self.set_expert(bool(QSettings(*SETTINGS).value('expert_view', False, type=bool)))
        self.select('home' if 'home' in available else next(iter(available), None))

    def expert_ids(self):
        return [self.tools.item(i).data(USER_ROLE) for i in range(self.tools.count()) if self.tools.item(i).data(USER_ROLE)]

    def expert_visible(self):
        return self._expert

    def set_expert(self, visible, remember=False):
        self._expert = bool(visible)
        self.expert_button.setChecked(self._expert)
        self.tools.setVisible(self._expert)
        self.spacer.setVisible(not self._expert)
        if remember:
            QSettings(*SETTINGS).setValue('expert_view', self._expert)
        if not self._expert and self._current in self.expert_ids():
            self.select('home')

    # -- selection
    def _tool_changed(self, item, previous=None):
        panel_id = item.data(USER_ROLE) if item else None
        if panel_id and panel_id != self._current:
            self.select(panel_id)

    def select(self, panel_id):
        if not panel_id or (self._known and panel_id not in self._known):
            return
        expert = panel_id not in self._buttons
        if expert and not self._expert:
            self.set_expert(True)
        for key, item in self._buttons.items():
            item.setChecked(key == panel_id)
        self.tools.blockSignals(True)
        if expert:
            for index in range(self.tools.count()):
                if self.tools.item(index).data(USER_ROLE) == panel_id:
                    self.tools.setCurrentRow(index)
                    break
        else:
            self.tools.setCurrentRow(-1)
            self.tools.clearSelection()
        self.tools.blockSignals(False)
        self._current = panel_id
        self.panel_selected.emit(panel_id)

    def current(self):
        return self._current

    def handle_key(self, key, ctrl=False):
        if ctrl and 0x31 <= key < 0x31 + len(PRIMARY):
            self.select(PRIMARY[key - 0x31][0])
            return True
        return False

    def set_count(self, panel_id, count):
        item = self._buttons.get(panel_id)
        if item is not None:
            title = next(t for p, t, _ in PRIMARY if p == panel_id)
            item.setText('  ' + title + ('   %d' % count if count else ''))

    def set_connected(self, connected):
        self.connection.setText('●  Yerel okuyucu bağlı' if connected else '○  Okuyucu bağlantısı bekleniyor')
        self.connection.setStyleSheet('color:' + (Colors.TEXT_SECONDARY if connected else Colors.TEXT_MUTED) + ';font-size:11px;')
