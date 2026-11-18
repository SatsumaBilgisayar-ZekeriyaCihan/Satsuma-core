"""Sidebar of the panel: nine sections, every page a tab inside one of them (2.2.47).

Owner, 2026-11-18: "delete the old design and bring the old menus into the new
one, one by one", "do not add the old design again", and "antivirus scanning,
the firewall and application control each in its own area; all logs in a
separate, easily readable section". There is no expert view; every earlier
page is a tab of one section. Ctrl+1…9 open the sections.

Kenar çubuğu: dokuz bölüm; her sayfa bunlardan birinin sekmesi. Antivirüs,
güvenlik duvarı ve uygulama denetimi ayrı bölümlerdir; bütün kayıtlar
Kayıtlar bölümündedir. Uzman görünümü yoktur.
"""
from ..qt import QFrame, QVBoxLayout, QHBoxLayout, QPushButton, QLabel, QSize, pyqtSignal, POINTING
from .. import panels as registry
from ..security_widgets import icon
from ..style.theme import Colors

# (section id, title, icon, ((tab id, tab title), ...)); the first tab opens with the section.
SECTIONS = (
    ('home', 'Durum', 'home', (('home', 'Durum'),)),
    ('activity', 'Olanlar', 'activity', (
        ('activity', 'Akış'), ('findings', 'Bulgular'), ('stopped_processes', 'Durdurulan programlar'),
        ('auto_actions', 'Satsuma’nın işlemleri'), ('investigation', 'İnceleme'), ('deepseek', 'Araştırma stüdyosu'))),
    ('antivirus', 'Antivirüs', 'bug', (
        ('scanners', 'Taramalar ve karantina'), ('memory_defense', 'Bellek savunması'), ('integrity', 'Dosya bütünlüğü'))),
    ('firewall', 'Güvenlik duvarı', 'firewall', (
        ('firewall_settings', 'Ayarlar'), ('blocks', 'Engeller'), ('network_response', 'Engel geçmişi'), ('network_defense', 'Ağ bulguları'),
        ('network_devices', 'Cihazlar'), ('dns', 'DNS sorguları'), ('suricata', 'Trafik analizi'),
        ('otx', 'Tehdit istihbaratı'), ('vpn_proxy', 'VPN ve proxy'))),
    ('apps', 'Uygulama denetimi', 'app', (('apps', 'Uygulama izinleri'), ('process_approvals', 'Onay bekleyenler'))),
    ('protection', 'Koruma', 'shield', (('protection', 'Ayarlar'), ('rules', 'Kurallar'))),
    ('health', 'Sağlık', 'pulse', (
        ('health', 'Genel'), ('services', 'Servisler'), ('workers', 'Bileşenler'),
        ('host_provenance', 'Açılış, TPM ve paketler'), ('system_health', 'Ayrıntılı kontroller'))),
    ('logs', 'Kayıtlar', 'logs', (
        ('logbook', 'Tüm kayıtlar'), ('records', 'Türlere göre'), ('events', 'Olay geçmişi'),
        ('audit', 'Sistem denetimi'), ('errors', 'Hatalar'), ('database', 'Ham veritabanı'))),
    ('settings', 'Ayarlar', 'settings', (('settings', 'Genel'), ('welcome', 'Kurulum ve hesap'))),
)
# Section ids of earlier 2.2.47 builds and links stored in findings.
ALIASES = {'network': 'firewall', 'scan': 'scanners', 'quarantine': 'scanners', 'logs_all': 'logbook'}
PRIMARY = tuple((section, title, symbol) for section, title, symbol, _ in SECTIONS)
TABS = {section: tabs for section, _, _, tabs in SECTIONS}
SECTION_OF = {tab: section for section, _, _, tabs in SECTIONS for tab, _ in tabs}
TITLES = {tab: title for _, _, _, tabs in SECTIONS for tab, title in tabs}
SECTION_TITLES = {section: title for section, title, _, _ in SECTIONS}


def resolve(panel_id):
    """(section, tab) for a section id or a tab id; (None, None) when unknown."""
    panel_id = ALIASES.get(panel_id, panel_id)
    if panel_id in TABS:
        return panel_id, TABS[panel_id][0][0]
    section = SECTION_OF.get(panel_id)
    return (section, panel_id) if section else (None, None)


def title_of(panel_id):
    section, tab = resolve(panel_id)
    if section is None:
        return 'Satsuma'
    if len(TABS[section]) == 1 or tab == TABS[section][0][0]:
        return SECTION_TITLES[section]
    return SECTION_TITLES[section] + '  ·  ' + TITLES[tab]


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
        for index, (section, title, symbol) in enumerate(PRIMARY):
            item = QPushButton('  ' + title)
            item.setObjectName('navPrimary')
            item.setCheckable(True)
            item.setCursor(POINTING)
            item.setIcon(icon(symbol))
            item.setIconSize(QSize(20, 20))
            item.setMinimumHeight(44)
            item.setAccessibleName(title)
            item.setToolTip('%s  (Ctrl+%d)' % (title, index + 1))
            item.clicked.connect(lambda checked=False, s=section: self.select(s))
            layout.addWidget(item)
            self._buttons[section] = item
        layout.addStretch(1)
        self.connection = QLabel('○  Okuyucu bekleniyor')
        self.connection.setObjectName('secondary')
        layout.addWidget(self.connection)
        self._current = None
        self._known = set()

    def build(self):
        self._known = {c.PANEL_ID for c in registry.all_panels()}
        self.select('home')

    def select(self, panel_id):
        """Open a section (its first tab) or a tab by id; unknown ids are ignored."""
        section, tab = resolve(panel_id)
        if section is None or (self._known and tab not in self._known):
            return
        for key, item in self._buttons.items():
            item.setChecked(key == section)
        self._current = tab
        self.panel_selected.emit(tab)

    def current(self):
        return self._current

    def current_section(self):
        return resolve(self._current)[0] if self._current else None

    def handle_key(self, key, ctrl=False):
        if ctrl and 0x31 <= key < 0x31 + len(PRIMARY):
            self.select(PRIMARY[key - 0x31][0])
            return True
        return False

    def set_count(self, section, count):
        item = self._buttons.get(section)
        if item is not None:
            item.setText('  ' + SECTION_TITLES[section] + ('   %d' % count if count else ''))

    def set_connected(self, connected):
        self.connection.setText('●  Yerel okuyucu bağlı' if connected else '○  Okuyucu bağlantısı bekleniyor')
        self.connection.setStyleSheet('color:' + (Colors.TEXT_SECONDARY if connected else Colors.TEXT_MUTED) + ';font-size:11px;')
