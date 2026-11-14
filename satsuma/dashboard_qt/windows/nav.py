"""Persistent desktop sidebar with keyboard access to every panel.

"Kayıtlar" (2.2.30) is a top-level section: every record kind in the database.

Her panele klavyeyle erişim sağlayan kalıcı masaüstü kenar çubuğu. "Kayıtlar"
(2.2.30) ana bölümdür: veritabanındaki her kayıt türü.
"""
try:
    from PyQt6.QtWidgets import QFrame,QVBoxLayout,QHBoxLayout,QPushButton,QLabel,QListWidget,QListWidgetItem
    from PyQt6.QtCore import pyqtSignal,Qt,QSize
except ImportError:
    from PyQt5.QtWidgets import QFrame,QVBoxLayout,QHBoxLayout,QPushButton,QLabel,QListWidget,QListWidgetItem
    from PyQt5.QtCore import pyqtSignal,Qt,QSize
from .. import panels as registry
from ..security_widgets import icon
from ..style.theme import Colors

SECTIONS=(
    ('Genel bakış',('overview','welcome')),
    ('Kayıtlar',('records',)),
    ('Koruma',('findings','auto_actions','stopped_processes','events','investigation','rules','deepseek','scanners','memory_defense')),
    ('Ağ güvenliği',('network_response','network_devices','network_defense','dns','suricata','otx')),
    ('Sistem sağlığı',('system_health','services','workers','audit','integrity','errors','database')),
    ('Ayarlar',('admin',)),
)
TITLES={'overview':'Güvenlik merkezi','records':'Veritabanında ne var?','welcome':'Kurulum ve hesap','findings':'Tehdit bulguları',
 'scanners':'Antivirüs ve rootkit taraması','network_devices':'Ağ keşfi ve cihazlar',
 'auto_actions':'Güvenlik aksiyonları','stopped_processes':'Durdurulan işlemler','database':'Sınıflandırılmış veriler','events':'Olay geçmişi','investigation':'İnceleme',
 'deepseek':'DeepSeek araştırma stüdyosu','rules':'Güvenlik kuralları','memory_defense':'Bellek savunması','network_response':'Ağ koruması ve engeller',
 'network_defense':'Ağ etkinliği','dns':'DNS koruması','suricata':'Trafik analizi','otx':'Tehdit istihbaratı',
 'system_health':'Sistem sağlığı','services':'Servisler','workers':'Arka plan bileşenleri','audit':'Sistem denetimi',
 'integrity':'Dosya bütünlüğü','errors':'Hata kayıtları','admin':'Yönetim ve izinler'}
ROLE=Qt.ItemDataRole.UserRole if hasattr(Qt,'ItemDataRole') else Qt.UserRole

class NavigationBar(QFrame):
    panel_selected=pyqtSignal(str)
    def __init__(self,parent=None):
        super().__init__(parent);self.setObjectName('mainSidebar');self.setFixedWidth(236)
        layout=QVBoxLayout(self);layout.setContentsMargins(17,24,17,18);layout.setSpacing(6)
        brand=QHBoxLayout();glyph=QLabel();glyph.setPixmap(icon('shield',Colors.ACCENT,34).pixmap(QSize(34,34)));brand.addWidget(glyph)
        brand_text=QVBoxLayout();name=QLabel('SATSUMA');name.setStyleSheet('font-size:20px;font-weight:800;letter-spacing:2px;');brand_text.addWidget(name)
        sub=QLabel('INTERNET SECURITY');sub.setStyleSheet('font-size:9px;letter-spacing:1.7px;color:'+Colors.TEXT_MUTED+';');brand_text.addWidget(sub);brand.addLayout(brand_text);brand.addStretch();layout.addLayout(brand)
        layout.addSpacing(24)
        self._buttons=[];self._groups=[];self._remember={};self._current=None
        for i,((title,_),symbol) in enumerate(zip(SECTIONS,('home','database','shield','network','activity','settings'))):
            button=QPushButton('  '+title);button.setObjectName('navPrimary');button.setCheckable(True);button.setIcon(icon(symbol));button.setIconSize(QSize(20,20))
            button.setMinimumHeight(46);button.setAccessibleName(title);button.clicked.connect(lambda checked,idx=i:self._choose_group(idx))
            layout.addWidget(button);self._buttons.append(button)
        layout.addSpacing(24)
        self.section_label=QLabel('ÇALIŞMA ALANLARI');self.section_label.setObjectName('eyebrow');layout.addWidget(self.section_label)
        self.tools=QListWidget();self.tools.setObjectName('navTools');self.tools.setWordWrap(True)
        self.tools.currentRowChanged.connect(self._choose_tool);layout.addWidget(self.tools,1)
        self.connection=QLabel('○  Okuyucu bekleniyor');self.connection.setObjectName('secondary');layout.addWidget(self.connection)
        footer=QLabel('Satsuma Core  ·  Yerel koruma');footer.setStyleSheet('color:#8a8a8a;font-size:10px;padding-top:7px;');layout.addWidget(footer)

    def build(self):
        available={c.PANEL_ID:c for c in registry.all_panels()}
        self._groups=[[available[p] for p in ids if p in available] for _,ids in SECTIONS]
        known={c.PANEL_ID for group in self._groups for c in group}
        self._groups[3].extend(c for p,c in available.items() if p not in known and p!='tickets')
        self._choose_group(0)
    def _choose_group(self,idx):
        if idx>=len(self._groups) or not self._groups[idx]:return
        self.select(self._remember.get(idx,self._groups[idx][0].PANEL_ID))
    def _choose_tool(self,idx):
        item=self.tools.item(idx)
        if item:self.select(item.data(ROLE))
    def select(self,panel_id):
        for i,group in enumerate(self._groups):
            if not any(c.PANEL_ID==panel_id for c in group):continue
            self.tools.blockSignals(True)
            # Preserve the native list and focus while moving between its rows.
            if [self.tools.item(j).data(ROLE) for j in range(self.tools.count())]!=[c.PANEL_ID for c in group]:
                self.tools.clear()
                for cls in group:
                    item=QListWidgetItem(TITLES.get(cls.PANEL_ID,cls.PANEL_TITLE));item.setData(ROLE,cls.PANEL_ID);self.tools.addItem(item)
            self.tools.setCurrentRow(next(j for j,c in enumerate(group) if c.PANEL_ID==panel_id));self.tools.blockSignals(False)
            for j,button in enumerate(self._buttons):button.setChecked(j==i)
            self._remember[i]=panel_id;self._current=panel_id;self.panel_selected.emit(panel_id);return
    def current(self):return self._current
    def handle_key(self,key):
        if 0x31<=key<=0x35:self._choose_group(key-0x31);return True
        return False
    def set_connected(self,connected):
        self.connection.setText('●  Yerel okuyucu bağlı' if connected else '○  Okuyucu bağlantısı bekleniyor')
        self.connection.setStyleSheet('color:'+ (Colors.TEXT_SECONDARY if connected else Colors.TEXT_MUTED)+';font-size:11px;')
