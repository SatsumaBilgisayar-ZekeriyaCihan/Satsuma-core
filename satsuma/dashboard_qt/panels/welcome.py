"""Opening screen with observed readiness and explicit desktop setup steps."""
import subprocess
import getpass
import shlex
import time
try:
    from PyQt6.QtWidgets import QLabel, QPushButton, QHBoxLayout, QScrollArea, QWidget, QVBoxLayout
    from PyQt6.QtCore import Qt
except ImportError:
    from PyQt5.QtWidgets import QLabel, QPushButton, QHBoxLayout, QScrollArea, QWidget, QVBoxLayout
    from PyQt5.QtCore import Qt
from .base import BasePanel
from . import register
from ...critical_guardian import failure_text


@register
class WelcomePanel(BasePanel):
    PANEL_ID = 'welcome'
    PANEL_TITLE = 'Kurulum ve hesap'
    PANEL_ORDER = 0
    REFRESH_MS = 3000

    def _build(self):
        scroll = QScrollArea()
        scroll.setWidgetResizable(True)
        self._layout.setContentsMargins(0, 0, 0, 0)
        body = QWidget()
        body.setObjectName('transparent')
        content = QVBoxLayout(body)
        content.setSpacing(14)
        content.setContentsMargins(32, 24, 32, 24)
        scroll.setWidget(body)
        self._layout.addWidget(scroll)
        content.addWidget(self.make_title('Kurulum ve hesap'))
        intro = QLabel('Kurulumun durumu, yönetici parolası ve modem. Ayarları değiştirmek için sağ üstteki kilidi açın.')
        intro.setObjectName('pageSubtitle')
        intro.setWordWrap(True)
        content.addWidget(intro)
        self.readiness = QLabel('Servislerden veri bekleniyor; koruma henüz doğrulanmadı.')
        self.readiness.setWordWrap(True)
        content.addWidget(self.readiness)
        self.account = QLabel('Yönetici hesabı durumu bekleniyor.')
        self.account.setWordWrap(True)
        content.addWidget(self.account)
        steps = QLabel('Masaüstü kaydı kurulumda otomatik yapılır; gerekirse ilk açılışta sistem yönetici onayı istenir.\n'
                       'İlk Satsuma yönetici parolanızı aşağıdaki düğmeyle oluşturun.\n'
                       'Paneli normal kullanıcıyla açın. Mevcut parolayı değiştirmek için yönetici terminalinde satsuma-admin set-password kullanabilirsiniz.')
        steps.setWordWrap(True)
        steps.setTextInteractionFlags(Qt.TextInteractionFlag.TextSelectableByMouse if hasattr(Qt, 'TextInteractionFlag') else Qt.TextSelectableByMouse)
        content.addWidget(steps)
        first_password=QPushButton('İlk yönetici parolasını oluştur')
        first_password.clicked.connect(self._first_password)
        content.addWidget(first_password)
        self.policy = QLabel('Ağ ve uygulama politikası bekleniyor.')
        self.policy.setWordWrap(True)
        content.addWidget(self.policy)
        row = QHBoxLayout()
        self.buttons = {}
        from ..links import open_target
        for title, panel_id in [('Durum', 'home'), ('Servisleri incele', 'services'), ('Yönetici kilidi', 'settings')]:
            button = QPushButton(title)
            button.setObjectName('quiet')
            button.clicked.connect(lambda checked, pid=panel_id: open_target(self, pid))
            self.buttons[panel_id] = button
            row.addWidget(button)
        content.addLayout(row)
        internet = QPushButton("Uygulama internet izinlerini aç")
        internet.clicked.connect(self._open_permissions)
        content.addWidget(internet)
        from ..modem_setup import ModemSetup
        self.modem_setup=ModemSetup(self)
        content.addWidget(self.modem_setup)
        content.addStretch()

    def _first_password(self):
        from ..first_password import FirstPassword
        self.password_dialog=FirstPassword(self)
        self.password_dialog.show()

    def _open_permissions(self):
        from ..links import open_target
        open_target(self, 'apps')

    def refresh(self):
        try:
            health = self.backend.system_health()
            overview = self.backend.overview()
            critical = (overview.get('system') or {}).get('critical_integrity') or {}
            core = (overview.get('system') or {}).get('core_status')
            failures = critical.get('failures') or []
            fresh = isinstance(critical.get('checked_at'), (int, float)) and 0 <= time.time() - critical['checked_at'] <= 15
            self.readiness.setText('Core: ' + str(core or 'Doğrulanmadı') + '\nBütünlük: ' +
                ('; '.join(failure_text(f) for f in failures) if failures else
                 'Güncel denetim sağlıklı' if fresh and critical.get('status') == 'HEALTHY' else 'Güncel denetim doğrulanmadı') +
                '\nAyrıntılı servis durumu için “Servisleri incele”yi açın.')
            credential = health.get('admin_credential') or {}
            self.account.setText('Yönetici parolası: ' + ('Hazır — sağ üstteki kilitten açabilirsiniz.' if credential.get('configured') is True else
                'Oluşturulmamış veya doğrulanamıyor — ilk parola düğmesini kullanın.'))
            self.policy.setText('Uygulama filtresi yapılandırması: ' + self._app_state(health) +
                '\nTemel ağ politikası: dışarı TCP 53/443 ve UDP 53; yeni dış girişler kapalı.\n'
                'TeamViewer / AnyDesk: gelen kontrol henüz doğrulanmadı. Aktarma sunucusundan gelen kontrolü nftables tek başına ayıramaz; yerel uygulama politikası ve karşı cihaz testi zorunludur.')
        except Exception as exc:
            self.readiness.setText('Servis bağlantısı doğrulanamadı: ' + str(exc) + '\nServisleri incele bölümünü açın. Terminal tanısı: sudo satsuma-status')

    def _app_state(self, health):
        state = health.get('application_policy') or {}
        if state.get('enabled') is True:
            return 'Açık.'
        if state.get('enabled') is False:
            return 'Kapalı.'
        return 'Doğrulanmadı.'
