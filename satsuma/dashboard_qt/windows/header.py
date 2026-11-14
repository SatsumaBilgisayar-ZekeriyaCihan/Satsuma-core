"""Quiet product header; status details live on the relevant page."""
import datetime
try:
    from PyQt6.QtWidgets import QFrame,QHBoxLayout,QVBoxLayout,QLabel,QPushButton
    from PyQt6.QtCore import pyqtSignal,QSize
except ImportError:
    from PyQt5.QtWidgets import QFrame,QHBoxLayout,QVBoxLayout,QLabel,QPushButton
    from PyQt5.QtCore import pyqtSignal,QSize
from ..security_widgets import icon

class HeaderBar(QFrame):
    manage_requested=pyqtSignal()
    def __init__(self,version='-',started_at=None):
        super().__init__();self.setObjectName('header_bar');self.setFixedHeight(78)
        layout=QHBoxLayout(self);layout.setContentsMargins(30,15,30,15);layout.setSpacing(18)
        text=QVBoxLayout();self.page=QLabel('Güvenlik merkezi');self.page.setStyleSheet('font-size:18px;font-weight:700;');text.addWidget(self.page)
        sub=QLabel('YEREL ÇALIŞMA ALANI  /  SATSUMA SECURITY');sub.setObjectName('secondary');text.addWidget(sub);layout.addLayout(text);layout.addStretch()
        self.version_label=QLabel();self.version_label.setObjectName('secondary');self.set_version(version);layout.addWidget(self.version_label)
        self.clock_label=QLabel();self.clock_label.setObjectName('secondary');layout.addWidget(self.clock_label)
        account=QPushButton('Yönetici erişimi');account.setIcon(icon('lock',size=18));account.clicked.connect(self.manage_requested.emit);layout.addWidget(account);self.tick()
    def tick(self):self.clock_label.setText(datetime.datetime.now().strftime('%H:%M'))
    def set_version(self,version):self.version_label.setText('Core '+str(version))
    def set_page(self,title):self.page.setText(title)
