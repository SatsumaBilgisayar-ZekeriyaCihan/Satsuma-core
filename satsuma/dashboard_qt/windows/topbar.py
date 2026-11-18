"""Top bar of the 2.2.45 panel: page title, search, waiting count, administrator lock; feedback line under it.

Üst çubuk: sayfa başlığı, arama, bekleyen sayısı, yönetici kilidi; altında işlem geri bildirimi.
"""
from ..qt import QFrame, QHBoxLayout, QLabel, QLineEdit, QPushButton, QTimer, QSize, pyqtSignal, POINTING
from ..security_widgets import icon
from ..style.theme import Colors
from ..ui import TONES


class TopBar(QFrame):
    search_requested = pyqtSignal(str)
    lock_clicked = pyqtSignal()
    attention_clicked = pyqtSignal()

    def __init__(self, parent=None):
        super().__init__(parent)
        self.setObjectName('topBar')
        row = QHBoxLayout(self)
        row.setContentsMargins(32, 14, 24, 14)
        row.setSpacing(12)
        self.title = QLabel('Durum')
        self.title.setObjectName('topTitle')
        row.addWidget(self.title)
        row.addStretch()
        self.search = QLineEdit()
        self.search.setObjectName('topSearch')
        self.search.setPlaceholderText('Ara: program, adres, alan adı  (Ctrl+F)')
        self.search.setClearButtonEnabled(True)
        self.search.setFixedWidth(320)
        self.search.addAction(icon('search', Colors.TEXT_MUTED, 16), enum_leading())
        self.search.returnPressed.connect(lambda: self.search_requested.emit(self.search.text().strip()))
        row.addWidget(self.search)
        self.attention = QPushButton('')
        self.attention.setObjectName('topAttention')
        self.attention.setCursor(POINTING)
        self.attention.setIcon(icon('bell', Colors.TEXT_SECONDARY, 18))
        self.attention.setIconSize(QSize(18, 18))
        self.attention.setToolTip('Sizi bekleyen konular')
        self.attention.clicked.connect(self.attention_clicked.emit)
        row.addWidget(self.attention)
        self.lock = QPushButton('  Kilitli')
        self.lock.setObjectName('topLock')
        self.lock.setCursor(POINTING)
        self.lock.setIconSize(QSize(16, 16))
        self.lock.clicked.connect(self.lock_clicked.emit)
        row.addWidget(self.lock)
        self.set_locked(True)
        self.set_attention(0)

    def set_page(self, title):
        self.title.setText(title)

    def set_locked(self, locked):
        self.lock.setText('  Kilitli' if locked else '  Kilit açık')
        self.lock.setIcon(icon('lock' if locked else 'unlock', Colors.TEXT_SECONDARY if locked else Colors.ACCENT, 16))
        self.lock.setToolTip('Ayar değiştirmek için kilidi açın' if locked else 'Kilitlemek için tıklayın')
        self.lock.setProperty('unlocked', not locked)
        self.lock.style().unpolish(self.lock)
        self.lock.style().polish(self.lock)

    def set_attention(self, count, tone='warn'):
        self.attention.setText(' %d' % count if count else '')
        color = TONES.get(tone, TONES['warn'])[0] if count else Colors.TEXT_MUTED
        self.attention.setIcon(icon('bell', color, 18))
        self.attention.setAccessibleName('%d konu sizi bekliyor' % count if count else 'Bekleyen konu yok')


def enum_leading():
    from ..qt import QLineEdit as Line
    position = getattr(Line, 'ActionPosition', None)
    return position.LeadingPosition if position is not None else Line.LeadingPosition


class Feedback(QFrame):
    """One line under the top bar for the result of the last action; hides itself after a while."""

    def __init__(self, parent=None):
        super().__init__(parent)
        self.setObjectName('feedback')
        row = QHBoxLayout(self)
        row.setContentsMargins(32, 9, 24, 9)
        self.text = QLabel('')
        self.text.setWordWrap(True)
        row.addWidget(self.text, 1)
        close = QPushButton('Kapat')
        close.setObjectName('quiet')
        close.clicked.connect(self.hide)
        row.addWidget(close)
        self.timer = QTimer(self)
        self.timer.setSingleShot(True)
        self.timer.timeout.connect(self.hide)
        self.hide()

    def show_message(self, tone, text, seconds=None):
        fg, bg = TONES.get(tone, TONES['info'])
        self.setStyleSheet(f'QFrame#feedback{{background:{bg};border-bottom:1px solid {Colors.BORDER_SOFT};}}'
                           f'QLabel{{color:{fg};font-size:12px;font-weight:600;}}')
        self.text.setText(text)
        self.show()
        self.timer.start(int((seconds or (12 if tone == 'error' else 7)) * 1000))
