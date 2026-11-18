"""One import point for the 2.2.45 panel: PyQt6 first, PyQt5 as fallback, enum names unified.

2.2.45 paneli için tek içe aktarma noktası; PyQt6 önce, PyQt5 yedek.
"""
try:
    from PyQt6.QtWidgets import (QApplication, QWidget, QFrame, QLabel, QPushButton, QToolButton, QVBoxLayout, QHBoxLayout,
                                 QGridLayout, QScrollArea, QStackedWidget, QLineEdit, QComboBox, QCheckBox, QPlainTextEdit,
                                 QListWidget, QListWidgetItem, QDialog, QDialogButtonBox, QSizePolicy, QMainWindow,
                                 QSplitter, QButtonGroup, QRadioButton, QMessageBox, QInputDialog, QFileDialog)
    from PyQt6.QtGui import QColor, QFont, QIcon, QPixmap, QPainter, QPen, QBrush, QKeySequence, QShortcut
    from PyQt6.QtCore import Qt, QTimer, QSize, QObject, pyqtSignal, QSettings, QRectF, QPoint
    QT = 6
except ImportError:  # pragma: no cover - PyQt5 systems
    from PyQt5.QtWidgets import (QApplication, QWidget, QFrame, QLabel, QPushButton, QToolButton, QVBoxLayout, QHBoxLayout,
                                 QGridLayout, QScrollArea, QStackedWidget, QLineEdit, QComboBox, QCheckBox, QPlainTextEdit,
                                 QListWidget, QListWidgetItem, QDialog, QDialogButtonBox, QSizePolicy, QMainWindow,
                                 QSplitter, QButtonGroup, QRadioButton, QMessageBox, QInputDialog, QFileDialog, QShortcut)
    from PyQt5.QtGui import QColor, QFont, QIcon, QPixmap, QPainter, QPen, QBrush, QKeySequence
    from PyQt5.QtCore import Qt, QTimer, QSize, QObject, pyqtSignal, QSettings, QRectF, QPoint
    QT = 5


def enum(owner, group, name):
    """Qt6 scoped enums (Qt.AlignmentFlag.AlignTop) and Qt5 flat ones (Qt.AlignTop)."""
    scoped = getattr(owner, group, None)
    return getattr(scoped, name) if scoped is not None and hasattr(scoped, name) else getattr(owner, name)


ALIGN_TOP = enum(Qt, 'AlignmentFlag', 'AlignTop')
ALIGN_LEFT = enum(Qt, 'AlignmentFlag', 'AlignLeft')
ALIGN_RIGHT = enum(Qt, 'AlignmentFlag', 'AlignRight')
ALIGN_CENTER = enum(Qt, 'AlignmentFlag', 'AlignCenter')
ALIGN_VCENTER = enum(Qt, 'AlignmentFlag', 'AlignVCenter')
POINTING = enum(Qt, 'CursorShape', 'PointingHandCursor')
NO_SCROLL = enum(Qt, 'ScrollBarPolicy', 'ScrollBarAlwaysOff')
PASSWORD = enum(QLineEdit, 'EchoMode', 'Password')
EXPANDING = enum(QSizePolicy, 'Policy', 'Expanding')
PREFERRED = enum(QSizePolicy, 'Policy', 'Preferred')
FIXED = enum(QSizePolicy, 'Policy', 'Fixed')
MINIMUM = enum(QSizePolicy, 'Policy', 'Minimum')
USER_ROLE = enum(Qt, 'ItemDataRole', 'UserRole')
NO_ITEM_FLAGS = enum(Qt, 'ItemFlag', 'NoItemFlags')
TEXT_SELECTABLE = enum(Qt, 'TextInteractionFlag', 'TextSelectableByMouse')
RICH_TEXT = enum(Qt, 'TextFormat', 'RichText')
PLAIN_TEXT = enum(Qt, 'TextFormat', 'PlainText')
KEY_ESCAPE = enum(Qt, 'Key', 'Key_Escape')
DIALOG_OK = enum(QDialogButtonBox, 'StandardButton', 'Ok')
DIALOG_CANCEL = enum(QDialogButtonBox, 'StandardButton', 'Cancel')
ACCEPTED = enum(QDialog, 'DialogCode', 'Accepted')
