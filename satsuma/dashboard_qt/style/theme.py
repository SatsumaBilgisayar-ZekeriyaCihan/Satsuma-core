# -*- coding: utf-8 -*-
"""Satsuma Core dashboard theme.

Black surfaces with an orange accent (user choice 2026-11-04, design canvas C1);
semantic status colors stay distinct from the accent: green is healthy, amber
is a warning, red-orange is critical.

Satsuma Core panel teması: siyah yüzeyler ve turuncu vurgu (kullanıcı seçimi
2026-11-04, tasarım taslağı C1). Durum renkleri vurgudan ayrı kalır: yeşil
sağlıklı, kehribar uyarı, kırmızı-turuncu kritik.
"""


class Colors:
    BG_DEEP = '#050505'
    BG_BASE = '#0a0a0a'
    BG_SURFACE = '#161616'
    BG_ELEVATED = '#232323'
    BG_STRIP = '#000000'
    BG_SELECTED = '#3a2410'

    TEXT_PRIMARY = '#f2f2f2'
    TEXT_SECONDARY = '#cfcfcf'
    TEXT_MUTED = '#a0a0a0'
    TEXT_DISABLED = '#6a6a6a'
    TEXT_ORANGE = '#ff8c1a'
    TEXT_ORANGE_BRIGHT = '#ffb866'
    TEXT_ORANGE_DARK = '#e06a00'

    HEADER_FROM = '#1a1a1a'
    HEADER_TO = '#0b0b0b'
    HEADER_TEXT = '#ffffff'
    HEADER_ACCENT = '#ff8c1a'

    BORDER = '#3a3a3a'
    BORDER_LIGHT = '#2b2b2b'
    BORDER_SOFT = '#1f1f1f'
    BORDER_ACCENT = '#ff8c1a'

    STATUS_OK = '#9be15d'
    STATUS_WARN = '#ffc04d'
    STATUS_CRIT = '#ff5a36'
    STATUS_INFO = '#8ebaff'
    STATUS_MUTED = '#a0a0a0'

    S1 = '#c9232b'
    S2 = '#f06418'
    S3 = '#d99a13'
    S4 = '#2167a8'

    ACCENT = '#ff8c1a'
    ACCENT_DIM = '#3a2410'
    ACCENT_GLOW = '#ffb866'

    WHITE = '#ffffff'
    BLACK = '#000000'
    GRAY = '#8a8a8a'
    GRAY_LIGHT = '#b5b5b5'
    GRAY_TEXT = '#8a8a8a'
    NAVY = '#183b6b'
    NAVY_DARK = '#0a1f44'
    NAVY_LIGHT = '#2c5f98'
    NAVY_BG = '#eef2f7'
    ORANGE = '#ff6418'
    ORANGE_LIGHT = '#ff7d3a'
    ORANGE_DARK = '#d94d00'
    ORANGE_PASTEL = '#ffd6c2'
    FRAME_BLACK = '#0a1f44'
    FRAME_DARK = '#0a1f44'
    FRAME_DEEP_RED = '#3d1220'
    FRAME_RED = '#c9232b'
    FRAME_BRIGHT = '#ff6418'
    FRAME_ORANGE = '#ff6418'
    OK = STATUS_OK
    WARN = STATUS_WARN
    ERROR = STATUS_CRIT


FONT_MONO = 'FreeMono, "DejaVu Sans Mono", monospace'
FONT_UI = '"Inter", "Noto Sans", "DejaVu Sans", sans-serif'

FONT_SIZE_BRAND = 18
FONT_SIZE_TITLE = 24
FONT_SIZE_SUBTITLE = 12
FONT_SIZE_METRIC = 30
FONT_SIZE_LABEL = 11
FONT_SIZE_BODY = 13
FONT_SIZE_SMALL = 10

FONT_METRIC_SIZE = FONT_SIZE_METRIC
FONT_TITLE_SIZE = FONT_SIZE_TITLE
FONT_LABEL_SIZE = FONT_SIZE_LABEL
FONT_STATUS_SIZE = FONT_SIZE_BODY


GLOBAL_QSS = f"""
QWidget {{background-color:{Colors.BG_DEEP};color:{Colors.TEXT_PRIMARY};font-family:{FONT_UI};font-size:13px;}}
QMainWindow,QWidget#central {{background:{Colors.BG_DEEP};}}
QLabel {{background:transparent;border:none;}}
QLabel#eyebrow {{color:{Colors.TEXT_MUTED};font-size:10px;font-weight:700;letter-spacing:2px;}}
QLabel#pageTitle {{color:{Colors.TEXT_PRIMARY};font-size:28px;font-weight:700;}}
QLabel#secondary {{color:{Colors.TEXT_MUTED};font-size:12px;}}
QFrame#securityCard,QFrame#section_card,QFrame#op_card {{background:{Colors.BG_SURFACE};border:1px solid {Colors.BORDER_LIGHT};border-radius:16px;}}
QFrame#securityHero {{background:qlineargradient(x1:0,y1:0,x2:1,y2:1,stop:0 #3a2410,stop:1 #212121);border:1px solid #3e3e3e;border-radius:18px;}}
QFrame#mainSidebar {{background:{Colors.BG_STRIP};border-right:1px solid {Colors.BORDER_SOFT};}}
QFrame#header_bar {{background:{Colors.BG_DEEP};border-bottom:1px solid {Colors.BORDER_SOFT};}}
QWidget#transparent {{background:transparent;}}
QWidget#settingsPage {{background:{Colors.BG_SURFACE};border:1px solid {Colors.BORDER_LIGHT};border-radius:12px;}}
QPushButton {{background:{Colors.BG_ELEVATED};color:{Colors.TEXT_PRIMARY};border:1px solid {Colors.BORDER_LIGHT};border-radius:8px;padding:9px 15px;font-weight:600;}}
QPushButton:hover {{background:#343434;border-color:#616161;}}
QPushButton:pressed {{background:#3c3c3c;}}
QPushButton:focus {{border:1px solid {Colors.ACCENT};}}
QPushButton:disabled {{color:{Colors.TEXT_DISABLED};background:#212121;border-color:{Colors.BORDER_SOFT};}}
QPushButton#primary {{background:{Colors.ACCENT};color:#1a1715;border:1px solid {Colors.ACCENT};font-weight:700;}}
QPushButton#primary:hover {{background:#ffb866;border-color:#ffb866;}}
QPushButton#primary:disabled {{background:#493930;color:#9d8476;border-color:#493930;}}
QPushButton#danger {{background:#442630;color:#ffb3bb;border-color:#633541;}}
QPushButton#danger:hover {{background:#5a2c39;border-color:{Colors.STATUS_CRIT};}}
QPushButton#quiet {{background:transparent;color:{Colors.TEXT_SECONDARY};border:none;padding:6px 0;text-align:left;}}
QPushButton#quiet:hover {{color:{Colors.ACCENT};}}
QPushButton#navPrimary {{text-align:left;background:transparent;color:{Colors.TEXT_MUTED};border:none;border-left:3px solid transparent;border-radius:7px;padding:12px 14px;font-size:13px;font-weight:600;}}
QPushButton#navPrimary:hover {{background:#202020;color:{Colors.TEXT_PRIMARY};}}
QPushButton#navPrimary:checked {{background:#3a2410;color:{Colors.ACCENT};border-left:3px solid {Colors.ACCENT};}}
QListWidget#navTools {{background:transparent;border:none;outline:0;color:{Colors.TEXT_MUTED};font-size:12px;}}
QListWidget#navTools::item {{padding:9px 12px;border-radius:6px;margin:2px 0;}}
QListWidget#navTools::item:selected {{background:#3a2410;color:{Colors.TEXT_PRIMARY};}}
QListWidget#navTools::item:hover {{background:#202020;}}
QListWidget {{background:{Colors.BG_SURFACE};border:1px solid {Colors.BORDER_LIGHT};border-radius:9px;outline:0;}}
QListWidget::item {{padding:10px;border-radius:5px;}}
QListWidget::item:selected {{background:{Colors.BG_SELECTED};color:{Colors.ACCENT};}}
QLineEdit,QComboBox,QPlainTextEdit,QTextEdit {{background:#191919;color:{Colors.TEXT_PRIMARY};border:1px solid {Colors.BORDER_LIGHT};border-radius:7px;padding:9px 10px;selection-background-color:#434343;selection-color:white;}}
QLineEdit:focus,QComboBox:focus,QPlainTextEdit:focus,QTextEdit:focus {{border:1px solid {Colors.ACCENT};}}
QLineEdit:disabled,QComboBox:disabled {{color:{Colors.TEXT_DISABLED};}}
QComboBox::drop-down {{border:none;width:25px;}}
QComboBox QAbstractItemView {{background:{Colors.BG_SURFACE};color:{Colors.TEXT_PRIMARY};selection-background-color:#3a3a3a;padding:5px;border:1px solid {Colors.BORDER_LIGHT};}}
QCheckBox {{spacing:10px;padding:5px 0;background:transparent;}}
QCheckBox::indicator {{width:17px;height:17px;background:#181818;border:1px solid #616161;border-radius:4px;}}
QCheckBox::indicator:checked {{background:{Colors.ACCENT};border:4px solid #624638;}}
QCheckBox::indicator:disabled {{background:#232323;border:1px solid #414141;}}
QTableWidget,QTreeWidget {{background:{Colors.BG_SURFACE};alternate-background-color:#222222;color:{Colors.TEXT_SECONDARY};gridline-color:#303030;border:1px solid {Colors.BORDER_LIGHT};border-radius:10px;selection-background-color:#3c3c3c;selection-color:white;outline:0;}}
QTableWidget::item {{padding:9px 10px;border-bottom:1px solid #2e2e2e;}}
QHeaderView::section {{background:#1c1c1c;color:{Colors.TEXT_MUTED};padding:12px 10px;border:none;border-bottom:1px solid {Colors.BORDER_LIGHT};font-size:11px;font-weight:600;}}
QTableCornerButton::section {{background:#1c1c1c;border:none;}}
QScrollArea {{background:transparent;border:none;}}
QScrollBar:vertical {{background:transparent;width:8px;margin:2px;}}
QScrollBar::handle:vertical {{background:#414141;min-height:28px;border-radius:3px;}}
QScrollBar::handle:vertical:hover {{background:#707070;}}
QScrollBar::add-line:vertical,QScrollBar::sub-line:vertical {{height:0px;}}
QScrollBar:horizontal {{background:transparent;height:8px;margin:2px;}}
QScrollBar::handle:horizontal {{background:#414141;min-width:28px;border-radius:3px;}}
QScrollBar::add-line:horizontal,QScrollBar::sub-line:horizontal {{width:0px;}}
QScrollBar::add-page,QScrollBar::sub-page {{background:transparent;}}
QStatusBar {{background:{Colors.BG_STRIP};color:{Colors.TEXT_MUTED};border-top:1px solid {Colors.BORDER_SOFT};font-size:10px;}}
QStatusBar::item {{border:none;}}
QToolTip {{background:#313131;color:{Colors.TEXT_PRIMARY};border:1px solid #525252;padding:8px;}}
"""

GLOBAL_QSS += f"""
QTabWidget::pane {{border:1px solid {Colors.BORDER_SOFT};border-radius:14px;background:{Colors.BG_SURFACE};padding:14px;}}
QTabBar::tab {{background:transparent;color:{Colors.TEXT_MUTED};padding:12px 16px;margin:0 4px 8px 0;border-bottom:2px solid transparent;}}
QTabBar::tab:selected {{color:{Colors.ACCENT};border-bottom-color:{Colors.ACCENT};font-weight:700;}}
QTabBar::tab:hover {{color:{Colors.TEXT_PRIMARY};}}
QLabel#workflowStatus {{background:{Colors.BG_SURFACE};border:1px solid {Colors.BORDER_LIGHT};border-radius:10px;padding:12px 16px;color:{Colors.TEXT_SECONDARY};}}
QTableWidget {{gridline-color:{Colors.BORDER_SOFT};alternate-background-color:#232323;}}
QHeaderView::section {{padding:12px 14px;background:#1c1c1c;color:{Colors.TEXT_MUTED};border:none;border-bottom:1px solid {Colors.BORDER_LIGHT};font-weight:600;}}
QToolTip {{background:{Colors.BG_ELEVATED};color:{Colors.TEXT_PRIMARY};border:1px solid {Colors.BORDER_LIGHT};padding:8px;}}
"""
