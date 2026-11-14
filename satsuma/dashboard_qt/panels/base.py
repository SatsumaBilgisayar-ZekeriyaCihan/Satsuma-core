# -*- coding: utf-8 -*-
"""Satsuma Core — Panel temel sinifi.

Her panel bu siniftan miras alir. Metadata sinif degiskeni olarak durur,
registry bunlari okuyup navigasyonu otomatik kurar.

Yeni panel eklemek icin:
  1. panels/yeni_panel.py olustur
  2. BasePanel'i miras al
  3. @register dekoratoru koy
  4. PANEL_ID, PANEL_TITLE, PANEL_ORDER gibi metadata yaz
  5. _build() ve refresh() metotlarini doldur

Bitti. Registry otomatik kesfeder.
"""
try:
    from PyQt6.QtWidgets import QWidget, QVBoxLayout, QLabel
    from PyQt6.QtCore import Qt
    QT_VERSION = 6
except ImportError:
    from PyQt5.QtWidgets import QWidget, QVBoxLayout, QLabel
    from PyQt5.QtCore import Qt
    QT_VERSION = 5

try:
    from ..style.theme import (
        Colors, FONT_UI, FONT_MONO,
        FONT_SIZE_TITLE, FONT_SIZE_SUBTITLE, FONT_SIZE_BODY,
    )
except ImportError:
    from style.theme import (
        Colors, FONT_UI, FONT_MONO,
        FONT_SIZE_TITLE, FONT_SIZE_SUBTITLE, FONT_SIZE_BODY,
    )


class BasePanel(QWidget):
    """Tum panellerin ortak iskeleti."""

    # --- Sinif metadata (registry okur) ---
    PANEL_ID = None              # benzersiz kimlik (zorunlu)
    PANEL_TITLE = 'Panel'        # menude gorunen
    PANEL_ICON = ''              # emoji veya karakter
    PANEL_ORDER = 99             # navigasyondaki sira
    PANEL_GROUP = 'main'         # gruplama (main/system/security/admin)
    PANEL_SUBTITLE = ''          # panel alt basligi (opsiyonel)
    REFRESH_MS = 3000            # bu panelin yenilenme sikligi

    def __init__(self, backend, parent=None):
        super().__init__(parent)
        self.backend = backend
        self.setObjectName(f'panel_{self.PANEL_ID or "base"}')

        # Ana layout — alt sinif _build_ui() icinde doldurur
        self._layout = QVBoxLayout(self)
        self._layout.setContentsMargins(24, 20, 24, 20)
        self._layout.setSpacing(12)

        # Baslik (opsiyonel, alt sinif gizleyebilir)
        self._title_label = None

        # Alt sinifin kurulumunu cagir
        self._build()

    # ------------------------------------------------------------------
    # Alt sinif doldurur
    # ------------------------------------------------------------------

    def _build(self):
        """UI kur. Alt sinif override eder."""
        raise NotImplementedError(
            f'{self.__class__.__name__}._build() tanimlanmali'
        )

    def refresh(self):
        """Veriyi yenile. Alt sinif override eder."""
        raise NotImplementedError(
            f'{self.__class__.__name__}.refresh() tanimlanmali'
        )

    # ------------------------------------------------------------------
    # Yasam dongusu kancalari (opsiyonel)
    # ------------------------------------------------------------------

    def on_activate(self):
        """Panel gorunur oldu — veri tazele, animasyon baslat vb."""
        self.refresh()

    def on_deactivate(self):
        """Panel gizlendi — animasyonu durdur, timer'i duraklat vb."""
        pass

    # ------------------------------------------------------------------
    # Yardimcilar
    # ------------------------------------------------------------------

    def make_title(self, text):
        """Standart panel basligi olustur — BUYUK, BOLD, PARLAK TURUNCU."""
        label = QLabel(text)
        label.setWordWrap(True)
        label.setStyleSheet(
            f'color: {Colors.TEXT_PRIMARY}; '
            f'font-family: {FONT_UI}; '
            f'font-size: {FONT_SIZE_TITLE}px; '
            f'font-weight: 700; '
            f'letter-spacing: 0px; '
            f'background: transparent;'
        )
        return label

    def make_subtitle(self, text):
        """Ikincil baslik (kucuk, gri)."""
        label = QLabel(text)
        label.setWordWrap(True)
        label.setStyleSheet(
            f'color: {Colors.TEXT_MUTED}; '
            f'font-family: {FONT_UI}; '
            f'font-size: {FONT_SIZE_SUBTITLE}px; '
            f'letter-spacing: 0px; '
            f'background: transparent;'
        )
        return label

    def layout(self):
        """Qt'nin layout() metoduyla cakismamak icin override."""
        return super().layout()
