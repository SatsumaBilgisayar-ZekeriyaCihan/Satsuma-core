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


def _sentence(text):
    """'BULGULAR' -> 'Bulgular': titles written in capitals read as shouting (2.2.47 design)."""
    text = str(text or '')
    if not text.isupper():
        return text
    lower = text.lower().replace('i̇', 'i')
    table = str.maketrans({'ı': 'ı'})
    lower = ''.join(('i' if c == 'i' else c) for c in lower).translate(table)
    first = lower[:1]
    return ({'i': 'İ', 'ı': 'I'}.get(first, first.upper())) + lower[1:]


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
        self._layout.setContentsMargins(32, 24, 32, 24)
        self._layout.setSpacing(14)

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
        """Page title in the 2.2.47 design (sentence case, no capitals shouting)."""
        label = QLabel(_sentence(text))
        label.setWordWrap(True)
        label.setObjectName('pageTitle')
        return label

    def make_subtitle(self, text):
        """One line under the title saying what the page shows."""
        label = QLabel(_sentence(text) if text and text.isupper() else text)
        label.setWordWrap(True)
        label.setObjectName('pageSubtitle')
        return label

    def layout(self):
        """Qt'nin layout() metoduyla cakismamak icin override."""
        return super().layout()
