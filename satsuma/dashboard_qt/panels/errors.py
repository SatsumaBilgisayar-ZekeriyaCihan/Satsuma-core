# -*- coding: utf-8 -*-
"""Satsuma Core — Hatalar paneli."""
try:
    from PyQt6.QtWidgets import (
        QLabel, QVBoxLayout, QHBoxLayout, QFrame,
        QScrollArea, QWidget,
    )
    from PyQt6.QtCore import Qt
    QT_VERSION = 6
except ImportError:
    from PyQt5.QtWidgets import (
        QLabel, QVBoxLayout, QHBoxLayout, QFrame,
        QScrollArea, QWidget,
    )
    from PyQt5.QtCore import Qt
    QT_VERSION = 5

try:
    from .base import BasePanel
    from . import register
except ImportError:
    from base import BasePanel
    from panels import register

try:
    from ..style.theme import (
        Colors, FONT_UI, FONT_MONO,
        FONT_SIZE_TITLE, FONT_SIZE_BODY, FONT_SIZE_SMALL,
    )
except ImportError:
    from style.theme import (
        Colors, FONT_UI, FONT_MONO,
        FONT_SIZE_TITLE, FONT_SIZE_BODY, FONT_SIZE_SMALL,
    )


@register
class ErrorsPanel(BasePanel):
    """Son hatalari gosteren panel."""

    PANEL_ID = 'errors'
    PANEL_TITLE = 'Hatalar'
    PANEL_ICON = '⚠️'
    PANEL_ORDER = 16
    PANEL_GROUP = 'system'
    REFRESH_MS = 5000

    def _build(self):
        # Buyuk bold turuncu baslik
        title = self.make_title(self.PANEL_TITLE)
        self._layout.addWidget(title)

        # Ince turuncu ayrac
        line = QFrame()
        line.setFixedHeight(2)
        line.setStyleSheet(
            f'background-color: {Colors.TEXT_ORANGE}; border: none;'
        )
        self._layout.addWidget(line)
        self._layout.addSpacing(10)

        # Icerik kaydirilabilir
        self.scroll = QScrollArea()
        self.scroll.setWidgetResizable(True)
        self.scroll.setFrameShape(QFrame.Shape.NoFrame if QT_VERSION == 6
                                  else QFrame.NoFrame)
        self.scroll.setStyleSheet('background: transparent;')

        self.content = QWidget()
        self.content_layout = QVBoxLayout(self.content)
        self.content_layout.setContentsMargins(0, 0, 0, 0)
        self.content_layout.setSpacing(10)
        self.content_layout.addStretch()

        self.scroll.setWidget(self.content)
        self._layout.addWidget(self.scroll, 1)

        # Bos durum etiketi
        self.empty_label = QLabel('Henüz hata kaydı yok.')
        self.empty_label.setStyleSheet(
            f'color: {Colors.TEXT_SECONDARY}; '
            f'font-family: {FONT_UI}; '
            f'font-size: {FONT_SIZE_BODY}px; '
            f'background: transparent;'
        )
        self._layout.addWidget(self.empty_label)
        self.empty_label.hide()

    def refresh(self):
        # Eski satirlari temizle (stretch haric)
        while self.content_layout.count() > 1:
            item = self.content_layout.takeAt(0)
            w = item.widget()
            if w:
                w.deleteLater()

        # Veri cek
        try:
            rows = self.backend.rows('errors', limit=12)
        except Exception as e:
            print(f'[errors panel] backend hatasi: {e}')
            rows = []

        if not rows:
            self.empty_label.show()
            self.scroll.hide()
            return

        self.empty_label.hide()
        self.scroll.show()

        for row in rows:
            row_widget = self._make_row(row)
            self.content_layout.insertWidget(
                self.content_layout.count() - 1, row_widget
            )

    def _make_row(self, item):
        """Tek bir hata satiri — lacivert cerceve + turuncu sol kenar."""
        frame = QFrame()
        frame.setObjectName('error_row')
        frame.setStyleSheet(f"""
            QFrame#error_row {{
                background-color: {Colors.BG_SURFACE};
                border: 2px solid {Colors.BORDER};
                border-left: 6px solid {Colors.TEXT_ORANGE};
                border-radius: 4px;
            }}
        """)

        layout = QHBoxLayout(frame)
        layout.setContentsMargins(14, 12, 14, 12)
        layout.setSpacing(18)

        # Zaman — mono, koyu lacivert, bold
        ts = str(item.get('timestamp', '-'))
        time_lbl = QLabel(self._short_time(ts))
        time_lbl.setStyleSheet(
            f'color: {Colors.TEXT_PRIMARY}; '
            f'font-family: {FONT_MONO}; '
            f'font-size: {FONT_SIZE_BODY}px; '
            f'font-weight: 700; '
            f'background: transparent;'
        )
        time_lbl.setFixedWidth(100)
        layout.addWidget(time_lbl)

        # Bilesen — buyuk harf, bold, turuncu
        component = str(item.get('component', '-'))
        comp_lbl = QLabel(component.upper())
        comp_lbl.setStyleSheet(
            f'color: {Colors.TEXT_ORANGE}; '
            f'font-family: {FONT_UI}; '
            f'font-size: {FONT_SIZE_BODY + 1}px; '
            f'font-weight: 900; '
            f'letter-spacing: 1px; '
            f'background: transparent;'
        )
        comp_lbl.setFixedWidth(160)
        layout.addWidget(comp_lbl)

        # Hata metni — lacivert, normal
        err_text = str(item.get('error', '-'))
        err_lbl = QLabel(err_text)
        err_lbl.setWordWrap(True)
        err_lbl.setStyleSheet(
            f'color: {Colors.TEXT_PRIMARY}; '
            f'font-family: {FONT_UI}; '
            f'font-size: {FONT_SIZE_BODY}px; '
            f'background: transparent;'
        )
        layout.addWidget(err_lbl, 1)

        return frame

    @staticmethod
    def _short_time(ts):
        """Unix timestamp veya ISO string'i HH:MM:SS'e cevir."""
        try:
            import datetime
            if isinstance(ts, (int, float)):
                dt = datetime.datetime.fromtimestamp(ts)
                return dt.strftime('%H:%M:%S')
            s = str(ts).replace('T', ' ')
            return s[11:19] if len(s) >= 19 else s[:8]
        except Exception:
            return str(ts)[:8]
