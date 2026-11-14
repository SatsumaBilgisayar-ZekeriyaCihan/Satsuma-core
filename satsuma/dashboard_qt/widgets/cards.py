# -*- coding: utf-8 -*-
"""Satsuma Core — ortak dashboard komponentleri.

Bu modul, paneller arasi tutarli gorunum saglar. Mevcut acik SOC paletini
(style.theme.Colors) kullanir; yeni renk tanimlamaz.

Komponentler:
  MetricCard   — buyuk sayi + etiket + renkli ust serit
  SectionCard  — baslik + icerik kapsayici (kart)
  StatusBadge  — durum rozeti (ACTIVE/FAILED/UNKNOWN ...)
  ActivityRow  — nokta + kaynak + metin + zaman satiri
"""
from __future__ import annotations

try:
    from PyQt6.QtWidgets import (
        QFrame, QLabel, QVBoxLayout, QHBoxLayout, QWidget,
    )
    from PyQt6.QtCore import Qt
    QT_VERSION = 6
except ImportError:
    from PyQt5.QtWidgets import (
        QFrame, QLabel, QVBoxLayout, QHBoxLayout, QWidget,
    )
    from PyQt5.QtCore import Qt
    QT_VERSION = 5

try:
    from ..style.theme import (
        Colors, FONT_UI, FONT_MONO,
        FONT_SIZE_BODY, FONT_SIZE_SMALL, FONT_SIZE_LABEL,
    )
except ImportError:
    from style.theme import (
        Colors, FONT_UI, FONT_MONO,
        FONT_SIZE_BODY, FONT_SIZE_SMALL, FONT_SIZE_LABEL,
    )


# Durum -> renk eslemesi (tek merkezden; paneller tekrar tanimlamaz)
STATUS_COLORS = {
    'ok': Colors.STATUS_OK,
    'active': Colors.STATUS_OK,
    'running': Colors.STATUS_OK,
    'valid': Colors.STATUS_OK,
    'warn': Colors.STATUS_WARN,
    'degraded': Colors.STATUS_WARN,
    'info': Colors.STATUS_INFO,
    'crit': Colors.STATUS_CRIT,
    'failed': Colors.STATUS_CRIT,
    'error': Colors.STATUS_CRIT,
    'unknown': Colors.STATUS_MUTED,
    'inactive': Colors.STATUS_MUTED,
    'disabled': Colors.STATUS_MUTED,
}


def status_color(state):
    """Durum metnini renge cevir (bilinmeyen -> notr)."""
    return STATUS_COLORS.get(str(state or '').strip().lower(), Colors.STATUS_MUTED)


class MetricCard(QFrame):
    """Buyuk metrik karti — ust serit rengi duruma gore degisir."""

    def __init__(self, title, value='—', accent=None, parent=None):
        super().__init__(parent)
        self.setObjectName('metric_card')
        self._accent = accent or Colors.ACCENT
        self.setMinimumHeight(84)
        self._apply_style()

        lay = QVBoxLayout(self)
        lay.setContentsMargins(14, 10, 14, 10)
        lay.setSpacing(2)

        self._title = QLabel(str(title).upper())
        self._title.setStyleSheet(
            f'color:{Colors.TEXT_MUTED}; font-family:{FONT_UI}; '
            f'font-size:{FONT_SIZE_LABEL}px; font-weight:700; letter-spacing:1px;'
        )
        lay.addWidget(self._title)

        self.value = QLabel(str(value))
        self.value.setStyleSheet(
            f'color:{Colors.TEXT_PRIMARY}; font-family:{FONT_UI}; '
            f'font-size:22px; font-weight:900;'
        )
        lay.addWidget(self.value)
        lay.addStretch()

    def _apply_style(self):
        self.setStyleSheet(f"""
            QFrame#metric_card {{
                background:{Colors.BG_SURFACE};
                border:1px solid {Colors.BORDER_LIGHT};
                border-top:4px solid {self._accent};
                border-radius:7px;
            }}
        """)

    def set_value(self, value, color=None, accent=None):
        """Degeri (ve istege bagli rengi) guncelle."""
        self.value.setText(str(value))
        c = color or Colors.TEXT_PRIMARY
        self.value.setStyleSheet(
            f'color:{c}; font-family:{FONT_UI}; font-size:22px; font-weight:900;'
        )
        if accent:
            self._accent = accent
            self._apply_style()

    def set_state(self, value, state):
        """Degeri durum rengiyle birlikte ayarla."""
        self.set_value(value, color=status_color(state), accent=status_color(state))


class SectionCard(QFrame):
    """Baslik + icerik kapsayici kart."""

    def __init__(self, title=None, parent=None):
        super().__init__(parent)
        self.setObjectName('section_card')
        self.setStyleSheet(f"""
            QFrame#section_card {{
                background:{Colors.BG_SURFACE};
                border:1px solid {Colors.BORDER_LIGHT};
                border-radius:7px;
            }}
        """)
        self._outer = QVBoxLayout(self)
        self._outer.setContentsMargins(14, 12, 14, 12)
        self._outer.setSpacing(8)

        if title:
            head = QLabel(str(title).upper())
            head.setStyleSheet(
                f'color:{Colors.TEXT_ORANGE}; font-family:{FONT_UI}; '
                f'font-size:{FONT_SIZE_BODY}px; font-weight:900; letter-spacing:2px;'
            )
            self._outer.addWidget(head)

        self.body = QWidget()
        self.body_layout = QVBoxLayout(self.body)
        self.body_layout.setContentsMargins(0, 0, 0, 0)
        self.body_layout.setSpacing(6)
        self._outer.addWidget(self.body)

    def add(self, widget):
        """Icerige widget ekle."""
        self.body_layout.addWidget(widget)
        return widget

    def add_layout(self, layout):
        self.body_layout.addLayout(layout)
        return layout


class StatusBadge(QLabel):
    """Durum rozeti — arka plani durum rengi, beyaz yazi."""

    def __init__(self, text='—', state=None, parent=None):
        super().__init__(parent)
        self.setAlignment(
            Qt.AlignmentFlag.AlignCenter if QT_VERSION == 6 else Qt.AlignCenter
        )
        self.set_state(text, state)

    def set_state(self, text, state=None):
        self.setText(str(text).upper())
        color = status_color(state if state is not None else text)
        self.setStyleSheet(f"""
            QLabel {{
                background:{color};
                color:{Colors.WHITE};
                border-radius:4px;
                padding:2px 9px;
                font-family:{FONT_UI};
                font-size:{FONT_SIZE_SMALL}px;
                font-weight:800;
                letter-spacing:1px;
            }}
        """)


class ActivityRow(QFrame):
    """Aktivite satiri — nokta + kaynak + metin + zaman."""

    def __init__(self, source, text, ts='—', state='info', parent=None):
        super().__init__(parent)
        self.setObjectName('activity_row')
        accent = status_color(state)
        self.setStyleSheet(f"""
            QFrame#activity_row {{
                background:{Colors.BG_SURFACE};
                border:none;
                border-bottom:1px solid {Colors.BORDER_SOFT};
            }}
        """)
        lay = QHBoxLayout(self)
        lay.setContentsMargins(4, 7, 4, 7)
        lay.setSpacing(9)

        dot = QLabel('●')
        dot.setStyleSheet(f'color:{accent}; font-size:10px;')
        dot.setFixedWidth(12)
        lay.addWidget(dot)

        src = QLabel(str(source).upper())
        src.setFixedWidth(96)
        src.setStyleSheet(
            f'color:{Colors.TEXT_SECONDARY}; font-family:{FONT_UI}; '
            f'font-size:{FONT_SIZE_SMALL + 1}px; font-weight:900; letter-spacing:1px;'
        )
        lay.addWidget(src)

        body = QLabel(str(text))
        body.setWordWrap(False)
        body.setStyleSheet(
            f'color:{Colors.TEXT_PRIMARY}; font-family:{FONT_UI}; '
            f'font-size:{FONT_SIZE_BODY}px;'
        )
        lay.addWidget(body, 1)

        time = QLabel(str(ts))
        time.setStyleSheet(
            f'color:{Colors.TEXT_MUTED}; font-family:{FONT_MONO}; '
            f'font-size:{FONT_SIZE_SMALL}px;'
        )
        lay.addWidget(time)
