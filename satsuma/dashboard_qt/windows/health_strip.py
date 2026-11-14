# -*- coding: utf-8 -*-
"""Satsuma Core — SOC Health Strip.

Header'in hemen altinda kalici durum seridi. Amac: operatorun
kartlara bakmadan once 2 saniyede sistem durumunu gormesi.

  ● HEALTHY | 3 Alerts | 0 Critical | 24/25 Workers | Last: 12s ago
"""
try:
    from PyQt6.QtWidgets import QFrame, QHBoxLayout, QLabel
    from PyQt6.QtCore import Qt
    QT_VERSION = 6
except ImportError:
    from PyQt5.QtWidgets import QFrame, QHBoxLayout, QLabel
    from PyQt5.QtCore import Qt
    QT_VERSION = 5

try:
    from ..style.theme import Colors, FONT_MONO, FONT_UI
except ImportError:
    from style.theme import Colors, FONT_MONO, FONT_UI


# Durum seviyeleri
STATE_HEALTHY = 'HEALTHY'
STATE_DEGRADED = 'DEGRADED'
STATE_CRITICAL = 'CRITICAL'
STATE_UNKNOWN = 'UNKNOWN'

_STATE_COLORS = {
    STATE_HEALTHY: Colors.STATUS_OK,
    STATE_DEGRADED: Colors.STATUS_WARN,
    STATE_CRITICAL: Colors.STATUS_CRIT,
    STATE_UNKNOWN: Colors.STATUS_MUTED,
}


class HealthStrip(QFrame):
    """Kalici SOC durum seridi."""

    def __init__(self):
        super().__init__()
        self.setObjectName('health_strip')
        self.setFixedHeight(34)
        self.setStyleSheet(f"""
            QFrame#health_strip {{
                background-color: {Colors.BG_STRIP};
                border: none;
                border-bottom: 1px solid {Colors.BG_ELEVATED};
            }}
        """)

        layout = QHBoxLayout(self)
        layout.setContentsMargins(24, 4, 24, 4)
        layout.setSpacing(16)

        # ---- Durum noktasi ----
        self.status_dot = QLabel('●')
        self.status_dot.setStyleSheet(
            f'color: {Colors.STATUS_MUTED}; font-size: 14px; '
            f'background: transparent;'
        )
        layout.addWidget(self.status_dot)

        # ---- Durum metni ----
        self.status_label = QLabel(STATE_UNKNOWN)
        self.status_label.setStyleSheet(
            f'color: {Colors.STATUS_MUTED}; '
            f'font-family: {FONT_UI}; '
            f'font-size: 11px; font-weight: 700; '
            f'letter-spacing: 2px; background: transparent;'
        )
        layout.addWidget(self.status_label)

        layout.addWidget(self._sep())

        # ---- Alert sayisi ----
        self.alerts_label = QLabel('0 alerts')
        self.alerts_label.setStyleSheet(self._metric_style())
        layout.addWidget(self.alerts_label)

        layout.addWidget(self._sep())

        # ---- Kritik sayisi ----
        self.critical_label = QLabel('0 critical')
        self.critical_label.setStyleSheet(self._metric_style())
        layout.addWidget(self.critical_label)

        layout.addWidget(self._sep())

        # ---- Worker durumu ----
        self.workers_label = QLabel('-/- workers')
        self.workers_label.setStyleSheet(self._metric_style())
        layout.addWidget(self.workers_label)

        layout.addStretch()

        # ---- Son olay zamani ----
        self.last_event_label = QLabel('last: —')
        self.last_event_label.setStyleSheet(
            f'color: {Colors.TEXT_MUTED}; '
            f'font-family: {FONT_MONO}; '
            f'font-size: 10px; background: transparent;'
        )
        layout.addWidget(self.last_event_label)

    # ------------------------------------------------------------------
    # Yardimcilar
    # ------------------------------------------------------------------

    def _sep(self):
        """Dikey ayrac."""
        s = QLabel('│')
        s.setStyleSheet(
            f'color: {Colors.TEXT_DISABLED}; '
            f'font-size: 12px; background: transparent;'
        )
        return s

    def _metric_style(self):
        return (
            f'color: {Colors.TEXT_SECONDARY}; '
            f'font-family: {FONT_UI}; '
            f'font-size: 11px; background: transparent;'
        )

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def update_state(self, state, alerts=0, critical=0,
                     workers_active=0, workers_total=0,
                     last_event_seconds=None):
        """Seridi guncelle.

        Args:
            state: STATE_HEALTHY / DEGRADED / CRITICAL / UNKNOWN
            alerts: toplam uyari sayisi
            critical: kritik olay sayisi
            workers_active: aktif worker
            workers_total: toplam worker
            last_event_seconds: son olaydan bu yana gecen saniye (None=bilinmiyor)
        """
        color = _STATE_COLORS.get(state, Colors.STATUS_MUTED)

        # Durum noktasi + metni
        self.status_dot.setStyleSheet(
            f'color: {color}; font-size: 14px; background: transparent;'
        )
        self.status_label.setText(state)
        self.status_label.setStyleSheet(
            f'color: {color}; '
            f'font-family: {FONT_UI}; '
            f'font-size: 11px; font-weight: 700; '
            f'letter-spacing: 2px; background: transparent;'
        )

        # Alert sayisi
        self.alerts_label.setText(f'{alerts} alert' + ('s' if alerts != 1 else ''))
        if alerts > 0 and critical == 0:
            self.alerts_label.setStyleSheet(
                f'color: {Colors.STATUS_WARN}; '
                f'font-family: {FONT_UI}; font-size: 11px; '
                f'background: transparent;'
            )
        else:
            self.alerts_label.setStyleSheet(self._metric_style())

        # Kritik sayisi
        self.critical_label.setText(f'{critical} critical')
        if critical > 0:
            self.critical_label.setStyleSheet(
                f'color: {Colors.STATUS_CRIT}; '
                f'font-family: {FONT_UI}; font-size: 11px; font-weight: 700; '
                f'background: transparent;'
            )
        else:
            self.critical_label.setStyleSheet(self._metric_style())

        # Worker durumu
        if workers_total > 0:
            self.workers_label.setText(f'{workers_active}/{workers_total} workers')
            if workers_active == workers_total:
                self.workers_label.setStyleSheet(
                    f'color: {Colors.STATUS_OK}; '
                    f'font-family: {FONT_UI}; font-size: 11px; '
                    f'background: transparent;'
                )
            else:
                self.workers_label.setStyleSheet(
                    f'color: {Colors.STATUS_WARN}; '
                    f'font-family: {FONT_UI}; font-size: 11px; '
                    f'background: transparent;'
                )
        else:
            self.workers_label.setText('-/- workers')
            self.workers_label.setStyleSheet(self._metric_style())

        # Son olay
        if last_event_seconds is None:
            self.last_event_label.setText('last: —')
        elif last_event_seconds < 60:
            self.last_event_label.setText(f'last: {last_event_seconds}s ago')
        elif last_event_seconds < 3600:
            self.last_event_label.setText(f'last: {last_event_seconds // 60}m ago')
        else:
            self.last_event_label.setText(f'last: {last_event_seconds // 3600}h ago')


def compute_state(critical=0, alerts=0, workers_active=0, workers_total=0):
    """Durum seviyesini otomatik hesapla.

    Kurallar:
      - critical > 0        -> CRITICAL
      - alerts > 0          -> DEGRADED
      - workers eksik       -> DEGRADED
      - aksi                -> HEALTHY
    """
    if critical > 0:
        return STATE_CRITICAL
    if alerts > 0:
        return STATE_DEGRADED
    if workers_total > 0 and workers_active < workers_total:
        return STATE_DEGRADED
    return STATE_HEALTHY
