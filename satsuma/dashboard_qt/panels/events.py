# -*- coding: utf-8 -*-
"""Satsuma Core events panel.

Mixed host/network/DNS events are normalized into a compact operations table.
Duplicate rows and empty event records are hidden from the operator view.
"""
try:
    from PyQt6.QtWidgets import (
        QLabel, QVBoxLayout, QHBoxLayout, QFrame, QTableWidget,
        QTableWidgetItem, QHeaderView, QAbstractItemView,
        QComboBox, QLineEdit,
    )
    from PyQt6.QtCore import Qt
    from PyQt6.QtGui import QColor, QBrush
    QT_VERSION = 6
except ImportError:
    from PyQt5.QtWidgets import (
        QLabel, QVBoxLayout, QHBoxLayout, QFrame, QTableWidget,
        QTableWidgetItem, QHeaderView, QAbstractItemView,
        QComboBox, QLineEdit,
    )
    from PyQt5.QtCore import Qt
    from PyQt5.QtGui import QColor, QBrush
    QT_VERSION = 5

import datetime
from ...presentation import fields, priority_key

try:
    from .base import BasePanel
    from . import register
except ImportError:
    from base import BasePanel
    from panels import register

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


ALIGN_CENTER = Qt.AlignmentFlag.AlignCenter if QT_VERSION == 6 else Qt.AlignCenter


@register
class EventsPanel(BasePanel):
    PANEL_ID = 'events'
    PANEL_TITLE = 'Olaylar'
    PANEL_ICON = '▤'
    PANEL_ORDER = 2
    PANEL_GROUP = 'main'
    REFRESH_MS = 4000

    COLUMNS = [
        ('ÖNEM', 78),
        ('SINIFLANDIRMA', 110),
        ('TARİH / SAAT', 160),
        ('SÜREÇ', 140),
        ('PID', 72),
        ('TİP', 120),
        ('KAYNAK', 190),
        ('HEDEF / DOMAIN', 260),
        ('PROTO', 72),
        ('DETAY', 0),
    ]

    def _build(self):
        self._events = []

        title_row = QHBoxLayout()
        title_row.addWidget(self.make_title(f'{self.PANEL_ICON}  {self.PANEL_TITLE}'))
        title_row.addStretch()
        self.info_label = QLabel('')
        self.info_label.setStyleSheet(
            f'color:{Colors.TEXT_MUTED}; font-family:{FONT_MONO}; '
            f'font-size:{FONT_SIZE_SMALL}px; background:transparent;'
        )
        title_row.addWidget(self.info_label)
        self._layout.addLayout(title_row)

        line = QFrame()
        line.setFixedHeight(2)
        line.setStyleSheet(f'background:{Colors.TEXT_ORANGE}; border:none;')
        self._layout.addWidget(line)

        self._build_filters()
        self._build_table()

    def _build_filters(self):
        frame = QFrame()
        frame.setObjectName('events_filter')
        frame.setStyleSheet(f"""
            QFrame#events_filter {{
                background:{Colors.BG_SURFACE};
                border:1px solid {Colors.BORDER_LIGHT};
                border-radius:7px;
            }}
        """)
        row = QHBoxLayout(frame)
        row.setContentsMargins(10, 7, 10, 7)
        row.setSpacing(8)

        lbl = QLabel('Görünüm')
        lbl.setStyleSheet(f'color:{Colors.TEXT_MUTED}; font-weight:700;')
        row.addWidget(lbl)

        self.kind_filter = QComboBox()
        for text, value in (
            ('Tümü', ''),
            ('Ağ', 'network'),
            ('DNS', 'dns'),
            ('Host', 'host'),
            ('Alarm', 'alert'),
        ):
            self.kind_filter.addItem(text, value)
        self.kind_filter.currentIndexChanged.connect(self._render)
        row.addWidget(self.kind_filter)

        self.search = QLineEdit()
        self.search.setPlaceholderText('Olay ara: IP, domain, komut, imza, protokol...')
        self.search.textChanged.connect(self._render)
        row.addWidget(self.search, 1)

        self.dedupe_label = QLabel('')
        self.dedupe_label.setStyleSheet(
            f'color:{Colors.TEXT_MUTED}; font-family:{FONT_MONO}; '
            f'font-size:{FONT_SIZE_SMALL}px;'
        )
        row.addWidget(self.dedupe_label)
        self._layout.addWidget(frame)

    def _build_table(self):
        self.table = QTableWidget()
        self.table.setColumnCount(len(self.COLUMNS))
        self.table.setHorizontalHeaderLabels([c[0] for c in self.COLUMNS])
        self.table.verticalHeader().setVisible(False)
        self.table.setSelectionBehavior(
            QAbstractItemView.SelectionBehavior.SelectRows if QT_VERSION == 6
            else QAbstractItemView.SelectRows
        )
        self.table.setSelectionMode(
            QAbstractItemView.SelectionMode.SingleSelection if QT_VERSION == 6
            else QAbstractItemView.SingleSelection
        )
        self.table.setEditTriggers(
            QAbstractItemView.EditTrigger.NoEditTriggers if QT_VERSION == 6
            else QAbstractItemView.NoEditTriggers
        )
        self.table.setShowGrid(False)

        header = self.table.horizontalHeader()
        for i, (_, width) in enumerate(self.COLUMNS):
            if width == 0:
                header.setSectionResizeMode(
                    i,
                    QHeaderView.ResizeMode.Stretch if QT_VERSION == 6 else QHeaderView.Stretch,
                )
            else:
                header.setSectionResizeMode(
                    i,
                    QHeaderView.ResizeMode.Fixed if QT_VERSION == 6 else QHeaderView.Fixed,
                )
                self.table.setColumnWidth(i, width)

        self.table.setStyleSheet(f"""
            QTableWidget {{
                background:{Colors.BG_SURFACE};
                border:1px solid {Colors.BORDER_LIGHT};
                border-radius:7px;
                color:{Colors.TEXT_PRIMARY};
                font-size:{FONT_SIZE_BODY}px;
            }}
            QTableWidget::item {{
                padding:6px; border-bottom:1px solid {Colors.BORDER_SOFT};
            }}
            QTableWidget::item:selected {{
                background:{Colors.BG_SELECTED}; color:{Colors.TEXT_PRIMARY};
            }}
            QHeaderView::section {{
                background:{Colors.BG_ELEVATED}; color:{Colors.TEXT_SECONDARY};
                padding:8px 6px; border:none;
                border-bottom:2px solid {Colors.TEXT_ORANGE};
                font-size:{FONT_SIZE_LABEL}px; font-weight:900;
                letter-spacing:1px;
            }}
        """)
        self._layout.addWidget(self.table, 1)

    def refresh(self):
        try:
            raw = self.backend.rows('events', limit=250)
        except Exception as e:
            print(f'[events] backend: {e}')
            raw = []

        normalized = []
        seen = set()
        duplicates = 0
        empty = 0
        for ev in raw:
            view = self._normalize(ev)
            if not self._meaningful(view):
                empty += 1
                continue
            fp = (
                view['time'], view['type'], view['source'], view['target'],
                view['proto'], view['detail'], view['severity'], view['classification'], view['process_name'], view['pid'],
            )
            if fp in seen:
                duplicates += 1
                continue
            seen.add(fp)
            normalized.append(view)

        self._events = sorted(normalized, key=priority_key)
        hidden = duplicates + empty
        self.dedupe_label.setText(
            f'{hidden} tekrar/boş gizlendi' if hidden else 'temiz akış'
        )
        self._render()

    def _render(self):
        if not hasattr(self, 'table'):
            return
        kind = self.kind_filter.currentData() if hasattr(self, 'kind_filter') else ''
        needle = self.search.text().strip().lower() if hasattr(self, 'search') else ''

        rows = []
        for item in self._events:
            if kind and item['group'] != kind:
                continue
            if needle:
                hay = ' '.join(str(item[k]) for k in (
                    'type', 'source', 'target', 'proto', 'detail', 'process_name', 'pid', 'classification_label', 'severity_label'
                )).lower()
                if needle not in hay:
                    continue
            rows.append(item)

        rows = rows[:150]
        self.table.setRowCount(len(rows))
        for row, ev in enumerate(rows):
            values = [
                ev['severity_label'], ev['classification_label'], ev['time'], ev['process_name'], ev['pid'], ev['type'], ev['source'], ev['target'],
                ev['proto'], ev['detail'],
            ]
            for col, text in enumerate(values):
                item = QTableWidgetItem(str(text))
                if col == 2:
                    item.setForeground(QBrush(QColor(Colors.TEXT_MUTED)))
                    f = item.font(); f.setFamily(FONT_MONO.split(',')[0].strip()); item.setFont(f)
                elif col == 5:
                    item.setForeground(QBrush(QColor(self._type_color(ev['type'], ev['group']))))
                    f = item.font(); f.setBold(True); item.setFont(f)
                elif col == 8:
                    item.setForeground(QBrush(QColor(Colors.TEXT_ORANGE)))
                    item.setTextAlignment(ALIGN_CENTER)
                else:
                    item.setForeground(QBrush(QColor(Colors.TEXT_PRIMARY)))
                self.table.setItem(row, col, item)
            self.table.setRowHeight(row, 31)

        self.info_label.setText(f'{len(rows)} gösteriliyor  ·  {len(self._events)} benzersiz')

    def _normalize(self, ev):
        meta = ev.get('metadata') or {}
        exts = meta.get('extensions') or {}
        dns_raw = ev.get('dns') or {}

        event_type = str(
            ev.get('event_type') or ev.get('action') or ev.get('kind')
            or ev.get('category') or '-'
        ).strip()
        et = event_type.lower()
        category = str(ev.get('category') or '').lower()
        kind = str(ev.get('kind') or '').lower()

        src_ip = ev.get('src_ip') or exts.get('network.src_ip') or ''
        src_port = ev.get('src_port') or exts.get('network.src_port') or ''
        dst_ip = ev.get('dest_ip') or exts.get('network.dest_ip') or ''
        dst_port = ev.get('dest_port') or exts.get('network.dest_port') or ''
        proto = str(ev.get('proto') or exts.get('network.proto') or '').upper()

        source = self._endpoint(src_ip, src_port)
        target = self._endpoint(dst_ip, dst_port)
        detail = fields(ev).get('action_outcome') or str(
            ev.get('signature') or ev.get('app_proto') or ev.get('cmd')
            or exts.get('host.cmd') or ev.get('file_path') or ev.get('path')
            or ev.get('operation') or ''
        ).strip()

        group = 'host' if category == 'host' or kind in ('process', 'file', 'host') else 'network'
        if et == 'alert' or ev.get('signature'):
            group = 'alert'

        is_dns = et == 'dns' or bool(
            exts.get('suricata.dns.rrname') or dns_raw.get('rrname')
            or ev.get('query') or ev.get('domain')
        )
        if is_dns:
            group = 'dns'
            event_type = 'dns'
            query = str(
                exts.get('suricata.dns.rrname')
                or exts.get('suricata.dns.query')
                or dns_raw.get('rrname')
                or ev.get('query') or ev.get('domain') or ''
            ).strip()
            rrtype = str(
                exts.get('suricata.dns.rrtype') or dns_raw.get('rrtype')
                or ev.get('rrtype') or ''
            ).strip()
            answers_raw = (
                exts.get('suricata.dns.answers') or dns_raw.get('answers')
                or ev.get('ips') or []
            )
            if isinstance(answers_raw, list):
                answers = ', '.join(
                    str(a.get('rdata')) if isinstance(a, dict) and a.get('rdata') else str(a)
                    for a in answers_raw
                )
            else:
                answers = str(answers_raw or '')
            rcode = str(
                exts.get('suricata.dns.rcode') or dns_raw.get('rcode')
                or ev.get('rcode') or ''
            ).strip()
            target = query or target
            detail = '  '.join(x for x in (rrtype, answers or rcode) if x)
            proto = proto or 'DNS'

        # Host/process events need a useful local target instead of a wall of dashes.
        if group == 'host':
            source = source or str(ev.get('uid') or exts.get('host.uid') or 'local')
            target = target or str(
                ev.get('cmd') or exts.get('host.cmd') or ev.get('file_path')
                or ev.get('path') or ev.get('exe') or ''
            )
            detail = detail or str(ev.get('parent_cmd') or exts.get('host.parent_cmd') or '')
            proto = proto or 'LOCAL'

        return {
            **fields(ev),
            'time': fields(ev)['time_label'],
            'type': event_type or '-',
            'source': source or '—',
            'target': target or '—',
            'proto': proto or '—',
            'detail': detail or '—',
            'group': group,
        }

    @staticmethod
    def _endpoint(ip, port):
        ip = str(ip or '').strip()
        port = str(port or '').strip()
        if not ip:
            return ''
        return f'{ip}:{port}' if port and port not in ('0', 'None') else ip

    @staticmethod
    def _meaningful(view):
        fields = (view['type'], view['source'], view['target'], view['detail'])
        return any(str(v).strip() not in ('', '-', '—', 'None', 'none') for v in fields)

    @staticmethod
    def _type_color(etype, group):
        if group == 'alert':
            return Colors.STATUS_CRIT
        if group == 'dns':
            return Colors.STATUS_INFO
        if group == 'host':
            return Colors.STATUS_WARN
        if str(etype).lower() in ('flow', 'quic', 'tls', 'http'):
            return Colors.ACCENT
        return Colors.TEXT_PRIMARY

    @staticmethod
    def _short_time(ts):
        if not ts:
            return '—'
        try:
            if isinstance(ts, (int, float)):
                return datetime.datetime.fromtimestamp(ts).strftime('%H:%M:%S')
            s = str(ts).replace('T', ' ')
            return s[11:19] if len(s) >= 19 else s[:8]
        except Exception:
            return str(ts)[:8]
