# -*- coding: utf-8 -*-
"""Satsuma Core KeyDesk ticket operations panel.

Ticket decisions are explicit operator actions. Detection/correlation engines
create and enrich tickets; they do not use this UI write path.
"""
try:
    from PyQt6.QtWidgets import (
        QLabel, QVBoxLayout, QHBoxLayout, QGridLayout, QFrame,
        QWidget, QTableWidget, QTableWidgetItem, QHeaderView,
        QAbstractItemView, QSizePolicy, QSplitter, QComboBox,
        QLineEdit, QPlainTextEdit, QPushButton, QMessageBox,
    )
    from PyQt6.QtCore import Qt
    from PyQt6.QtGui import QColor, QBrush
    QT_VERSION = 6
except ImportError:
    from PyQt5.QtWidgets import (
        QLabel, QVBoxLayout, QHBoxLayout, QGridLayout, QFrame,
        QWidget, QTableWidget, QTableWidgetItem, QHeaderView,
        QAbstractItemView, QSizePolicy, QSplitter, QComboBox,
        QLineEdit, QPlainTextEdit, QPushButton, QMessageBox,
    )
    from PyQt5.QtCore import Qt
    from PyQt5.QtGui import QColor, QBrush
    QT_VERSION = 5

import datetime
import json

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


USER_ROLE = Qt.ItemDataRole.UserRole if QT_VERSION == 6 else Qt.UserRole
ALIGN_CENTER = Qt.AlignmentFlag.AlignCenter if QT_VERSION == 6 else Qt.AlignCenter
HORIZONTAL = Qt.Orientation.Horizontal if QT_VERSION == 6 else Qt.Horizontal


STATUS_LABELS = {
    'open': 'AÇIK',
    'in_progress': 'BEKLET',
    'resolved': 'ÇÖZÜLDÜ',
    'false_positive': 'YANLIŞ ALARM',
    'closed': 'KAPALI',
    'ack': 'İNCELENİYOR',
}


class StatBox(QFrame):
    def __init__(self, title, value='0', color=None):
        super().__init__()
        self.setObjectName('ticket_stat_box')
        self._color = color or Colors.TEXT_PRIMARY
        self.setMinimumHeight(70)
        self.setSizePolicy(
            QSizePolicy.Policy.Expanding if QT_VERSION == 6 else QSizePolicy.Expanding,
            QSizePolicy.Policy.Fixed if QT_VERSION == 6 else QSizePolicy.Fixed,
        )
        self.setStyleSheet(f"""
            QFrame#ticket_stat_box {{
                background-color: {Colors.BG_SURFACE};
                border: 1px solid {Colors.BORDER_LIGHT};
                border-left: 4px solid {self._color};
                border-radius: 7px;
            }}
        """)

        layout = QVBoxLayout(self)
        layout.setContentsMargins(12, 8, 12, 8)
        layout.setSpacing(1)

        title_label = QLabel(title.upper())
        title_label.setStyleSheet(
            f'color:{Colors.TEXT_MUTED}; font-size:{FONT_SIZE_LABEL}px; '
            f'font-weight:700; letter-spacing:1px; background:transparent;'
        )
        layout.addWidget(title_label)

        self.value_label = QLabel(str(value))
        self.value_label.setStyleSheet(
            f'color:{self._color}; font-size:22px; font-weight:900; '
            f'background:transparent;'
        )
        layout.addWidget(self.value_label)

    def set_value(self, value):
        self.value_label.setText(str(value))


@register
class TicketsPanel(BasePanel):
    PANEL_ID = 'tickets'
    PANEL_TITLE = 'TICKETLAR'
    PANEL_ICON = '▣'
    PANEL_ORDER = 3
    PANEL_GROUP = 'admin'
    REFRESH_MS = 4000

    COLUMNS = [
        ('SEV', 48),
        ('ID', 112),
        ('BAŞLIK', 0),
        ('SINIFLAMA', 90),
        ('GÜVEN', 72),
        ('DURUM', 96),
        ('ADET', 58),
        ('İLK', 78),
        ('SON', 78),
        ('RULE/BULGU', 150),
    ]

    def _build(self):
        self._all_tickets = []
        self._visible_tickets = []
        self._selected_ticket_id = None

        title_row = QHBoxLayout()
        title_row.addWidget(self.make_title(f'{self.PANEL_ICON}  {self.PANEL_TITLE}'))
        title_row.addStretch()
        self.summary_label = QLabel('')
        self.summary_label.setStyleSheet(
            f'color:{Colors.TEXT_MUTED}; font-family:{FONT_MONO}; '
            f'font-size:{FONT_SIZE_SMALL}px; background:transparent;'
        )
        title_row.addWidget(self.summary_label)
        self._layout.addLayout(title_row)

        line = QFrame()
        line.setFixedHeight(2)
        line.setStyleSheet(f'background:{Colors.TEXT_ORANGE}; border:none;')
        self._layout.addWidget(line)

        self._build_stats()
        self._build_filters()
        self._build_workspace()

    def _build_stats(self):
        row = QHBoxLayout()
        row.setSpacing(10)
        self.box_total = StatBox('TOPLAM', '0', Colors.TEXT_PRIMARY)
        self.box_open = StatBox('AÇIK', '0', Colors.TEXT_ORANGE)
        self.box_wait = StatBox('BEKLET', '0', Colors.STATUS_INFO)
        self.box_resolved = StatBox('ÇÖZÜLDÜ', '0', Colors.STATUS_OK)
        self.box_l1 = StatBox('L1 KRİTİK', '0', Colors.S1)
        for w in (
            self.box_total, self.box_open, self.box_wait,
            self.box_resolved, self.box_l1,
        ):
            row.addWidget(w)
        self._layout.addLayout(row)

    def _build_filters(self):
        bar = QFrame()
        bar.setObjectName('ticket_filter_bar')
        bar.setStyleSheet(f"""
            QFrame#ticket_filter_bar {{
                background:{Colors.BG_SURFACE};
                border:1px solid {Colors.BORDER_LIGHT};
                border-radius:7px;
            }}
        """)
        layout = QHBoxLayout(bar)
        layout.setContentsMargins(10, 7, 10, 7)
        layout.setSpacing(8)

        status_lbl = QLabel('Durum')
        status_lbl.setStyleSheet(f'color:{Colors.TEXT_MUTED}; font-weight:700;')
        layout.addWidget(status_lbl)

        self.status_filter = QComboBox()
        self.status_filter.addItem('Tümü', '')
        self.status_filter.addItem('Açık', 'open')
        self.status_filter.addItem('Beklet', 'in_progress')
        self.status_filter.addItem('Çözüldü', 'resolved')
        self.status_filter.addItem('Yanlış alarm', 'false_positive')
        self.status_filter.addItem('Kapalı (eski)', 'closed')
        self.status_filter.currentIndexChanged.connect(self._render_table)
        layout.addWidget(self.status_filter)

        level_lbl = QLabel('Seviye')
        level_lbl.setStyleSheet(f'color:{Colors.TEXT_MUTED}; font-weight:700;')
        layout.addWidget(level_lbl)

        self.level_filter = QComboBox()
        self.level_filter.addItem('Tümü', 0)
        for n in range(1, 5):
            self.level_filter.addItem(f'L{n}', n)
        self.level_filter.currentIndexChanged.connect(self._render_table)
        layout.addWidget(self.level_filter)

        self.search = QLineEdit()
        self.search.setPlaceholderText('Ticket ara: başlık, takım, tip, ID...')
        self.search.textChanged.connect(self._render_table)
        layout.addWidget(self.search, 1)

        self.filter_count = QLabel('0 kayıt')
        self.filter_count.setStyleSheet(
            f'color:{Colors.TEXT_MUTED}; font-family:{FONT_MONO}; '
            f'font-size:{FONT_SIZE_SMALL}px;'
        )
        layout.addWidget(self.filter_count)
        self._layout.addWidget(bar)

    def _build_workspace(self):
        splitter = QSplitter(HORIZONTAL)
        splitter.setChildrenCollapsible(False)
        splitter.setHandleWidth(6)
        splitter.setStyleSheet(f'QSplitter::handle{{background:{Colors.BG_DEEP};}}')

        table_frame = QFrame()
        table_frame.setObjectName('section_card')
        table_layout = QVBoxLayout(table_frame)
        table_layout.setContentsMargins(0, 0, 0, 0)
        table_layout.setSpacing(0)
        self._build_table(table_layout)
        splitter.addWidget(table_frame)

        detail_frame = self._build_detail_panel()
        splitter.addWidget(detail_frame)
        splitter.setSizes([760, 460])
        self._layout.addWidget(splitter, 1)

    def _build_table(self, parent_layout):
        self.tickets_table = QTableWidget()
        self.tickets_table.setColumnCount(len(self.COLUMNS))
        self.tickets_table.setHorizontalHeaderLabels([c[0] for c in self.COLUMNS])
        self.tickets_table.verticalHeader().setVisible(False)
        self.tickets_table.setSelectionBehavior(
            QAbstractItemView.SelectionBehavior.SelectRows if QT_VERSION == 6
            else QAbstractItemView.SelectRows
        )
        self.tickets_table.setSelectionMode(
            QAbstractItemView.SelectionMode.SingleSelection if QT_VERSION == 6
            else QAbstractItemView.SingleSelection
        )
        self.tickets_table.setEditTriggers(
            QAbstractItemView.EditTrigger.NoEditTriggers if QT_VERSION == 6
            else QAbstractItemView.NoEditTriggers
        )
        self.tickets_table.setShowGrid(False)
        self.tickets_table.setAlternatingRowColors(False)
        self.tickets_table.cellClicked.connect(self._select_row)
        self.tickets_table.itemDoubleClicked.connect(
            lambda item: self._select_row(item.row(), item.column())
        )

        header = self.tickets_table.horizontalHeader()
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
                self.tickets_table.setColumnWidth(i, width)

        self.tickets_table.setStyleSheet(f"""
            QTableWidget {{
                background:{Colors.BG_SURFACE}; border:none;
                color:{Colors.TEXT_PRIMARY}; font-size:{FONT_SIZE_BODY}px;
            }}
            QTableWidget::item {{
                padding:7px 6px; border-bottom:1px solid {Colors.BORDER_SOFT};
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
        parent_layout.addWidget(self.tickets_table)

    def _build_detail_panel(self):
        frame = QFrame()
        frame.setObjectName('section_card')
        layout = QVBoxLayout(frame)
        layout.setContentsMargins(16, 14, 16, 14)
        layout.setSpacing(10)

        top = QHBoxLayout()
        self.detail_title = QLabel('Ticket seçin')
        self.detail_title.setWordWrap(True)
        self.detail_title.setStyleSheet(
            f'color:{Colors.TEXT_PRIMARY}; font-size:18px; font-weight:900;'
        )
        top.addWidget(self.detail_title, 1)
        self.detail_severity = QLabel('')
        self.detail_severity.setStyleSheet(
            f'color:{Colors.TEXT_MUTED}; font-family:{FONT_MONO}; font-weight:900;'
        )
        top.addWidget(self.detail_severity)
        layout.addLayout(top)

        self.detail_id = QLabel('')
        self.detail_id.setStyleSheet(
            f'color:{Colors.TEXT_MUTED}; font-family:{FONT_MONO}; '
            f'font-size:{FONT_SIZE_SMALL}px;'
        )
        layout.addWidget(self.detail_id)

        meta = QFrame()
        meta.setStyleSheet(f"""
            QFrame {{background:{Colors.BG_ELEVATED}; border:none; border-radius:6px;}}
        """)
        meta_grid = QGridLayout(meta)
        meta_grid.setContentsMargins(10, 8, 10, 8)
        meta_grid.setHorizontalSpacing(12)
        meta_grid.setVerticalSpacing(5)
        self.meta_labels = {}
        keys = [
            ('Durum', 'status'), ('Takım', 'team'),
            ('Öncelik', 'priority'), ('Güven', 'confidence'),
            ('Adet', 'occurrence_count'), ('Son', 'last_seen'),
        ]
        for idx, (caption, key) in enumerate(keys):
            r, c = divmod(idx, 2)
            cap = QLabel(caption.upper())
            cap.setStyleSheet(
                f'color:{Colors.TEXT_MUTED}; font-size:{FONT_SIZE_SMALL}px; '
                f'font-weight:700; letter-spacing:1px;'
            )
            val = QLabel('—')
            val.setStyleSheet(f'color:{Colors.TEXT_PRIMARY}; font-weight:700;')
            meta_grid.addWidget(cap, r * 2, c)
            meta_grid.addWidget(val, r * 2 + 1, c)
            self.meta_labels[key] = val
        layout.addWidget(meta)

        desc_head = QLabel('AÇIKLAMA')
        desc_head.setStyleSheet(
            f'color:{Colors.TEXT_ORANGE}; font-size:{FONT_SIZE_LABEL}px; '
            f'font-weight:900; letter-spacing:1px;'
        )
        layout.addWidget(desc_head)
        self.description = QLabel('Ticket seçildiğinde açıklama burada görünür.')
        self.description.setWordWrap(True)
        self.description.setStyleSheet(f'color:{Colors.TEXT_SECONDARY};')
        layout.addWidget(self.description)

        ev_head = QLabel('EVIDENCE')
        ev_head.setStyleSheet(
            f'color:{Colors.TEXT_ORANGE}; font-size:{FONT_SIZE_LABEL}px; '
            f'font-weight:900; letter-spacing:1px;'
        )
        layout.addWidget(ev_head)

        self.evidence = QPlainTextEdit()
        self.evidence.setReadOnly(True)
        self.evidence.setPlaceholderText('Ticket seçildiğinde kanıt burada görünür.')
        self.evidence.setStyleSheet(f"""
            QPlainTextEdit {{
                background:{Colors.BG_BASE}; color:{Colors.TEXT_PRIMARY};
                border:1px solid {Colors.BORDER_LIGHT}; border-radius:6px;
                font-family:{FONT_MONO}; font-size:{FONT_SIZE_SMALL + 1}px;
                padding:8px;
            }}
        """)
        layout.addWidget(self.evidence, 1)

        action_head = QLabel('OPERATÖR KARARI')
        action_head.setStyleSheet(
            f'color:{Colors.TEXT_ORANGE}; font-size:{FONT_SIZE_LABEL}px; '
            f'font-weight:900; letter-spacing:1px;'
        )
        layout.addWidget(action_head)

        self.operator_note = QLineEdit()
        self.operator_note.setPlaceholderText('Operatör notu (isteğe bağlı)')
        self.operator_note.setEnabled(True)
        layout.addWidget(self.operator_note)

        actions = QHBoxLayout()
        actions.setSpacing(8)
        self.btn_resolved = QPushButton('ÇÖZÜLDÜ')
        self.btn_wait = QPushButton('BEKLET')
        self.btn_fp = QPushButton('YANLIŞ ALARM')
        self.btn_resolved.setStyleSheet(
            f'QPushButton{{color:{Colors.STATUS_OK}; border:1px solid {Colors.STATUS_OK};}}'
        )
        self.btn_wait.setStyleSheet(
            f'QPushButton{{color:{Colors.STATUS_INFO}; border:1px solid {Colors.STATUS_INFO};}}'
        )
        self.btn_fp.setStyleSheet(
            f'QPushButton{{color:{Colors.STATUS_WARN}; border:1px solid {Colors.STATUS_WARN};}}'
        )
        for button, status in (
            (self.btn_resolved, 'resolved'),
            (self.btn_wait, 'in_progress'),
            (self.btn_fp, 'false_positive'),
        ):
            button.clicked.connect(lambda _, s=status: self._request_status_change(s))
            actions.addWidget(button)
        layout.addLayout(actions)

        self.action_info = QLabel(
            'KeyDesk operatör karar kanalı kontrol ediliyor…'
        )
        self.action_info.setWordWrap(True)
        self.action_info.setStyleSheet(
            f'color:{Colors.TEXT_MUTED}; font-size:{FONT_SIZE_SMALL}px;'
        )
        layout.addWidget(self.action_info)
        self._update_action_availability()
        return frame

    def _update_action_availability(self):
        try:
            available = bool(self.backend.ticket_actions_available())
        except Exception:
            available = False
        for button in (self.btn_resolved, self.btn_wait, self.btn_fp):
            button.setEnabled(available)
        self.operator_note.setEnabled(available)
        if available:
            self.action_info.setText('Operatör aksiyon kanalı bağlı.')
        else:
            self.action_info.setText('Operatör aksiyon kanalı kullanılamıyor.')

    def refresh(self):
        try:
            stats = self.backend.tickets_stats()
        except Exception as e:
            print(f'[tickets] stats: {e}')
            stats = {'total': 0, 'by_status': {}, 'by_level': {}}

        by_status = stats.get('by_status') or {}
        by_level = stats.get('by_level') or {}
        self.box_total.set_value(stats.get('total', 0))
        self.box_open.set_value(by_status.get('open', 0))
        self.box_wait.set_value(by_status.get('in_progress', 0))
        self.box_resolved.set_value(by_status.get('resolved', 0))
        self.box_l1.set_value(by_level.get(1, 0))

        try:
            self._all_tickets = self.backend.tickets(limit=300)
        except Exception as e:
            print(f'[tickets] list: {e}')
            self._all_tickets = []

        self.summary_label.setText(
            f'{stats.get("total", 0)} ticket  ·  '
            f'{by_status.get("open", 0) + by_status.get("in_progress", 0)} aktif'
        )
        self._render_table()
        self._update_action_availability()

    def _render_table(self):
        if not hasattr(self, 'tickets_table'):
            return
        status_filter = self.status_filter.currentData() if hasattr(self, 'status_filter') else ''
        level_filter = self.level_filter.currentData() if hasattr(self, 'level_filter') else 0
        needle = self.search.text().strip().lower() if hasattr(self, 'search') else ''

        visible = []
        for t in self._all_tickets:
            if status_filter and t.get('status') != status_filter:
                continue
            if level_filter:
                try:
                    if int(t.get('ticket_level') or 0) != int(level_filter):
                        continue
                except (TypeError, ValueError):
                    continue
            if needle:
                haystack = ' '.join(str(t.get(k, '')) for k in (
                    'ticket_id', 'title', 'description', 'type', 'team',
                    'status', 'severity', 'priority', 'confidence',
                )).lower()
                if needle not in haystack:
                    continue
            visible.append(t)

        self._visible_tickets = visible
        self.filter_count.setText(f'{len(visible)} kayıt')
        self.tickets_table.setRowCount(len(visible))

        restore_row = None
        for row, t in enumerate(visible):
            level = t.get('ticket_level', '-')
            raw_status = str(t.get('status', '')).lower()
            status = STATUS_LABELS.get(raw_status, raw_status.replace('_', ' ').upper() or '—')
            values = [
                f'L{level}' if level not in (None, '', '-') else '—',
                str(t.get('ticket_id') or '—'),
                str(t.get('title') or t.get('type') or '—'),
                str(t.get('classification') or t.get('type') or '—'),
                str(t.get('confidence') or '—'),
                status,
                str(t.get('occurrence_count') or 0),
                self._short_time(t.get('first_seen')),
                self._short_time(t.get('last_seen')),
                str(t.get('related_rule') or t.get('related_finding') or '—'),
            ]
            for col, text in enumerate(values):
                item = QTableWidgetItem(text)
                if col == 0:
                    item.setForeground(QBrush(self._level_color(level)))
                    item.setTextAlignment(ALIGN_CENTER)
                    f = item.font(); f.setBold(True); item.setFont(f)
                elif col == 5:
                    item.setForeground(QBrush(self._status_color(raw_status)))
                    f = item.font(); f.setBold(True); item.setFont(f)
                elif col in (4, 6, 7, 8):
                    item.setTextAlignment(ALIGN_CENTER)
                if col == 2:
                    item.setData(USER_ROLE, t.get('ticket_id', ''))
                self.tickets_table.setItem(row, col, item)
            self.tickets_table.setRowHeight(row, 34)
            if t.get('ticket_id') == self._selected_ticket_id:
                restore_row = row

        if restore_row is not None:
            self.tickets_table.selectRow(restore_row)
            self._show_ticket(self._visible_tickets[restore_row])
        elif visible and self._selected_ticket_id is None:
            self.tickets_table.selectRow(0)
            self._show_ticket(visible[0])
        elif not visible:
            self._clear_detail()

    def _select_row(self, row, _col=0):
        if 0 <= row < len(self._visible_tickets):
            self._show_ticket(self._visible_tickets[row])

    def _show_ticket(self, ticket):
        self._selected_ticket_id = ticket.get('ticket_id')
        self.detail_title.setText(str(ticket.get('title') or ticket.get('type') or 'Ticket'))
        level = ticket.get('ticket_level', '?')
        self.detail_severity.setText(
            f'L{level}  {str(ticket.get("severity") or "").upper()}'
        )
        self.detail_severity.setStyleSheet(
            f'color:{self._level_color(level).name()}; font-family:{FONT_MONO}; font-weight:900;'
        )
        self.detail_id.setText(str(ticket.get('ticket_id') or ''))

        meta_values = {
            'status': STATUS_LABELS.get(
                str(ticket.get('status') or '').lower(),
                str(ticket.get('status') or '—').upper(),
            ),
            'team': ticket.get('team') or '—',
            'priority': str(ticket.get('priority') or '—').upper(),
            'confidence': str(ticket.get('confidence') or '—').upper(),
            'occurrence_count': ticket.get('occurrence_count') or 0,
            'last_seen': self._full_time(ticket.get('last_seen')),
        }
        for key, value in meta_values.items():
            self.meta_labels[key].setText(str(value))

        desc = str(ticket.get('description') or 'Açıklama yok.')
        self.description.setText(desc)

        evidence = ticket.get('evidence') or '{}'
        try:
            obj = json.loads(evidence) if isinstance(evidence, str) else evidence
            text = json.dumps(obj, indent=2, ensure_ascii=False)
        except Exception:
            text = str(evidence)
        self.evidence.setPlainText(text)

    def _clear_detail(self):
        self._selected_ticket_id = None
        self.detail_title.setText('Ticket seçin')
        self.detail_severity.setText('')
        self.detail_id.setText('')
        for label in self.meta_labels.values():
            label.setText('—')
        self.description.setText('Filtreye uygun ticket bulunamadı.')
        self.evidence.clear()

    def _request_status_change(self, status):
        if not self._selected_ticket_id:
            return

        try:
            available = bool(self.backend.ticket_actions_available())
        except Exception:
            available = False
        if not available:
            QMessageBox.warning(
                self, 'KeyDesk', 'Operatör aksiyon kanalı şu anda kullanılamıyor.'
            )
            return

        label = STATUS_LABELS.get(status, status)
        yes = QMessageBox.StandardButton.Yes if QT_VERSION == 6 else QMessageBox.Yes
        no = QMessageBox.StandardButton.No if QT_VERSION == 6 else QMessageBox.No
        answer = QMessageBox.question(
            self,
            'KeyDesk operatör kararı',
            f'{self._selected_ticket_id}\n\nDurum “{label}” olarak güncellensin mi?',
            yes | no,
            no,
        )
        if answer != yes:
            return

        note = self.operator_note.text().strip()
        result = self.backend.update_ticket_status(
            self._selected_ticket_id, status, note
        )
        if not result or not result.get('ok'):
            error = (result or {}).get('error', 'bilinmeyen hata')
            QMessageBox.critical(self, 'KeyDesk', f'Ticket güncellenemedi:\n{error}')
            return

        self.operator_note.clear()
        QMessageBox.information(
            self, 'KeyDesk', f'{self._selected_ticket_id} → {label}'
        )
        self.refresh()

    @staticmethod
    def _level_color(level):
        try:
            lvl = int(level)
        except (TypeError, ValueError):
            return QColor(Colors.TEXT_PRIMARY)
        return {
            1: QColor(Colors.S1),
            2: QColor(Colors.S2),
            3: QColor(Colors.S3),
            4: QColor(Colors.S4),
        }.get(lvl, QColor(Colors.TEXT_PRIMARY))

    @staticmethod
    def _status_color(status):
        s = str(status).lower()
        if s == 'open':
            return QColor(Colors.STATUS_CRIT)
        if s == 'in_progress':
            return QColor(Colors.STATUS_INFO)
        if s in ('resolved', 'closed'):
            return QColor(Colors.STATUS_OK)
        if s == 'false_positive':
            return QColor(Colors.STATUS_WARN)
        return QColor(Colors.TEXT_SECONDARY)

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

    @staticmethod
    def _full_time(ts):
        if not ts:
            return '—'
        try:
            if isinstance(ts, (int, float)):
                return datetime.datetime.fromtimestamp(ts).strftime('%d.%m.%Y %H:%M:%S')
            return str(ts).replace('T', ' ')[:19]
        except Exception:
            return str(ts)
