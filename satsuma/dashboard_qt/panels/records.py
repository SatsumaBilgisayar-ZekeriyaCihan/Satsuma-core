"""Records: every kind of record in the database, explained in plain Turkish.

User request 2026-11-04: "whatever is in the database must be shown to me
in a way I understand". The left list holds every record kind the reader
finds in both databases (record_catalog), with its count in the chosen
window; kinds missing from the catalog appear as "Tanımsız tür", never
hidden. Selecting a kind shows what it is, why it matters and its newest
records as sentences; the masked raw record opens on demand.

Kayıtlar: veritabanındaki her kayıt türü, sade Türkçe açıklamasıyla.
Kullanıcı isteği 2026-11-04: "veritabanında ne varsa bana anlayacağım
şekilde göstermeli". Soldaki liste okuyucunun iki veritabanında bulduğu her
kayıt türünü seçilen zaman aralığındaki sayısıyla gösterir; katalogda
olmayan türler gizlenmez, "Tanımsız tür" olarak görünür. Bir tür seçilince
ne olduğu, neden önemli olduğu ve en yeni kayıtları cümle olarak görünür;
gizli alanları maskeli ham kayıt istenince açılır.
"""
import datetime
import json

try:
    from PyQt6.QtWidgets import (QLabel, QHBoxLayout, QVBoxLayout, QListWidget, QListWidgetItem, QTableWidget,
                                 QTableWidgetItem, QHeaderView, QPlainTextEdit, QPushButton, QFrame, QAbstractItemView)
    from PyQt6.QtCore import Qt
    ROLE = Qt.ItemDataRole.UserRole
except ImportError:
    from PyQt5.QtWidgets import (QLabel, QHBoxLayout, QVBoxLayout, QListWidget, QListWidgetItem, QTableWidget,
                                 QTableWidgetItem, QHeaderView, QPlainTextEdit, QPushButton, QFrame, QAbstractItemView)
    from PyQt5.QtCore import Qt
    ROLE = Qt.UserRole

from .base import BasePanel
from . import register
from ..stable_widgets import StableComboBox as QComboBox
from ..style.theme import Colors

WINDOWS = (('Son 1 saat', 1), ('Son 24 saat', 24), ('Son 7 gün', 168))
TONES = {'ok': Colors.STATUS_OK, 'warn': Colors.STATUS_WARN, 'crit': Colors.STATUS_CRIT}


def clock(value):
    try:
        return datetime.datetime.fromtimestamp(float(value)).strftime('%d.%m %H:%M:%S')
    except (TypeError, ValueError, OverflowError, OSError):
        return str(value or '')


def count_text(value):
    return f'{int(value):,}'.replace(',', '.')


@register
class RecordsPanel(BasePanel):
    PANEL_ID = 'records'
    PANEL_TITLE = 'Kayıtlar'
    PANEL_ORDER = 3
    PANEL_GROUP = 'security'
    REFRESH_MS = 10000

    def _build(self):
        self._overview, self._selected, self._page = None, None, None
        head = QHBoxLayout()
        text = QVBoxLayout()
        text.addWidget(self.make_title('Kayıtlar: veritabanında ne var?'))
        self.total = self.make_subtitle('Kayıtlar okunuyor…')
        text.addWidget(self.total)
        head.addLayout(text, 1)
        self.window_box = QComboBox()
        for name, hours in WINDOWS:
            self.window_box.addItem(name, hours)
        self.window_box.setCurrentIndex(1)
        self.window_box.currentIndexChanged.connect(lambda *_: self.refresh(force=True))
        head.addWidget(self.window_box)
        self._layout.addLayout(head)

        body = QHBoxLayout()
        self.kinds = QListWidget()
        self.kinds.setMinimumWidth(300)
        self.kinds.setMaximumWidth(400)
        self.kinds.currentItemChanged.connect(self._picked)
        body.addWidget(self.kinds)

        right = QVBoxLayout()
        card = QFrame()
        card.setObjectName('securityCard')
        card_layout = QVBoxLayout(card)
        self.kind_name = QLabel('Bir kayıt türü seçin')
        self.kind_name.setStyleSheet(f'font-size:22px;font-weight:700;color:{Colors.ACCENT};')
        card_layout.addWidget(self.kind_name)
        self.what = QLabel('')
        self.what.setWordWrap(True)
        card_layout.addWidget(self.what)
        self.why = QLabel('')
        self.why.setWordWrap(True)
        self.why.setStyleSheet(f'color:{Colors.TEXT_SECONDARY};')
        card_layout.addWidget(self.why)
        right.addWidget(card)

        self.table = QTableWidget(0, 4)
        self.table.setHorizontalHeaderLabels(['Zaman', 'Ne oldu', 'Ayrıntı', 'Sonuç'])
        self.table.verticalHeader().hide()
        self.table.setShowGrid(False)
        self.table.setWordWrap(True)
        self.table.setEditTriggers(QAbstractItemView.EditTrigger.NoEditTriggers if hasattr(QAbstractItemView, 'EditTrigger') else QAbstractItemView.NoEditTriggers)
        self.table.setSelectionBehavior(QAbstractItemView.SelectionBehavior.SelectRows if hasattr(QAbstractItemView, 'SelectionBehavior') else QAbstractItemView.SelectRows)
        header = self.table.horizontalHeader()
        stretch = QHeaderView.ResizeMode.Stretch if hasattr(QHeaderView, 'ResizeMode') else QHeaderView.Stretch
        header.setSectionResizeMode(1, stretch)
        header.setSectionResizeMode(2, stretch)
        self.table.setColumnWidth(0, 120)
        self.table.setColumnWidth(3, 200)
        self.table.currentCellChanged.connect(lambda *_: self._show_raw())
        right.addWidget(self.table, 1)

        raw_row = QHBoxLayout()
        self.raw_button = QPushButton('Ham kaydı göster')
        self.raw_button.setCheckable(True)
        self.raw_button.toggled.connect(lambda on: (self.raw.setVisible(on), self._show_raw()))
        raw_row.addWidget(self.raw_button)
        self.more = QPushButton('Daha eski kayıtlar')
        self.more.clicked.connect(self._older)
        raw_row.addWidget(self.more)
        raw_row.addStretch()
        right.addLayout(raw_row)
        self.raw = QPlainTextEdit()
        self.raw.setReadOnly(True)
        self.raw.setMaximumHeight(180)
        self.raw.hide()
        right.addWidget(self.raw)
        body.addLayout(right, 1)
        self._layout.addLayout(body, 1)
        self.offset = 0

    def _hours(self):
        return self.window_box.currentData() or 24

    def refresh(self, force=False):
        try:
            data = self.backend.call('records_overview', hours=self._hours())
        except Exception as exc:
            self.total.setText('Kayıtlar okunamadı: ' + str(exc)[:200])
            return
        if data != self._overview or force:
            self._overview = data
            self._fill_kinds(data)
        if self._selected:
            self._load_page()

    def _fill_kinds(self, data):
        groups = {g['id']: g['name'] for g in data.get('groups', [])}
        unknown = data.get('unknown_kinds') or []
        self.total.setText(f"{self.window_box.currentText()}: {count_text(data.get('total', 0))} kayıt, "
                           f"{len(data.get('kinds', []))} tür" + (f" · {len(unknown)} tanımsız tür" if unknown else '')
                           + (' · Kısmi okuma: ' + ', '.join(data['errors']) if data.get('errors') else ''))
        current = self._selected
        self.kinds.blockSignals(True)
        self.kinds.clear()
        last_group = None
        for kind in data.get('kinds', []):
            if kind.get('group') != last_group:
                last_group = kind.get('group')
                header = QListWidgetItem(groups.get(last_group, last_group or '').upper())
                header.setFlags(Qt.ItemFlag.NoItemFlags if hasattr(Qt, 'ItemFlag') else Qt.NoItemFlags)
                header.setForeground(self._color(Colors.TEXT_MUTED))
                self.kinds.addItem(header)
            item = QListWidgetItem(f"{kind['name']}\n{kind.get('short', '')}  ·  {count_text(kind.get('count', 0))}")
            item.setData(ROLE, {'kind': kind['kind'], 'db': kind.get('db') or 'core'})
            if not kind.get('known'):
                item.setForeground(self._color(Colors.STATUS_WARN))
            self.kinds.addItem(item)
            if current and item.data(ROLE) == current:
                self.kinds.setCurrentItem(item)
        self.kinds.blockSignals(False)
        if not current:
            for row in range(self.kinds.count()):
                if self.kinds.item(row).data(ROLE):
                    self.kinds.setCurrentRow(row)
                    break

    @staticmethod
    def _color(hex_value):
        try:
            from PyQt6.QtGui import QColor
        except ImportError:
            from PyQt5.QtGui import QColor
        return QColor(hex_value)

    def _picked(self, item, _previous=None):
        target = item.data(ROLE) if item else None
        if not target:
            return
        self._selected, self.offset = target, 0
        self._load_page()

    def _older(self):
        if self._page and self._page.get('has_more'):
            self.offset += self._page.get('limit', 50)
            self._load_page()

    def _load_page(self):
        try:
            page = self.backend.call('records_explained', kind=self._selected['kind'], database=self._selected['db'],
                                     offset=self.offset, limit=50)
        except Exception as exc:
            self.what.setText('Kayıtlar yükleniyor… ' + str(exc)[:120])
            return
        if page == self._page:
            return
        self._page = page
        self.kind_name.setText(f"{page.get('name')}  ·  {count_text(page.get('count', 0))}")
        self.what.setText('Bu ne? ' + str(page.get('what', '')))
        self.why.setText('Neden önemli? ' + str(page.get('why', '')))
        items = page.get('items', [])
        self.table.setRowCount(len(items))
        for row, record in enumerate(items):
            values = (clock(record.get('time') or record.get('created')), record.get('text', ''), record.get('detail', ''), record.get('chip', ''))
            for column, value in enumerate(values):
                cell = QTableWidgetItem(str(value))
                cell.setToolTip(str(value))
                if column == 3 and record.get('tone') in TONES:
                    cell.setForeground(self._color(TONES[record['tone']]))
                self.table.setItem(row, column, cell)
        self.table.resizeRowsToContents()
        self.more.setEnabled(bool(page.get('has_more')))
        self._show_raw()

    def _show_raw(self):
        if not self.raw.isVisible() or not self._page:
            return
        row = self.table.currentRow()
        items = self._page.get('items', [])
        if 0 <= row < len(items):
            self.raw.setPlainText(json.dumps(items[row].get('raw'), ensure_ascii=False, indent=2, default=str)[:20000])
        else:
            self.raw.setPlainText('Bir kayıt seçin.')
