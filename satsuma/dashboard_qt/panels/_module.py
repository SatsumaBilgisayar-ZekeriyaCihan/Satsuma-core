# -*- coding: utf-8 -*-
"""Reusable read-only module panel for the final dashboard.

Every panel in this module obtains data exclusively through
``Backend.call(...)`` (the Unix socket reader).  The GUI never opens core.db
or host.db directly.  JSON dumps are not the primary view; they are available
only through the generic "raw" field if an operator explicitly expands it.
"""
from __future__ import annotations

import datetime
from copy import deepcopy
import json

try:
    from PyQt6.QtWidgets import (
        QLabel, QVBoxLayout, QHBoxLayout, QTableWidget, QTableWidgetItem,
        QHeaderView, QPushButton, QComboBox, QLineEdit, QPlainTextEdit,
    )
    from PyQt6.QtCore import Qt
    QT_VERSION = 6
except ImportError:
    from PyQt5.QtWidgets import (
        QLabel, QVBoxLayout, QHBoxLayout, QTableWidget, QTableWidgetItem,
        QHeaderView, QPushButton, QComboBox, QLineEdit, QPlainTextEdit,
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
    from ..style.theme import Colors, FONT_UI, FONT_MONO
except ImportError:
    from style.theme import Colors, FONT_UI, FONT_MONO


from ...status_view import label, timestamp
from ..stable_widgets import StableComboBox as QComboBox

def _fmt(value):
    if value is None or value == '':return 'Kayıtta belirtilmemiş'
    if value is True:return 'Evet'
    if value is False:return 'Hayır'
    if isinstance(value,list):
        return ', '.join(str(x) for x in value) if all(isinstance(x,(str,int,float)) for x in value) and value else 'Teknik ayrıntılarda'
    if isinstance(value,dict):return 'Teknik ayrıntılarda' if value else 'Kayıtta belirtilmemiş'
    return label(value)


class ReadOnlyModulePanel(BasePanel):
    METHOD = None
    KEY = 'items'
    COLUMNS = ()
    PARAMS = {}
    FILTERS = ()

    def _build(self):
        """2.2.47 design: title, one-line summary card, quiet table, readable detail beside it.

        2.2.47 tasarımı: başlık, özet kartı, sade tablo ve yanında okunur ayrıntı.
        """
        if not self.METHOD:
            raise ValueError(f'{self.__class__.__name__}: METHOD tanimli degil')
        from ..qt import QFrame, QSplitter, Qt as _Qt, enum
        self._layout.addWidget(self.make_title(self.PANEL_TITLE))
        if self.PANEL_SUBTITLE:
            self._layout.addWidget(self.make_subtitle(self.PANEL_SUBTITLE))
        filter_row = QHBoxLayout()
        filter_row.setSpacing(10)
        self._filter_widgets = {}
        for field, caption_text, values in self.FILTERS:
            caption = QLabel(caption_text)
            caption.setObjectName('secondary')
            filter_row.addWidget(caption)
            if values:
                widget = QComboBox()
                widget.addItem('Tümü', '')
                for item in values:
                    widget.addItem(str(item), str(item))
            else:
                widget = QLineEdit()
                widget.setPlaceholderText('Ara')
                widget.setClearButtonEnabled(True)
            widget.currentTextChanged.connect(self.refresh) if isinstance(widget, QComboBox) else widget.returnPressed.connect(self.refresh)
            self._filter_widgets[field] = widget
            filter_row.addWidget(widget)
        refresh_btn = QPushButton('Yenile')
        refresh_btn.setObjectName('quiet')
        refresh_btn.clicked.connect(self.refresh)
        if self.FILTERS:
            filter_row.addStretch()
            filter_row.addWidget(refresh_btn)
            self._layout.addLayout(filter_row)

        self.summary_card = QFrame()
        self.summary_card.setObjectName('summaryCard')
        summary = QHBoxLayout(self.summary_card)
        summary.setContentsMargins(18, 8, 10, 8)
        self.status = QLabel('Veri bekleniyor')
        self.status.setWordWrap(True)
        self.status.setObjectName('summaryText')
        self.status.setTextInteractionFlags(enum(_Qt, 'TextInteractionFlag', 'TextSelectableByMouse'))
        summary.addWidget(self.status, 1)
        if not self.FILTERS:
            # 2.2.47: no row of its own; the table keeps the height.
            summary.addWidget(refresh_btn)
        self._layout.addWidget(self.summary_card)

        self.table = QTableWidget()
        self.table.setObjectName('dataTable')
        self.table.setColumnCount(len(self.COLUMNS))
        self.table.setHorizontalHeaderLabels([c[0] for c in self.COLUMNS])
        self.table.setEditTriggers(QTableWidget.EditTrigger.NoEditTriggers if QT_VERSION == 6 else QTableWidget.NoEditTriggers)
        self._last_render = None
        self.table.setAlternatingRowColors(False)
        self.table.setShowGrid(False)
        self.table.setWordWrap(False)
        self.table.verticalHeader().setVisible(False)
        self.table.verticalHeader().setDefaultSectionSize(38)
        self.table.horizontalHeader().setStretchLastSection(True)
        if QT_VERSION == 6:
            self.table.setSelectionBehavior(QTableWidget.SelectionBehavior.SelectRows)
        else:
            self.table.setSelectionBehavior(QTableWidget.SelectRows)
        self._rows=[]
        detail = QFrame()
        detail.setObjectName('detailCard')
        detail.setMinimumWidth(300)
        box = QVBoxLayout(detail)
        box.setContentsMargins(18, 16, 18, 16)
        box.setSpacing(8)
        heading = QLabel('Seçili kayıt')
        heading.setObjectName('fieldLabel')
        box.addWidget(heading)
        self.detail_view = QLabel('Ayrıntısını görmek için tablodan bir kayıt seçin.')
        self.detail_view.setObjectName('body')
        self.detail_view.setWordWrap(True)
        self.detail_view.setTextFormat(enum(_Qt, 'TextFormat', 'RichText'))
        self.detail_view.setTextInteractionFlags(enum(_Qt, 'TextInteractionFlag', 'TextSelectableByMouse'))
        self.detail_view.setAlignment(enum(_Qt, 'AlignmentFlag', 'AlignTop'))
        # 2.2.47: a long record (ClamAV files, warning lines) scrolls instead of being cut off.
        from ..qt import QScrollArea
        detail_scroll = QScrollArea()
        detail_scroll.setObjectName('detailScroll')
        detail_scroll.setWidgetResizable(True)
        detail_scroll.setFrameShape(QFrame.Shape.NoFrame if hasattr(QFrame, 'Shape') else QFrame.NoFrame)
        detail_scroll.setWidget(self.detail_view)
        box.addWidget(detail_scroll, 1)
        details_button=QPushButton('Teknik ayrıntıları göster')
        details_button.setObjectName('quiet')
        self.details=QPlainTextEdit();self.details.setReadOnly(True);self.details.setObjectName('technical');self.details.hide()
        def toggle():
            self.details.setVisible(self.details.isHidden())
            details_button.setText('Teknik ayrıntıları gizle' if self.details.isVisible() else 'Teknik ayrıntıları göster')
        details_button.clicked.connect(toggle)
        box.addWidget(details_button)
        box.addWidget(self.details, 2)
        split = QSplitter(enum(_Qt, 'Orientation', 'Horizontal'))
        split.setObjectName('dataSplit')
        split.setChildrenCollapsible(False)
        split.addWidget(self.table)
        split.addWidget(detail)
        split.setStretchFactor(0, 3)
        split.setStretchFactor(1, 2)
        self.table.itemSelectionChanged.connect(self._show_details)
        self._layout.addWidget(split, 1)

    def _show_details(self):
        import html
        row=self.table.currentRow()
        if not 0<=row<len(self._rows):
            self.details.setPlainText('Bir kayıt seçin.')
            self.detail_view.setText('Ayrıntısını görmek için tablodan bir kayıt seçin.')
            return
        item=self._rows[row]
        self.details.setPlainText(json.dumps(item,ensure_ascii=False,indent=2,default=str))
        lines=[]
        for caption,key in self.COLUMNS:
            value=item.get(key)
            is_time=key in ('timestamp','created','added_at','expires_at','last_run','last_successful_event','last_verification','last_successful_update','last_attempt')
            text=timestamp(value) if is_time else _fmt(value)
            lines.append('<p style="margin:0 0 8px 0"><span style="color:#8a8a8a;font-size:11px">%s</span><br>%s</p>'
                         % (html.escape(str(caption)), html.escape(str(text))))
        self.detail_view.setText(''.join(lines))

    @staticmethod
    def _row_key(item):
        for key in ('record_key','finding_id','_group_id','id','_id','_record_id','serial','rule_id','ip','name','field'):
            if item.get(key) is not None:return (key,str(item[key]))
        return (str(item.get('timestamp')),str(item.get('action')),str(item.get('target')))


    def _rows_from(self, data):
        if isinstance(data, list):
            return data
        if not isinstance(data, dict):
            return []
        value = data.get(self.KEY)
        if isinstance(value, list):
            return value
        if isinstance(data.get('items'), list):
            return data['items']
        # Flatten one level for status-style dictionaries.
        return [data]

    def _params(self):
        params = dict(self.PARAMS)
        for field, widget in getattr(self, '_filter_widgets', {}).items():
            value = widget.currentData() if isinstance(widget, QComboBox) else widget.text()
            if value:
                params[field] = value
        return params

    def refresh(self, *args):
        try:
            data = self.backend.call(self.METHOD, **self._params())
        except Exception as exc:
            self.status.setText(f'HATA: {exc}')
            self._last_render = None
            return
        self._render_data(data)

    def _render_data(self, data):
        filters=tuple((name,widget.currentData() if isinstance(widget,QComboBox) else widget.text()) for name,widget in self._filter_widgets.items())
        render_key = (self._params(), data, filters)
        if render_key == self._last_render:
            return
        self._last_render = deepcopy(render_key)
        rows = self._rows_from(data)
        old_row=self.table.currentRow()
        selected=self._row_key(self._rows[old_row]) if 0<=old_row<len(self._rows) else None
        vbar=self.table.verticalScrollBar();hbar=self.table.horizontalScrollBar()
        vertical,horizontal=vbar.value(),hbar.value()
        top=self.table.rowAt(0)
        top_key=self._row_key(self._rows[top]) if 0<=top<len(self._rows) else None
        self._rows=[item if isinstance(item,dict) else {'value':item} for item in rows]
        self.table.blockSignals(True);self.table.setUpdatesEnabled(False)
        try:
            self.table.setRowCount(len(rows));self.table.clearSelection();self.table.setCurrentCell(-1,-1)
            for r,item in enumerate(self._rows):
                for c,(_,key) in enumerate(self.COLUMNS):
                    value=item.get(key)
                    is_time=key in ('timestamp','created','added_at','expires_at','last_run','last_successful_event','last_verification','last_successful_update','last_attempt')
                    cell=QTableWidgetItem(timestamp(value) if is_time else ('Hata kaydı yok' if key=='last_error' and not value else _fmt(value)))
                    self.table.setItem(r,c,cell)
                if selected and self._row_key(item)==selected:self.table.selectRow(r)
            if not getattr(self,'_columns_sized',False) and rows:
                self.table.resizeColumnsToContents();self._columns_sized=True
            # Restore viewport by record identity if rows were inserted above it.
            anchor=next((r for r,item in enumerate(self._rows) if top_key and self._row_key(item)==top_key),None)
            if anchor is not None:
                scroll_mode=self.table.verticalScrollMode()
                if scroll_mode==(self.table.ScrollMode.ScrollPerItem if hasattr(self.table,'ScrollMode') else self.table.ScrollPerItem):vertical=anchor
            vbar.setValue(vertical);hbar.setValue(horizontal)
        finally:
            self.table.blockSignals(False);self.table.setUpdatesEnabled(True)
        self._show_details()
        state = data.get('data_state') if isinstance(data, dict) else 'OK'
        count = data.get('count') if isinstance(data, dict) else len(rows)
        state_text={'OK':'Veri alındı','UNKNOWN':'Veri alınamadı','NO_DATA':'Henüz veri yok','STALE':'Veri eski'}.get(state,_fmt(state))
        self.status.setText(f'{state_text} · {len(rows) if count is None else count} kayıt'+(' · Henüz kayıt yok; boş tablo korumanın çalıştığını doğrulamaz.' if not rows else ''))
