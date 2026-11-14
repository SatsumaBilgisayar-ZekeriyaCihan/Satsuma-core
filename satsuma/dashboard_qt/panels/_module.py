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
        if not self.METHOD:
            raise ValueError(f'{self.__class__.__name__}: METHOD tanimli degil')
        self._layout.addWidget(self.make_title(self.PANEL_TITLE))
        self._layout.addWidget(self.make_subtitle(self.PANEL_SUBTITLE or 'SALT OKUNUR'))
        filter_row = QHBoxLayout()
        self._filter_widgets = {}
        for field, label, values in self.FILTERS:
            filter_row.addWidget(QLabel(label))
            if values:
                widget = QComboBox()
                widget.addItem('Tümü', '')
                for item in values:
                    widget.addItem(str(item), str(item))
            else:
                widget = QLineEdit()
                widget.setPlaceholderText('Filtre')
            widget.currentTextChanged.connect(self.refresh) if isinstance(widget, QComboBox) else widget.returnPressed.connect(self.refresh)
            self._filter_widgets[field] = widget
            filter_row.addWidget(widget)
        refresh_btn = QPushButton('Yenile')
        refresh_btn.clicked.connect(self.refresh)
        filter_row.addStretch()
        filter_row.addWidget(refresh_btn)
        self._layout.addLayout(filter_row)

        self.status = QLabel('Veri bekleniyor')
        self.status.setWordWrap(True)
        self.status.setMinimumHeight(60)
        self.status.setStyleSheet(
            f'color:{Colors.TEXT_MUTED}; font-family:{FONT_MONO}; font-size:11px;'
        )
        self._layout.addWidget(self.status)

        self.table = QTableWidget()
        self.table.setColumnCount(len(self.COLUMNS))
        self.table.setHorizontalHeaderLabels([c[0] for c in self.COLUMNS])
        self.table.setEditTriggers(QTableWidget.EditTrigger.NoEditTriggers if QT_VERSION == 6 else QTableWidget.NoEditTriggers)
        self._last_render = None
        self.table.setAlternatingRowColors(True)
        self.table.verticalHeader().setVisible(False)
        self.table.horizontalHeader().setStretchLastSection(True)
        if QT_VERSION == 6:
            self.table.setSelectionBehavior(QTableWidget.SelectionBehavior.SelectRows)
        else:
            self.table.setSelectionBehavior(QTableWidget.SelectRows)
        self._layout.addWidget(self.table, 1)
        self._rows=[]
        details_button=QPushButton('Teknik ayrıntılar / seçili kayıt')
        self.details=QPlainTextEdit();self.details.setReadOnly(True);self.details.setMaximumHeight(180);self.details.hide()
        details_button.clicked.connect(lambda:self.details.setVisible(self.details.isHidden()))
        self.table.itemSelectionChanged.connect(self._show_details)
        self._layout.addWidget(details_button);self._layout.addWidget(self.details)

    def _show_details(self):
        row=self.table.currentRow()
        self.details.setPlainText(json.dumps(self._rows[row],ensure_ascii=False,indent=2,default=str) if 0<=row<len(self._rows) else 'Bir kayıt seçin.')

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
                    is_time=key in ('timestamp','added_at','expires_at','last_run','last_successful_event','last_verification','last_successful_update','last_attempt')
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
        self.status.setText(f'{_fmt(state)} · Kayıt: {len(rows) if count is None else count}'+(' · Henüz kayıt yok; boş tablo korumanın çalıştığını doğrulamaz.' if not rows else ''))
