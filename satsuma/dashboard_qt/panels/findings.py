# -*- coding: utf-8 -*-
"""Bulgular modülü — bulgu listesi, filtreler ve detay."""
try:
    from PyQt6.QtWidgets import (
        QTableWidgetItem, QDialog, QVBoxLayout, QHBoxLayout, QLabel, QTextBrowser, QPushButton,
    )
    from PyQt6.QtCore import Qt
except ImportError:
    from PyQt5.QtWidgets import (
        QTableWidgetItem, QDialog, QVBoxLayout, QHBoxLayout, QLabel, QTextBrowser, QPushButton,
    )
    from PyQt5.QtCore import Qt

try:
    from ._module import ReadOnlyModulePanel
    from . import register
except ImportError:
    from _module import ReadOnlyModulePanel
    from panels import register

try:
    from ..style.theme import Colors, FONT_MONO
except ImportError:
    from style.theme import Colors, FONT_MONO


from ..detail_sanitizer import detail_lines


class FindingDetailDialog(QDialog):
    def __init__(self, detail, parent=None):
        super().__init__(parent)
        self.setWindowTitle("Bulgu Detayı — " + detail_lines(detail.get("finding_id") or "-"))
        self.resize(760, 620)
        root = QVBoxLayout(self)
        title = QLabel(detail_lines(detail.get('title') or detail.get('finding_id') or 'Bulgu'))
        title.setStyleSheet(f'color:{Colors.TEXT_ORANGE}; font-size:16px; font-weight:900;')
        root.addWidget(title)
        body = QTextBrowser()
        body.setOpenExternalLinks(False)
        sections = (
            ('NE OLDU?', detail.get('what_happened')),
            ('NEDEN İŞARETLENDİ?', detail.get('why_flagged')),
            ('KANIT', detail.get('evidence')),
            ('KAYNAKLAR', detail.get('sources')),
            ('İLGİLİ PROCESS / IP / PATH', detail.get('entities')),
            ('İLGİLİ RULE', detail.get('related_rule')),
            ('CORRELATION', detail.get('correlation')),
            ('SATSUMA\'NIN YAPTIĞI AKSİYON', detail.get('action')),
            ('ÖNERİLEN İŞLEM', detail.get('recommendation')),
            ('HEDEF SİSTEM', detail.get('target_scope')),
            ('SON DURUM', detail.get('last_status')),
        )
        import html
        parts = []
        for heading, value in sections:
            if value in (None, '', [], {}):
                value = 'BİLİNMİYOR / VERİ YOK'
            value = detail_lines(value)
            parts.append(
                f"<h3 style='color:#d78700'>{html.escape(heading)}</h3>"
                f"<pre style='white-space:pre-wrap'>{html.escape(str(value))}</pre>"
            )
        body.setHtml(''.join(parts))
        root.addWidget(body, 1)
        close = QPushButton('Kapat')
        close.clicked.connect(self.accept)
        root.addWidget(close)


@register
class FindingsPanel(ReadOnlyModulePanel):
    PANEL_ID = 'findings'
    PANEL_TITLE = 'BULGULAR'
    PANEL_ICON = '🔎'
    PANEL_ORDER = 2
    PANEL_GROUP = 'main'
    PANEL_SUBTITLE = 'Satsuma kurallarının bulduğu her şey; bir kayda çift tıklayınca ne olduğu, neden işaretlendiği ve kanıtı açılır.'
    METHOD = 'findings'
    KEY = 'items'
    PARAMS = {'limit': 250}
    COLUMNS = (
        ('Önem', 'severity_label'),
        ('Sınıflama', 'classification_label'),
        ('Tarih / Saat', 'time_label'),
        ('Süreç', 'process_name'),
        ('PID', 'pid'),
        ('Başlık', 'title'),
        ('Güven', 'confidence'),
        ('Rule ID', 'rule_id'),
        ('Kaynak', 'source'),
        ('Hedef sistem', 'target_scope'),
        ('Olay', 'event_type'),
        ('Durum', 'status'),
    )
    FILTERS = (
        ('classification', 'Sınıflama', ['indicator', 'suspicious', 'likely', 'confirmed']),
        ('severity', 'Önem', ['info', 'low', 'medium', 'high', 'critical']),
        ('source', 'Kaynak', ['CORE', 'CLAMAV', 'AUDIT', 'SURICATA', 'PROCESS', 'DNS', 'OPNSENSE']),
        ('rule_id', 'Rule', None),
        ('text', 'Ara', None),
    )

    def _build(self):
        super()._build()
        self.table.cellDoubleClicked.connect(self._open_detail)
        self._current_items = []
        self._offset = 0
        self._filter_signature = None
        self._pending_detail = None
        pager = QHBoxLayout()
        self.previous_page = QPushButton('Önceki sayfa')
        self.next_page = QPushButton('Sonraki sayfa')
        self.previous_page.setEnabled(False)
        self.next_page.setEnabled(False)
        self.previous_page.clicked.connect(lambda: self._page(-1))
        self.next_page.clicked.connect(lambda: self._page(1))
        pager.addWidget(self.previous_page)
        pager.addWidget(self.next_page)
        self._layout.addLayout(pager)

    def _params(self):
        params = super()._params()
        signature = tuple(sorted(params.items()))
        if signature != getattr(self, '_filter_signature', None):
            self._offset = 0
            self._filter_signature = signature
        params['offset'] = getattr(self, '_offset', 0)
        return params

    def _page(self, direction):
        self._offset = max(0, self._offset + direction * self.PARAMS['limit'])
        self.refresh()

    def _render_data(self, data):
        super()._render_data(data)
        if isinstance(data, dict):
            self.previous_page.setEnabled(self._offset > 0)
            self.next_page.setEnabled(bool(data.get('has_more')))
            if data.get('total_count') is not None:
                self.status.setText(
                    f"{data.get('data_state')} · Toplam: {data['total_count']} · "
                    f"Filtrelenen: {data.get('filtered_count')} · Gösterilen: {len(self._rows)}"
                    + (f" · {data['error']}" if data.get('error') else ''))
        if self._pending_detail:
            self._load_detail()


    def _rows_from(self, data):
        from ...presentation import fields, priority_key
        rows = [dict(row, **fields(row)) for row in super()._rows_from(data)]
        rows.sort(key=priority_key)
        self._current_items = rows
        return rows

    def _open_detail(self, row, _column=0):
        if not (0 <= row < len(self._current_items)):
            return
        item = self._current_items[row]
        if not item.get('finding_id'):
            return
        self._pending_detail = (item['finding_id'], item.get('record_key'))
        self._load_detail()

    def _load_detail(self):
        finding_id, record_key = self._pending_detail
        try:
            detail = self.backend.finding(finding_id, record_key=record_key)
        except Exception as exc:
            self.status.setText('Bulgu detayı: ' + detail_lines(str(exc)))
            if 'arka planda yükleniyor' not in str(exc):
                self._pending_detail = None
            return
        self._pending_detail = None
        if not detail.get('available'):
            self.status.setText(f"Bulgu detayı alınamadı: {detail_lines(detail.get('error') or detail.get('data_state') or 'Veri yok')}")
            return
        FindingDetailDialog(detail, self).exec()
