"""Paginated verified process exits and classified database browsing.

Record kinds are listed under their plain Turkish names from record_catalog.

Doğrulanmış süreç çıkışları ve sınıflandırılmış veritabanı için sayfalı arayüz.
Kayıt türleri record_catalog'daki sade Türkçe adlarıyla listelenir.
"""
from ._module import ReadOnlyModulePanel, QHBoxLayout, QPushButton, QComboBox, QLabel, QTableWidget, QTableWidgetItem
from . import register


class PagedPanel(ReadOnlyModulePanel):
    def _build(self):
        self.offset = 0
        super()._build()
        buttons = QHBoxLayout()
        self.previous_page = QPushButton('Önceki sayfa')
        self.next_page = QPushButton('Sonraki sayfa')
        self.previous_page.clicked.connect(lambda: self._move(-50))
        self.next_page.clicked.connect(lambda: self._move(50))
        buttons.addWidget(self.previous_page)
        buttons.addWidget(self.next_page)
        self._layout.addLayout(buttons)

    def _move(self, amount):
        self.offset = max(0, self.offset + amount)
        self.refresh()

    def _params(self):
        return {**super()._params(), 'offset': self.offset, 'limit': 50}

    def _render_data(self, data):
        super()._render_data(data)
        self.previous_page.setEnabled(self.offset > 0)
        self.next_page.setEnabled(bool(data.get('has_more')))


@register
class StoppedProcessesPanel(PagedPanel):
    PANEL_ID = 'stopped_processes'
    PANEL_TITLE = 'Durdurulan işlemler'
    PANEL_ORDER = 4
    PANEL_SUBTITLE = 'Yalnız sinyal gönderilen ve çıkışı doğrulanan süreçler. Diğer girişimler Güvenlik aksiyonları bölümündedir.'
    METHOD = 'stopped_processes'
    COLUMNS = (('Zaman', 'timestamp'), ('PID', 'pid'), ('Kural', 'rule_id'),
               ('Sinyal gönderildi', 'signal_sent'), ('Çıkış doğrulandı', 'exit_verified'), ('Hedef', 'target'))

    def _build(self):
        super()._build()
        self._layout.addWidget(QLabel('Exec Guard — engellenen çalıştırma girişimleri (süreç sonlandırma değildir)'))
        self.denials = QTableWidget()
        self.denials.setColumnCount(5)
        self.denials.setHorizontalHeaderLabels(['Zaman', 'PID', 'proc klasörü', 'İşlem / süreç adı', 'Yapılan işlem'])
        self.denials.setEditTriggers(QTableWidget.EditTrigger.NoEditTriggers if hasattr(QTableWidget,'EditTrigger') else QTableWidget.NoEditTriggers)
        self._layout.addWidget(self.denials)

    def refresh(self, *args):
        super().refresh(*args)
        try:
            data = self.backend.call('exec_guard_events', kind='refused', limit=50)
            rows = data.get('items') or []
            self.denials.setRowCount(len(rows))
            for i, row in enumerate(rows):
                for j, key in enumerate(('timestamp','pid','proc_dir','process_name','action')):
                    self.denials.setItem(i, j, QTableWidgetItem(str(row.get(key) or '')))
        except Exception as exc:
            self.denials.setRowCount(0)
            self.status.setText(self.status.text()+' · Exec Guard kayıtları alınamadı: '+str(exc)[:120])



@register
class DatabasePanel(PagedPanel):
    PANEL_ID = 'database'
    PANEL_TITLE = 'Sınıflandırılmış veriler'
    PANEL_ORDER = 40
    PANEL_SUBTITLE = 'Core ve host verileri sayfalıdır. Kimlik/oturum tabloları yalnız envanterde sayılır; gizli alanlar maskelenir. Kayıt seçerek ayrıntıları açın.'
    METHOD = 'database_page'
    COLUMNS = (('Kayıt', 'record'), ('İçerik', 'preview'))

    def _build(self):
        self._selection = None
        self._catalog = None
        super()._build()
        self.sources = QComboBox()
        self.sources.currentIndexChanged.connect(self._selected)
        self._layout.insertWidget(2, self.sources)

    def _selected(self, *args):
        self.offset = 0
        self._selection = self.sources.currentData()
        self.refresh()

    def _params(self):
        return {**(self._selection or {}), 'offset': self.offset, 'limit': 50}

    def refresh(self, *args):
        try:
            catalog = self.backend.call('database_catalog')
            if catalog != self._catalog:
                self.sources.blockSignals(True)
                previous = self.sources.currentData()
                self.sources.clear()
                for database, tables in catalog.get('databases', {}).items():
                    for table in tables:
                        if table['access'] == 'metadata_only':
                            continue
                        groups = table['groups'] or [{'kind': None, 'count': table['count']}]
                        for group in groups:
                            params = {'database': database, 'table': table['table']}
                            if group['kind'] is not None:
                                params['kind'] = group['kind']
                            if group['kind'] is not None:
                                from ...record_catalog import describe
                                label = f"{describe(group['kind'])['name']} ({group['count']}) · {database}/{group['kind']}"
                            else:
                                label = f"{database} / {table['table']} / tümü ({group['count']})"
                            self.sources.addItem(label, params)
                index = self.sources.findData(previous)
                self.sources.setCurrentIndex(max(0, index))
                self._selection = self.sources.currentData()
                if previous != self._selection:
                    self.offset = 0
                self.sources.blockSignals(False)
                self._catalog = catalog
            if not self._selection:
                self.status.setText('Görüntülenebilir tablo bulunamadı; envanter boş veya okunamadı.')
                return
            super().refresh()
            if catalog.get('errors'):
                self.status.setText(self.status.text() + ' · Kısmi erişim: ' + str(catalog['errors']))
        except Exception as exc:
            self.status.setText(f'HATA: {exc}')

    def _rows_from(self, data):
        import json
        return [{**row, 'record': row.get('id', row.get('key', self.offset + i + 1)),
                 'preview': json.dumps(row, ensure_ascii=False, default=str)[:240]}
                for i, row in enumerate(data.get('items', []))]
