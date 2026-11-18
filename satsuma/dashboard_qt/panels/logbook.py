"""Kayıtlar → Tüm kayıtlar: every log of Satsuma in one readable list (2.2.47).

User request 2026-11-18: "technical logs should be meaningful; put all logs
in a separate section in an easily readable form". Records of both databases
are shown newest first as one sentence each (record_catalog.render), with
their importance, their kind, and on selection what the kind is, why it is
kept, and the masked raw record. Raw telemetry is a separate view.

Kullanıcı isteği 2026-11-18: teknik kayıtlar anlamlı olsun, tüm kayıtlar ayrı
bir bölümde kolay okunur hâle gelsin. İki veritabanındaki kayıtlar en yenisi
üstte, her biri tek cümle olarak; önemi, türü ve seçilince türün ne olduğu,
neden tutulduğu ve maskeli ham kaydıyla gösterilir.
"""
import html

from ._module import ReadOnlyModulePanel, QComboBox, QLineEdit, QHBoxLayout, QLabel, QPushButton
from . import register
from ..style.theme import Colors
from ...status_view import timestamp

VIEWS = (('Önemli kayıtlar', 'important'), ('Yalnızca uyarı ve hatalar', 'problems'), ('Koruma', 'protection'),
         ('Ağ', 'network'), ('Satsuma’nın sağlığı', 'health'), ('Ham olaylar (çok sayıda)', 'raw'))
WINDOWS = (('Son 1 saat', 1), ('Son 24 saat', 24), ('Son 7 gün', 168), ('Son 30 gün', 720))
LEVEL_COLORS = {'Hata': Colors.STATUS_CRIT, 'Önemli': Colors.STATUS_CRIT, 'Uyarı': Colors.STATUS_WARN, 'Başarılı': Colors.STATUS_OK}


def detail_html(item):
    """Selected record: the sentence, its kind explained, and where it came from."""
    def block(caption, text):
        return ('<p style="margin:0 0 10px 0"><span style="color:#8a8a8a;font-size:11px">%s</span><br>%s</p>'
                % (html.escape(caption), html.escape(str(text)).replace('\n', '<br>')))
    parts = [block('Ne oldu', item.get('text') or '—')]
    if item.get('detail') and item['detail'] != '—':
        parts.append(block('Ayrıntı', item['detail']))
    when = timestamp(item.get('created'))
    if item.get('repeat'):
        when = '%d kez · ilk %s · son %s' % (item['repeat'], timestamp(item.get('first_created')), when)
    parts.append(block('Zaman', when))
    parts.append(block('Önem', (item.get('level') or 'Bilgi') + (' · ' + item['chip'] if item.get('chip') else '')))
    parts.append(block('Kayıt türü', item.get('kind_name') or item.get('kind') or '—'))
    if item.get('kind_what'):
        parts.append(block('Bu tür nedir', item['kind_what']))
    if item.get('kind_why'):
        parts.append(block('Neden önemli', item['kind_why']))
    source = {'core': 'Satsuma veritabanı', 'host': 'Sistem denetimi veritabanı'}.get(item.get('db'), item.get('db') or '')
    parts.append(block('Kaynak', source + ' · ' + str(item.get('kind')) + ' · ' + str(item.get('id'))))
    return ''.join(parts)


@register
class LogbookPanel(ReadOnlyModulePanel):
    PANEL_ID = 'logbook'
    PANEL_TITLE = 'Tüm kayıtlar'
    PANEL_GROUP = 'system'
    PANEL_ORDER = 2
    METHOD = 'logbook'
    KEY = 'items'
    REFRESH_MS = 10000
    PANEL_SUBTITLE = ('Satsuma’nın tuttuğu bütün kayıtlar tek listede, en yenisi üstte ve her biri bir cümleyle. '
                      'Bir kayıt seçince ne olduğunu, neden tutulduğunu ve ham hâlini görürsünüz.')
    COLUMNS = (('Zaman', 'created'), ('Önem', 'level'), ('Tür', 'kind_name'), ('Ne oldu', 'text'), ('Ayrıntı', 'detail'))

    def _build(self):
        super()._build()
        row = QHBoxLayout()
        row.setSpacing(10)
        self.view = QComboBox()
        for text, value in VIEWS:
            self.view.addItem(text, value)
        self.period = QComboBox()
        for text, value in WINDOWS:
            self.period.addItem(text, value)
        self.period.setCurrentIndex(1)
        self.search = QLineEdit()
        self.search.setPlaceholderText('Kayıtlarda ara: program, adres, kural, hata…')
        self.search.setClearButtonEnabled(True)
        self.older = QPushButton('Daha eski kayıtlar')
        self.older.setObjectName('quiet')
        self.newest = QPushButton('En yeniye dön')
        self.newest.setObjectName('quiet')
        self.newest.hide()
        for caption, widget in (('Göster', self.view), ('Dönem', self.period)):
            text = QLabel(caption)
            text.setObjectName('secondary')
            row.addWidget(text)
            row.addWidget(widget)
        row.addWidget(self.search, 1)
        row.addWidget(self.older)
        row.addWidget(self.newest)
        from ..qt import QWidget
        holder = QWidget()
        holder.setLayout(row)
        self._layout.insertWidget(2, holder)
        self._before = None
        self.view.currentIndexChanged.connect(self._restart)
        self.period.currentIndexChanged.connect(self._restart)
        self.search.returnPressed.connect(self._restart)
        self.older.clicked.connect(self._page_older)
        self.newest.clicked.connect(self._restart)
        self.table.setMinimumHeight(260)

    def _params(self):
        params = {'view': self.view.currentData(), 'hours': self.period.currentData(), 'limit': 100}
        text = self.search.text().strip()
        if text:
            params['search'] = text
        if self._before is not None:
            params['before'] = self._before
        return params

    def _restart(self, *args):
        self._before = None
        self.newest.hide()
        self._last_render = None
        self.refresh()

    def _page_older(self):
        data = self._last_render[1] if self._last_render else {}
        oldest = data.get('oldest') if isinstance(data, dict) else None
        if oldest is None:
            self.status.setText('Daha eski kayıt yok.')
            return
        self._before = oldest
        self.newest.show()
        self._last_render = None
        self.refresh()

    def refresh(self, *args):
        # Paging back must not be undone by the timer; only the newest page refreshes itself.
        if args == () and self._before is not None and self._last_render is not None:
            return
        super().refresh(*args)
        data = self._last_render[1] if self._last_render else {}
        if not isinstance(data, dict):
            return
        from ..qt import QColor
        for row, item in enumerate(self._rows):
            color = LEVEL_COLORS.get(item.get('level'))
            cell = self.table.item(row, 1)
            if color and cell is not None:
                cell.setForeground(QColor(color))
        self.older.setEnabled(bool(data.get('has_more')))
        errors = data.get('errors') or {}
        state = {'OK': 'Veri alındı', 'NO_DATA': 'Bu dönemde kayıt yok', 'DEGRADED': 'Kısmen alındı'}.get(data.get('data_state'), 'Veri alınamadı')
        text = '%s · %d satır gösteriliyor' % (state, len(self._rows))
        repeats = sum(item.get('repeat', 1) for item in self._rows)
        if repeats > len(self._rows):
            text += ' (%d kayıt; tekrarlar tek satırda)' % repeats
        if self._before is not None:
            text += ' · ' + timestamp(self._before) + ' öncesi'
        if errors:
            text += ' · Okunamayan veritabanı: ' + ', '.join(errors)
        self.status.setText(text)

    def _rows_from(self, data):
        return [{**item, 'detail': item.get('detail') or '—'} for item in super()._rows_from(data) if isinstance(item, dict)]

    def _show_details(self):
        super()._show_details()
        row = self.table.currentRow()
        if 0 <= row < len(self._rows):
            self.detail_view.setText(detail_html(self._rows[row]))
