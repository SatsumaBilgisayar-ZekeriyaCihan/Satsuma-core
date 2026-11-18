"""Durum: one verdict, what waits for the user, protection layers, the last day (2.2.45).

Durum: tek cümlelik sonuç, sizi bekleyenler, koruma katmanları, son 24 saat.
"""
from . import register
from ._userpage import UserPage
from ..qt import QFrame, QHBoxLayout, QVBoxLayout, QGridLayout
from ..ui import label, button, clear, Card, ActionRow, LayerTile, Metric, Empty, Pill, OUTCOME_TONES, section
from ..security_widgets import ShieldArtwork
from ...status_view import timestamp

HERO_TONES = {'ok': 'healthy', 'attention': 'warning', 'critical': 'critical', 'unknown': 'unknown'}


def short_time(value):
    text = timestamp(value)
    return text.split(' ')[1][:5] if ' ' in text else text


class ActivityLine(QFrame):
    def __init__(self, row, on_open, parent=None):
        super().__init__(parent)
        self.setObjectName('activityLine')
        line = QHBoxLayout(self)
        line.setContentsMargins(14, 9, 14, 9)
        line.setSpacing(12)
        pill = Pill(row['outcome_label'], OUTCOME_TONES.get(row['outcome'], 'unknown'))
        pill.setFixedWidth(112)
        line.addWidget(pill)
        text = QVBoxLayout()
        text.setSpacing(1)
        text.addWidget(label(row['title'], 'rowTitle'))
        if row.get('subject'):
            text.addWidget(label(row['subject'], 'mono'))
        line.addLayout(text, 1)
        times = ('%d kez · son %s' % (row['count'], short_time(row['last_at']))) if row['count'] > 1 else short_time(row['last_at'])
        line.addWidget(label(times, 'secondary', wrap=False))
        line.addWidget(button('Aç', lambda: on_open(row), 'quiet'))


@register
class HomePanel(UserPage):
    PANEL_ID = 'home'
    PANEL_TITLE = 'Durum'
    PANEL_ORDER = 0
    PAGE_TITLE = 'Durum'
    PAGE_SUBTITLE = 'Bu bilgisayarın korunma durumu ve sizden beklenenler.'
    REFRESH_MS = 5000

    def build(self, content):
        hero = Card(name='hero', margins=(24, 22, 28, 22))
        row = QHBoxLayout()
        row.setSpacing(22)
        self.art = ShieldArtwork()
        row.addWidget(self.art)
        text = QVBoxLayout()
        text.setSpacing(8)
        self.badge = Pill('Durum alınıyor', 'unknown')
        badge_row = QHBoxLayout()
        badge_row.addWidget(self.badge)
        badge_row.addStretch()
        text.addLayout(badge_row)
        self.verdict = label('Koruma durumunuz okunuyor', 'heroTitle')
        text.addWidget(self.verdict)
        self.detail = label('Satsuma servislerinden veri bekleniyor.', 'heroText')
        text.addWidget(self.detail)
        self.checked = label('', 'secondary')
        text.addWidget(self.checked)
        text.addStretch()
        row.addLayout(text, 1)
        hero.body.addLayout(row)
        content.addWidget(hero)

        content.addLayout(section('Sizi bekleyenler', 'Kararınızı ya da onarım bekleyen konular; her birinin yanında çözen düğme var.'))
        self.attention_box = QVBoxLayout()
        self.attention_box.setSpacing(8)
        content.addLayout(self.attention_box)

        content.addLayout(section('Koruma katmanları', 'Ayarlarını açmak için bir katmana tıklayın.'))
        self.layers_grid = QGridLayout()
        self.layers_grid.setHorizontalSpacing(12)
        self.layers_grid.setVerticalSpacing(12)
        content.addLayout(self.layers_grid)

        content.addLayout(section('Son 24 saat'))
        metrics = QHBoxLayout()
        metrics.setSpacing(12)
        self.metrics = {}
        for key, caption in (('stopped', 'Durdurulan program'), ('blocked', 'Engellenen bağlantı'),
                             ('quarantined', 'Karantinaya alınan dosya'), ('reported', 'Yalnızca bildirilen')):
            self.metrics[key] = Metric(caption)
            metrics.addWidget(self.metrics[key], 1)
        content.addLayout(metrics)

        recent_head = QHBoxLayout()
        recent_head.addLayout(section('Son olanlar'), 1)
        recent_head.addWidget(button('Tümünü gör  →', lambda: self.open('activity'), 'quiet'))
        content.addLayout(recent_head)
        self.recent = Card(name='listCard', margins=(0, 4, 0, 4), spacing=0)
        content.addWidget(self.recent)
        self.recent_empty = Empty('Son 24 saatte bir şey olmadı', 'Satsuma bir tehdit bulduğunda ya da bir işlem yaptığında burada görünür.')
        self.recent.body.addWidget(self.recent_empty)

    def refresh(self):
        data, error = self.fetch('home')
        if data is None:
            if error != 'loading' and self.changed('error', error):
                self.badge.set('Bağlantı yok', 'unknown')
                self.verdict.setText('Durum alınamıyor')
                self.detail.setText('Satsuma okuyucu servisine ulaşılamadı: ' + str(error))
                self.art.set_tone('unknown')
            return
        if not self.changed('home', {k: v for k, v in data.items() if k != 'generated_at'}):
            return
        self._last.pop('error', None)
        verdict = data.get('verdict') or {}
        tone = verdict.get('tone', 'unknown')
        self.art.set_tone(HERO_TONES.get(tone, 'unknown'))
        self.badge.set({'ok': 'Korunuyor', 'attention': 'Dikkat', 'critical': 'Kritik', 'unknown': 'Bilinmiyor'}.get(tone, 'Bilinmiyor'),
                       {'ok': 'ok', 'attention': 'warn', 'critical': 'crit'}.get(tone, 'unknown'))
        self.verdict.setText(verdict.get('title') or 'Durum alınamıyor')
        self.detail.setText(verdict.get('detail') or '')
        self.checked.setText(('Son sağlık kontrolü: ' + timestamp(data['checked_at'])) if data.get('checked_at') else
                             'Sağlık kontrolü henüz sonuç vermedi.')
        self._render_attention(data.get('attention') or [])
        self._render_layers(data.get('layers') or [])
        for key, metric in self.metrics.items():
            metric.set((data.get('counts') or {}).get(key))
        self._render_recent(data.get('recent') or [])

    def _render_attention(self, items):
        clear(self.attention_box)
        if not items:
            self.attention_box.addWidget(Empty('Bekleyen bir şey yok', 'Sizden bir karar ya da onarım beklenmiyor.'))
            return
        for item in items:
            self.attention_box.addWidget(ActionRow(item, lambda action, it: self.act(action)))

    def _render_layers(self, layers):
        clear(self.layers_grid)
        for index, layer in enumerate(layers):
            tile = LayerTile(layer)
            tile.clicked.connect(lambda target: self.open(target))
            self.layers_grid.addWidget(tile, index // 3, index % 3)
        for column in range(3):
            self.layers_grid.setColumnStretch(column, 1)

    def _render_recent(self, rows):
        clear(self.recent.body)
        if not rows:
            self.recent_empty = Empty('Son 24 saatte bir şey olmadı',
                                      'Satsuma bir tehdit bulduğunda ya da bir işlem yaptığında burada görünür.')
            self.recent.body.addWidget(self.recent_empty)
            return
        for index, row in enumerate(rows):
            if index:
                divider = QFrame()
                divider.setObjectName('divider')
                divider.setFixedHeight(1)
                self.recent.body.addWidget(divider)
            self.recent.body.addWidget(ActivityLine(row, lambda r: self.open('activity', {'row': r.get('id')})))
