"""Olanlar: everything that happened, repeats folded, each with what you can do about it (2.2.45).

Olanlar: tekrarlar tek satırda; her kayıtta ne oldu, Satsuma ne yaptı, siz ne yapabilirsiniz.
"""
from . import register
from ._userpage import UserPage
from ..qt import (QHBoxLayout, QVBoxLayout, QFrame, QListWidget, QListWidgetItem, QLineEdit, QComboBox, QSize,
                  QButtonGroup, USER_ROLE)
from ..ui import label, button, clear, Card, Pill, Empty, OUTCOME_TONES
from ...status_view import timestamp

FILTERS = (('', 'Tümü'), ('stopped', 'Durdurulan'), ('blocked', 'Engellenen'), ('quarantined', 'Karantina'),
           ('waiting', 'Onay bekleyen'), ('not_stopped', 'Durdurulamayan'), ('reported', 'Yalnızca bildirilen'))
PERIODS = ((24, 'Son 24 saat'), (24 * 7, 'Son 7 gün'), (24 * 30, 'Son 30 gün'))


class FeedRow(QFrame):
    def __init__(self, row, parent=None):
        super().__init__(parent)
        self.setObjectName('feedRow')
        line = QHBoxLayout(self)
        line.setContentsMargins(12, 8, 12, 8)
        line.setSpacing(10)
        pill = Pill(row['outcome_label'], OUTCOME_TONES.get(row['outcome'], 'unknown'))
        pill.setFixedWidth(112)
        line.addWidget(pill)
        text = QVBoxLayout()
        text.setSpacing(1)
        text.addWidget(label(row['title'], 'rowTitle'))
        text.addWidget(label(row.get('subject') or row.get('rule_id') or '', 'mono'))
        line.addLayout(text, 1)
        count = label(('%d kez' % row['count']) if row['count'] > 1 else '', 'countBadge', wrap=False)
        line.addWidget(count)
        when = timestamp(row['last_at'])
        line.addWidget(label(when.rsplit(' ', 1)[0] if ' ' in when else when, 'secondary', wrap=False))


@register
class ActivityPanel(UserPage):
    PANEL_ID = 'activity'
    PANEL_TITLE = 'Olanlar'
    PANEL_ORDER = 1
    PAGE_TITLE = 'Olanlar'
    PAGE_SUBTITLE = 'Satsuma’nın bulduğu ve yaptığı her şey. Aynı olay tekrar ettiğinde tek satırda sayılır.'
    REFRESH_MS = 8000

    def build(self, content):
        bar = QHBoxLayout()
        bar.setSpacing(8)
        self.filter_group = QButtonGroup(self)
        self.filter_group.setExclusive(True)
        self.filter_buttons = {}
        for index, (key, text) in enumerate(FILTERS):
            chip = button(text, None, 'chip')
            chip.setCheckable(True)
            chip.setChecked(index == 0)
            self.filter_group.addButton(chip, index)
            self.filter_buttons[key] = chip
            chip.clicked.connect(lambda checked=False: self.reload())
            bar.addWidget(chip)
        bar.addStretch()
        content.addLayout(bar)
        tools = QHBoxLayout()
        self.search = QLineEdit()
        self.search.setPlaceholderText('Program, adres, alan adı ya da kural ara')
        self.search.setClearButtonEnabled(True)
        self.search.returnPressed.connect(self.reload)
        tools.addWidget(self.search, 1)
        self.period = QComboBox()
        for hours, text in PERIODS:
            self.period.addItem(text, hours)
        self.period.currentIndexChanged.connect(lambda index: self.reload())
        tools.addWidget(self.period)
        content.addLayout(tools)
        self.summary = label('', 'secondary')
        content.addWidget(self.summary)

        split = QHBoxLayout()
        split.setSpacing(16)
        self.list = QListWidget()
        self.list.setObjectName('feed')
        self.list.setMinimumHeight(460)
        self.list.setSpacing(2)
        self.list.currentRowChanged.connect(self._select)
        split.addWidget(self.list, 3)
        self.detail = Card(name='detailCard', margins=(20, 18, 20, 18), spacing=10)
        self.detail.setMinimumWidth(320)
        split.addWidget(self.detail, 2)
        content.addLayout(split)
        self.rows = []
        self.wanted = None
        self._show_detail(None)

    def focus_row(self, row_id):
        self.wanted = row_id
        self._select_wanted()

    def _outcome(self):
        index = self.filter_group.checkedId()
        return FILTERS[index][0] if 0 <= index < len(FILTERS) else ''

    def refresh(self):
        params = {'hours': self.period.currentData() or 24, 'limit': 300}
        if self._outcome():
            params['outcome'] = self._outcome()
        if self.search.text().strip():
            params['search'] = self.search.text().strip()
        data, error = self.fetch('activity', **params)
        if data is None:
            if error != 'loading':
                self.summary.setText('Olaylar okunamadı: ' + str(error))
            else:
                self.summary.setText('Olaylar yükleniyor…')
            return
        if not self.changed('activity', (params, data.get('items'))):
            return
        self.rows = data.get('items') or []
        counts = data.get('counts') or {}
        self.summary.setText('%d kayıt · %d durdurma · %d engelleme · %d yalnızca bildirim' % (
            len(self.rows), counts.get('stopped', 0), counts.get('blocked', 0), counts.get('reported', 0)))
        selected = self.list.currentItem().data(USER_ROLE) if self.list.currentItem() else self.wanted
        self.list.blockSignals(True)
        self.list.clear()
        for row in self.rows:
            item = QListWidgetItem()
            item.setData(USER_ROLE, row['id'])
            widget = FeedRow(row)
            item.setSizeHint(QSize(10, max(56, widget.sizeHint().height())))
            self.list.addItem(item)
            self.list.setItemWidget(item, widget)
        self.list.blockSignals(False)
        if not self.rows:
            self._show_detail(None)
            return
        self.wanted = selected
        if not self._select_wanted():
            self.list.setCurrentRow(0)

    def _select_wanted(self):
        for index, row in enumerate(self.rows):
            if self.wanted and row['id'] == self.wanted:
                self.list.setCurrentRow(index)
                self._select(index)
                return True
        return False

    def _select(self, index):
        self._show_detail(self.rows[index] if 0 <= index < len(self.rows) else None)

    def _show_detail(self, row):
        clear(self.detail.body)
        if row is None:
            self.detail.body.addWidget(Empty('Bir kayıt seçin', 'Seçtiğiniz olayın ne olduğu, Satsuma’nın ne yaptığı ve sizin neler yapabileceğiniz burada görünür.'))
            self.detail.body.addStretch()
            return
        tags = QHBoxLayout()
        tags.addWidget(Pill(row['outcome_label'], OUTCOME_TONES.get(row['outcome'], 'unknown')))
        tags.addWidget(Pill(row.get('severity_label') or '', {'critical': 'crit', 'high': 'warn'}.get(row.get('severity'), 'unknown')))
        if row['count'] > 1:
            tags.addWidget(Pill('%d kez' % row['count'], 'info'))
        tags.addStretch()
        self.detail.body.addLayout(tags)
        self.detail.body.addWidget(label(row['title'], 'detailTitle', selectable=True))
        if row.get('subject'):
            self.detail.body.addWidget(label(row['subject'], 'mono', selectable=True))
        for heading, text in (('Ne oldu', row.get('what_happened')), ('Satsuma ne yaptı', row.get('what_satsuma_did')),
                              ('Öneri', row.get('recommendation'))):
            if text:
                self.detail.body.addWidget(label(heading, 'fieldLabel'))
                self.detail.body.addWidget(label(text, 'body', selectable=True))
        when = ('İlk: ' + timestamp(row['first_at']) + '\nSon: ' + timestamp(row['last_at'])) if row['count'] > 1 else timestamp(row['last_at'])
        self.detail.body.addWidget(label('Zaman', 'fieldLabel'))
        self.detail.body.addWidget(label(when, 'body'))
        if row.get('rule_id'):
            self.detail.body.addWidget(label('Kural', 'fieldLabel'))
            self.detail.body.addWidget(label(row['rule_id'], 'mono', selectable=True))
        actions = row.get('actions') or []
        if actions:
            self.detail.body.addWidget(label('Ne yapabilirsiniz', 'fieldLabel'))
            box = QVBoxLayout()
            box.setSpacing(6)
            for action in actions:
                box.addWidget(button(action['label'], lambda a=action: self.act(a),
                                     'danger' if action.get('weakens') else None,
                                     'Korumayı azaltır; parola yeniden sorulur.' if action.get('weakens') else None))
            self.detail.body.addLayout(box)
        self.detail.body.addStretch()
