"""Uygulama denetimi → Uygulama izinleri: decide what may reach the internet, and for how long (2.2.47).

Moved from the management page: pending requests with the decision's scope
(this connection / this program for this session / this program always),
saved rules (allow, block, ask again), App Control on/off and OpenSnitch's
state. Pending requests come from the reader; saved rules need the lock.

Uygulama izinleri: bekleyen isteklere süre seçerek karar, kayıtlı kurallar,
App Control açma/kapama ve OpenSnitch durumu.
"""
from . import register
from ._userpage import UserPage
from ..qt import QHBoxLayout, QVBoxLayout, QComboBox, QFrame
from ..ui import label, button, clear, Card, SettingRow, section

DURATIONS = (('application', 'Bu program için kalıcı (alt süreçler dahil)'),
             ('always', 'Bu program için kalıcı (yalnızca bu oturum ve kullanıcı)'),
             ('once', 'Yalnızca bu bağlantı (en fazla 5 dakika)'))
RULE_STATES = {'allow': 'İzinli', 'deny': 'Engelli', 'ask': 'Sorulacak'}


@register
class AppsPanel(UserPage):
    PANEL_ID = 'apps'
    PANEL_TITLE = 'Uygulama izinleri'
    PANEL_ORDER = 31
    PAGE_TITLE = 'Uygulama izinleri'
    PAGE_SUBTITLE = 'Yeni bir uygulama internete ilk kez çıkmak istediğinde size sorulur; siz karar verene kadar bekletilir.'
    REFRESH_MS = 4000

    def build(self, content):
        card = Card(name='card', margins=(22, 18, 22, 18), spacing=6)
        self.switch = SettingRow('Uygulamalar için izin sor', 'Kapalıyken her uygulama izin sorulmadan internete çıkabilir.')
        self.switch.toggled.connect(self._toggle)
        card.body.addWidget(self.switch)
        self.snitch = label('', 'secondary')
        card.body.addWidget(self.snitch)
        content.addWidget(card)

        card = Card(name='card', margins=(22, 18, 22, 18), spacing=8)
        card.body.addLayout(section('Karar bekleyen uygulamalar'))
        scope = QHBoxLayout()
        scope.addWidget(label('Kararın geçerliliği:', 'secondary', wrap=False))
        self.duration = QComboBox()
        for key, text in DURATIONS:
            self.duration.addItem(text, key)
        scope.addWidget(self.duration, 1)
        card.body.addLayout(scope)
        self.pending = QVBoxLayout()
        self.pending.setSpacing(6)
        card.body.addLayout(self.pending)
        content.addWidget(card)

        card = Card(name='card', margins=(22, 18, 22, 18), spacing=8)
        card.body.addLayout(section('Kayıtlı kurallar', 'Daha önce verdiğiniz kararlar. Kuralları görmek ve değiştirmek için kilidi açın.'))
        self.rules = QVBoxLayout()
        self.rules.setSpacing(4)
        card.body.addLayout(self.rules)
        content.addWidget(card)
        content.addStretch()
        self.operator = None

    def _toggle(self, value):
        self.switch.set(not value)
        self.act({'method': 'application_control', 'params': {'action': 'enable' if value else 'disable'}})

    def _decide(self, request, decision):
        self.act({'method': 'application_control',
                  'params': {'action': 'decision', 'decision': decision, 'request_id': request.get('id'),
                             'duration': self.duration.currentData()}})

    def _rule(self, key, scope, decision):
        self.act({'method': 'application_control', 'params': {'action': 'rule', 'decision': decision, 'key': key, 'scope': scope}})

    def _status(self, method, params, result):
        if isinstance(result, dict) and not result.get('error'):
            self.operator = result
            self._last.pop('apps', None)
            self.refresh()

    def refresh(self):
        session = self.session()
        unlocked = bool(session and session.unlocked())
        if unlocked and self.changed('unlocked', True):
            session.run('status', {}, self, then=self._status)
        elif not unlocked:
            self._last.pop('unlocked', None)
            self.operator = None
        data, error = self.fetch('protection')
        if data is None:
            if error != 'loading':
                self.snitch.setText('Uygulama izinleri okunamadı: ' + str(error))
            return
        app = data.get('app') or {}
        if not self.changed('apps', (app, self.operator)):
            return
        status = app.get('status')
        self.switch.set(True if status == 'ACTIVE' else False if status in ('DISABLED', 'HANDED_TO_OPENSNITCH') else None,
                        'OpenSnitch yönetiyor' if status == 'HANDED_TO_OPENSNITCH' else None)
        snitch = (self.operator or {}).get('opensnitch') or {}
        self.snitch.setText('OpenSnitch çalışıyor; uygulama izinlerini o veriyor, Satsuma kenarda bekliyor.' if snitch.get('running') else
                            'OpenSnitch kurulu ama çalışmıyor; izinleri Satsuma veriyor.' if snitch.get('installed') else
                            'İzinleri Satsuma veriyor.' if self.operator else '')
        clear(self.pending)
        pending = app.get('pending') or []
        if not pending:
            self.pending.addWidget(label('Karar bekleyen uygulama yok.', 'secondary'))
        for request in pending:
            program = (request.get('application') or {}).get('executable') or 'Bilinmeyen uygulama'
            line = QHBoxLayout()
            text = QVBoxLayout()
            text.setSpacing(1)
            text.addWidget(label(str(program).rsplit('/', 1)[-1] + ' internete çıkmak istiyor', 'rowTitle'))
            text.addWidget(label('%s → %s · %s bağlantı' % (program, request.get('destination'), request.get('connection_count') or 1), 'mono'))
            line.addLayout(text, 1)
            line.addWidget(button('İzin ver', lambda r=request: self._decide(r, 'allow'), 'primary'))
            line.addWidget(button('Engelle', lambda r=request: self._decide(r, 'deny')))
            self.pending.addLayout(line)
        clear(self.rules)
        if not self.operator:
            self.rules.addWidget(label('%d kayıtlı kural. Görmek için kilidi açın.' % (app.get('rule_count') or 0), 'secondary'))
            self.rules.addWidget(button('Kilidi aç', lambda: self.session() and self.session().unlock(self, self.reload)))
            return
        control = self.operator.get('app_control') or {}
        rules = [(key, 'session', value) for key, value in (control.get('rules') or {}).items()] + \
                [(key, 'application', value) for key, value in (control.get('application_rules') or {}).items()]
        if not rules:
            self.rules.addWidget(label('Kayıtlı kural yok.', 'secondary'))
        for key, scope, value in rules:
            line = QHBoxLayout()
            line.addWidget(label(key[:24] + ('…' if len(key) > 24 else ''), 'mono', wrap=False, selectable=True))
            line.addWidget(label(('Program, kalıcı' if scope == 'application' else 'Oturum') + ' · ' + RULE_STATES.get(value, str(value)), 'secondary'), 1)
            for verb, decision in (('İzin ver', 'allow'), ('Engelle', 'deny'), ('Yeniden sor', 'ask')):
                if decision != value:
                    line.addWidget(button(verb, lambda k=key, s=scope, d=decision: self._rule(k, s, d)))
            self.rules.addLayout(line)
            divider = QFrame()
            divider.setObjectName('divider')
            divider.setFixedHeight(1)
            self.rules.addWidget(divider)
