# -*- coding: utf-8 -*-
"""Show rule loading, central eligibility and actual intervention separately.

Kural yüklemesini, merkezi adaylığı ve gerçek müdahaleyi ayrı göster.
"""
try:
    from ._module import ReadOnlyModulePanel
    from . import register
except ImportError:
    from _module import ReadOnlyModulePanel
    from panels import register


@register
class RulesPanel(ReadOnlyModulePanel):
    PANEL_ID = 'rules'
    PANEL_TITLE = 'Kurallar'
    PANEL_ICON = '📜'
    PANEL_ORDER = 8
    PANEL_GROUP = 'system'
    PANEL_SUBTITLE = ('Bir kural eşleşince ne olur: programı durdurur ya da yalnızca bildirir. Durdurma, program hâlâ '
                      'çalışıyorsa yapılabilir; milisaniyede biten bir komut sinyal gitmeden biter ve kayıtlara öyle yazılır. '
                      'Teknik ayrıntılar (kanıt şartları, imza, ilke kararı) seçili kuralın teknik görünümündedir.')
    METHOD = 'rules'
    KEY = 'rules'
    COLUMNS = (
        ('Kural', 'name'),
        ('Ne yapar', 'what_happens'),
        ('Önem', 'severity_label'),
        ('Tür', 'classification_label'),
        ('Son müdahale', 'last_intervention'),
        ('Kimlik', 'rule_id'),
    )

    def _build(self):
        super()._build()
        from .deepseek import QPushButton
        research = QPushButton('Araştırma stüdyosunu aç  →');research.setObjectName('quiet')
        research.clicked.connect(lambda: __import__('satsuma.dashboard_qt.links', fromlist=['open_target']).open_target(self, 'deepseek'))
        self._layout.insertWidget(2, research)

    def refresh(self, *args):
        super().refresh(*args)
        data = self._last_render[1] if self._last_render else {}
        if isinstance(data, dict) and data.get('summary_text'):
            self.status.setText(data['summary_text'])
        elif isinstance(data, dict) and data.get('error'):
            self.status.setText('Kurallar okunamadı: ' + str(data['error'])[:200])
