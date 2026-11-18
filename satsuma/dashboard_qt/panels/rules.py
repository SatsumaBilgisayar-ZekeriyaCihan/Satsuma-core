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
    PANEL_SUBTITLE = 'Etkin tespit kuralları; hangisinin programı durdurabildiği ve gereken kanıt ayrı sütunlarda.'
    METHOD = 'rules'
    KEY = 'rules'
    COLUMNS = (
        ('Rule ID', 'rule_id'),
        ('Ad', 'name'),
        ('Sınıflama', 'classification'),
        ('Önem', 'severity'),
        ('Kaynak/Kategori', 'category'),
        ('İstenen davranış', 'behavior'),
        ('YAML durdurma tanımlı', 'direct_stop_defined'),
        ('Merkezi politika adayı (yetki değil)', 'central_policy_candidate'),
        ('Tespit', 'detection_state'),
        ('Gerekli kanıt', 'required_evidence_count'),
        ('Doğrulanmış kanıt', 'verified_evidence_count'),
        ('Eksik koşullar', 'missing_conditions'),
        ('Politika kararı', 'policy_decision'),
        ('İmza', 'signature_state'),
        ('Aktivasyon', 'activation_state'),
        ('Gerçek müdahale', 'intervention_result'),
    )

    def _build(self):
        super()._build()
        from .deepseek import QPushButton
        research = QPushButton('Araştırma stüdyosunu aç  →');research.setObjectName('quiet')
        research.clicked.connect(lambda: __import__('satsuma.dashboard_qt.links', fromlist=['open_target']).open_target(self, 'deepseek'))
        self._layout.insertWidget(2, research)

    def refresh(self, *args):
        super().refresh(*args)
        try:
            data = self.backend.call('rules')
            self.status.setText(
                f"{data.get('active_total')} etkin kural · {data.get('direct_stop_total')} tanesi programı doğrudan durdurabilir · "
                f"{data.get('without_direct_stop_total')} tanesi yalnızca bildirir · {data.get('future_total')} tanesi henüz etkin değil (gelecek telemetri). "
                f"Merkezi politika adayı: {data.get('central_policy_candidate_total')} (yetki değildir).")
        except Exception as exc:
            self.status.setText('Kurallar okunamadı: '+str(exc)[:200])
