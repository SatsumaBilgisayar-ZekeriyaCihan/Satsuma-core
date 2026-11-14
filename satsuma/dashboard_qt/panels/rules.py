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
    PANEL_TITLE = 'KURALLAR'
    PANEL_ICON = '📜'
    PANEL_ORDER = 8
    PANEL_GROUP = 'system'
    PANEL_SUBTITLE = 'Aktif tespit kuralları · doğrudan durdurma tanımı ve kanıt kapsamı ayrı gösterilir'
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
        research = QPushButton('DeepSeek araştırma stüdyosunu aç  →')
        research.clicked.connect(lambda: self.window().nav.select('deepseek'))
        self._layout.insertWidget(2, research)

    def refresh(self, *args):
        super().refresh(*args)
        try:
            data = self.backend.call('rules')
            self.status.setText(
                f"AKTİF: {data.get('active_total')}  ·  "
                f"YAML DOĞRUDAN DURDURMA: {data.get('direct_stop_total')}  ·  "
                f"DURDURMA TANIMI OLMAYAN: {data.get('without_direct_stop_total')}  ·  "
                f"GELECEK TELEMETRİ / ETKİN DEĞİL: {data.get('future_total')}  ·  "
                f"MERKEZİ POLİTİKA ADAYI: {data.get('central_policy_candidate_total')} (yetki/sonuç değildir) · "
                f"YÜKLEME DURUMU: {data.get('data_state')}"
            )
        except Exception as exc:
            self.status.setText('UNKNOWN · Veri okunamadı: '+str(exc)[:200])
