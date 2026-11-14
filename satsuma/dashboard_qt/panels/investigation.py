"""Real queued research results; no fake submission or direct DB access."""
from ._module import ReadOnlyModulePanel
from . import register

@register
class InvestigationPanel(ReadOnlyModulePanel):
    PANEL_ID = 'investigation'
    PANEL_TITLE = 'Araştırma Sonuçları'
    PANEL_ORDER = 4
    PANEL_SUBTITLE = 'Üretilmiş kural adayları. Bu görünüm araştırma isteği göndermez.'
    METHOD = 'research_queue'
    COLUMNS = (('Kural', 'rule_id'), ('Kaynak', 'source'), ('İnceleme durumu', 'status'), ('Teknik', 'technique'), ('Oluşturulma', 'created_at'))
