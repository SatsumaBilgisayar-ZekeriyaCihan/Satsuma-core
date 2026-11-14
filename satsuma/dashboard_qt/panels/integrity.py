# -*- coding: utf-8 -*-
"""Render integrity evidence without promoting unavailable data to healthy.

Bütünlük kanıtını göster; alınamayan veriyi sağlıklı olarak sunma.
"""
try:
    from ._module import ReadOnlyModulePanel
    from . import register
except ImportError:
    from _module import ReadOnlyModulePanel
    from panels import register


@register
class IntegrityPanel(ReadOnlyModulePanel):
    PANEL_ID = 'integrity'
    PANEL_TITLE = 'BÜTÜNLÜK'
    PANEL_ICON = '🔐'
    PANEL_ORDER = 13
    PANEL_GROUP = 'security'
    PANEL_SUBTITLE = 'MANIFEST · DOĞRULAMA · UYARI/BAŞARISIZ'
    METHOD = 'integrity'
    KEY = 'items'
    COLUMNS = (
        ('Alan', 'field'),
        ('Değer', 'value'),
    )

    def refresh(self, *args):
        errors = dict(getattr(self.backend, 'presentation_errors', {}) or {})
        try:
            super().refresh(*args)
            # An unchanged successful render can use its previous data.
            data = self._last_render[1] if self._last_render else None
            if (isinstance(data, dict) and isinstance(data.get('summary'), dict)
                    and data.get('data_state') not in ('UNKNOWN', 'NO_DATA')):
                errors.pop('integrity', None)
            else:
                errors['integrity'] = 'Bütünlük ayrıntıları doğrulanamadı'
        except Exception:
            self._last_render = None
            errors['integrity'] = 'Bütünlük paneli yenilenemedi'
            raise
        finally:
            self.backend.presentation_errors = errors

    def _rows_from(self, data):
        if not isinstance(data, dict):
            return [{'field':'Genel durum','value':'Veri alınamadı'}]
        summary = data.get('summary')
        if not isinstance(summary, dict) or data.get('data_state') in ('UNKNOWN', 'NO_DATA'):
            summary = {'overall':'Veri alınamadı','message':data.get('error') or 'Bütünlük kanıtı bekleniyor'}
        return [{'field':title,'value':summary.get(key),'raw':data} for key,title in (
            ('files','Uygulama dosyaları'),('configuration','Yapılandırma'),('protection','Koruma bileşenleri'),
            ('overall','Genel durum'),('message','Tutarlılık'),('host_scope','Kontrol kapsamı'))]+[
            {'field':'Son dosya/yapılandırma kontrolü','value':__import__('satsuma.status_view',fromlist=['timestamp']).timestamp(summary.get('checked_at'))},
            {'field':'Son koruma kontrolü','value':__import__('satsuma.status_view',fromlist=['timestamp']).timestamp(summary.get('protection_checked_at'))},
            {'field':'Son hata kaydı (geçmiş olabilir)','value':data.get('last_error') or 'Hata kaydı yok'}]
