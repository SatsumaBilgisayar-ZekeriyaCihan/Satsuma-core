# -*- coding: utf-8 -*-
"""Satsuma Core — Panel registry.

Paneller kendini @register dekoratoru ile kaydeder. Bu modul:
  - all_panels()      : kayitli panelleri sirali dondurur
  - get_panel(id)     : id ile panel sinifini bulur
  - autodiscover()    : panels/ altindaki tum modulleri import eder

Boylece yeni panel eklemek icin sadece yeni bir dosya olusturup
@register koymak yeterli. Navigasyon ve registry otomatik guncellenir.
"""
import importlib
import pkgutil
from pathlib import Path


# Panel siniflarini tutan sozluk: {panel_id: sinif}
_PANELS = {}


def register(cls):
    """Panel sinifini registry'e kaydet.

    Kullanim:
        @register
        class OverviewPanel(BasePanel):
            PANEL_ID = 'overview'
            ...
    """
    panel_id = getattr(cls, 'PANEL_ID', None)
    if not panel_id:
        raise ValueError(
            f'{cls.__name__} sinifinda PANEL_ID tanimli degil'
        )
    if panel_id in _PANELS:
        raise ValueError(
            f'Panel ID cakismasi: {panel_id!r} '
            f'({_PANELS[panel_id].__name__} vs {cls.__name__})'
        )
    _PANELS[panel_id] = cls
    return cls


def all_panels():
    """Kayitli tum panel siniflarini PANEL_ORDER'a gore sirali dondur."""
    return sorted(_PANELS.values(), key=lambda c: getattr(c, 'PANEL_ORDER', 99))


def get_panel(panel_id):
    """Panel ID ile sinifi bul. Yoksa None."""
    return _PANELS.get(panel_id)


def all_ids():
    """Kayitli tum panel ID'lerini sirali dondur."""
    return [c.PANEL_ID for c in all_panels()]


def autodiscover():
    """panels/ altindaki tum modulleri import et -> @register tetiklensin.

    '_' ile baslayan moduller ve 'base' haric tutulur.
    """
    pkg_dir = Path(__file__).parent
    for _, name, is_pkg in pkgutil.iter_modules([str(pkg_dir)]):
        if name.startswith('_') or name in ('base', 'tickets'):
            continue
        if is_pkg:
            continue
        try:
            importlib.import_module(f'.{name}', __package__)
        except Exception as e:
            import sys
            print(
                f'[panels] {name} yuklenemedi: {e}',
                file=sys.stderr,
            )


def clear():
    """Registry'i temizle (test icin)."""
    _PANELS.clear()
