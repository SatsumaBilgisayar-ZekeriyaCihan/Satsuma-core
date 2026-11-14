# -*- coding: utf-8 -*-
"""Satsuma Core — Qt Dashboard.

TUI (satsuma.dashboard) ile ayni core.db'yi okuyan grafik arayuz.

Kullanim:
    from satsuma.dashboard_qt import run
    run()

    # veya panel gelistirmek icin:
    from satsuma.dashboard_qt.panels import register, BasePanel
    from satsuma.dashboard_qt.backend import Backend
"""
from .app import run
from .backend import Backend

__version__ = '0.5.0'
__all__ = ['run', 'Backend', '__version__']
