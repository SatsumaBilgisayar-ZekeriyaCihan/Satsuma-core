# -*- coding: utf-8 -*-
"""DEPRECATED compatibility shim.

Use ``satsuma.dashboard_qt.windows.main_window.MainWindow`` and the
read-only reader socket backend.  The former direct-database dashboard
generation was removed from the production call path.
"""
from __future__ import annotations

try:
    from .windows.main_window import MainWindow
except ImportError:
    from windows.main_window import MainWindow

__all__ = ['MainWindow']
