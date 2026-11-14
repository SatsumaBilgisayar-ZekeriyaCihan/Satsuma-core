# -*- coding: utf-8 -*-
"""DEPRECATED compatibility shim.

The canonical production dashboard entrypoint is
``satsuma.dashboard_qt.app:run`` (also reachable through ``main.py
--dashboard``).  This module used to contain a second, direct-database
dashboard generation.  It is intentionally not imported by the canonical
window and opens no database itself.
"""
from __future__ import annotations

import sys


def main():
    from .app import run
    return run()


if __name__ == '__main__':
    sys.exit(main())
