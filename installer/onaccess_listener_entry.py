#!/usr/bin/python3
"""Satsuma signed-image entrypoint; follows project import convention."""
import sys
sys.path.insert(0, '/opt/satsuma-core')
from satsuma.self_guard import verify
verify()
from satsuma.onaccess_listener import main
raise SystemExit(main())
