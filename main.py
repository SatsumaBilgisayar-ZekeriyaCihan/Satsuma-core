#!/usr/bin/python3
import sys
from pathlib import Path

# With Python -I, only this root-owned application directory is added.
sys.path.insert(0, str(Path(__file__).resolve().parent))

from satsuma.self_guard import verify

# Read-only help/version requests must remain usable before installation and
# during recovery.
if not any(arg in ("-h", "--help", "--version") for arg in sys.argv[1:]):
    try:
        verify()
    except Exception as exc:
        import json
        print(json.dumps({
            'status': getattr(exc, 'code', 'INTEGRITY_CHECK_FAILED'),
            'error': str(exc)[:1000],
            'monitoring_started': False,
            'mutations_locked': True,
        }), file=sys.stderr)
        raise SystemExit(78)

from satsuma.app import main

if __name__ == '__main__':
    from satsuma.configuration_status import entrypoint
    raise SystemExit(entrypoint(main))
