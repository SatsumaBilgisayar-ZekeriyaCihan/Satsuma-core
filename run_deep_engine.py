#!/usr/bin/env python3
"""Rootless deep evidence service entrypoint.

2.2.38 (owner, 2026-11-18: the deep engine stayed inactive): the integrity
check reads the root-only manifest key (/etc/satsuma-core/trust/manifest.key,
0600) and runs satsuma-image verify; under User=satsuma-engine it always failed
with PermissionError, so the service never served. The check now runs as root
before the service starts (``--verify``, ExecStartPre=+ in the unit); the
service itself still refuses to run as root.

Bütünlük denetimi yalnız root'un okuyabildiği anahtarı okur; satsuma-engine
kullanıcısıyla hep başarısız oluyordu. Denetim artık servis başlamadan önce root
olarak çalışır (``--verify``); servis yine root olarak çalışmayı reddeder.
"""
import os
import signal
import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parent))


def verify_only():
    if os.geteuid() != 0:
        raise PermissionError('--verify needs root (ExecStartPre=+)')
    from satsuma.self_guard import verify
    verify()
    return 0


def main():
    from satsuma_engine.process_ipc import serve
    stopping = False
    def stop(*_):
        nonlocal stopping
        stopping = True
    signal.signal(signal.SIGTERM, stop)
    signal.signal(signal.SIGINT, stop)
    serve(stop=lambda: stopping)

if __name__ == '__main__':
    if sys.argv[1:] == ['--verify']:
        raise SystemExit(verify_only())
    main()
