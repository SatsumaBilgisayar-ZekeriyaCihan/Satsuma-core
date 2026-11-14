#!/usr/bin/env python3
"""Rootless deep evidence service entrypoint."""
import signal
import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parent))
from satsuma.self_guard import verify
from satsuma_engine.process_ipc import serve

def main():
    verify()
    stopping = False
    def stop(*_):
        nonlocal stopping
        stopping = True
    signal.signal(signal.SIGTERM, stop)
    signal.signal(signal.SIGINT, stop)
    serve(stop=lambda: stopping)

if __name__ == '__main__':
    main()
