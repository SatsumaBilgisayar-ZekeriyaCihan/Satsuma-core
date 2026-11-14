#!/usr/bin/python3 -B
"""Satsuma Core — Integrity Guard CLI wrapper.
systemd `-I` modunda PYTHONPATH yok sayıldığı için
sys.path'i burada açıkça ayarlıyoruz.
"""
import sys

sys.path.insert(0, "/opt/satsuma-core")

from satsuma.self_guard.cli import main

if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
