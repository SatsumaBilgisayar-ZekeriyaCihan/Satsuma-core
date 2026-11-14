"""eBPF olayları için sistem bağlamı zenginleştirme."""
from __future__ import annotations
import os, socket
from dataclasses import dataclass
from typing import Any

@dataclass
class EnrichmentContext:
    hostname: str = ""
    def __post_init__(self):
        if not self.hostname:
            try:
                self.hostname = socket.gethostname()
            except Exception:
                self.hostname = "localhost"

def enrich_event(envelope: dict[str, Any], ctx: EnrichmentContext) -> dict[str, Any]:
    ev = envelope.get("event", {})
    if not ev.get("host"):
        ev["host"] = ctx.hostname
    return envelope
