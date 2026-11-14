"""Satsuma Core — Self-Integrity Guard: event üretimi.
Mevcut Store.add('events', ...) mekanizmasını kullanır.
Pipeline'a DOKUNMAZ, mapper'ı çağırmaz.
"""
from __future__ import annotations

import logging
import time
from typing import Iterable

from ._types import Violation, IntegrityState


logger = logging.getLogger("satsuma.self_guard.emit")

EVENT_TYPE = "SATSUMA_SELF_INTEGRITY"
EVENT_KIND = "self_integrity"


def _violation_to_event(v: Violation) -> dict:
    """Violation -> Store.add('events', body) formatı."""
    return {
        "kind": EVENT_KIND,
        "event_type": EVENT_TYPE,
        "source": "satsuma.self_guard",
        "severity": "high",
        **v.to_dict(),
    }


def emit_violations(store, violations: Iterable[Violation]) -> int:
    """Violation'ları store'a yaz. Returns: yazılan event sayısı."""
    count = 0
    for v in violations:
        try:
            store.add("events", _violation_to_event(v))
            count += 1
        except Exception as e:
            logger.error("emit failed for %s: %s", v.file, e)
    return count


def emit_state(store, state: IntegrityState, violation_count: int) -> None:
    """Özet durumu state tablosuna yaz."""
    try:
        store.set("self_integrity_health", {
            "status": state.value,
            "violation_count": violation_count,
            "updated_at": time.time(),
        })
    except Exception as e:
        logger.error("health write failed: %s", e)
