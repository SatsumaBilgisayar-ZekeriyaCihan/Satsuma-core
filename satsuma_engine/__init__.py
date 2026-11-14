"""Satsuma Engine — şema tabanlı tespit kural motoru ve bulgu (finding) hattı.

Bu paket, Satsuma Core ürününün kural motoru + bulgu bileşeninin çalışır,
dışa açık ve şema tabanlı bir yeniden uygulamasıdır.
"""

from __future__ import annotations

__version__ = "0.1.0"
ENGINE_NAME = "satsuma-engine"
RULE_API_VERSION = "satsuma/v1"
FINDING_SCHEMA_VERSION = "1.0"

__all__ = [
    "__version__",
    "ENGINE_NAME",
    "RULE_API_VERSION",
    "FINDING_SCHEMA_VERSION",
]
