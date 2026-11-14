"""
Satsuma Core — SatsumaEnvelope
Görev: Taşıma zarfı.
Sınır: Sadece veri taşır.
Yapmaz: Normalize, yorum, karar.
"""

from dataclasses import dataclass, field
from typing import Any, Dict


@dataclass
class SatsumaEnvelope:
    envelope_id: str
    created_at: str
    source_type: str
    source_host: str
    raw_format: str
    raw_data: Dict[str, Any]
    metadata: Dict[str, Any] = field(default_factory=dict)
