"""
Satsuma Worker — Host Mapper
Görev: Host worker'larından gelen ham veriyi SatsumaEvent'e dönüştürmek.
Yapmaz: Yorumlama, puanlama, karar.
"""
import logging
import socket
from datetime import datetime, timezone
from typing import Any, Dict, Optional
from uuid import uuid4

from core.events.event import SatsumaEnvelope
from core.schema.models import (
    SatsumaEvent,
    EventBlock,
    SourceBlock,
    RawBlock,
    HostBlock,
    MetadataBlock,
    Severity,
)


_KIND_TO_CATEGORY = {
    'process': 'host',
    'new_process': 'host',
    'module': 'host',
    'new_module': 'host',
    'usb': 'host',
    'new_usb': 'host',
    'pci': 'host',
    'new_pci': 'host',
    'port': 'network',
    'new_listening_port': 'network',
    'unit': 'host',
    'new_unit': 'host',
    'dbus': 'app',
    'dbus_suspicious_call': 'app',
    'kernel': 'host',
    'kernel_taint': 'host',
    'process_burst': 'host',
    'suspicious_module': 'host',
    'suspicious_unit': 'host',
    # Audit
    'syscall': 'host',
    'execve': 'host',
    'file_access': 'host',
    'user_event': 'user',
    # Journal
    'journal_event': 'app',
    # Kernel
    'kernel_event': 'host',
}

_KIND_TO_SEVERITY = {
    'suspicious_module': 'critical',
    'kernel_taint': 'critical',
    'suspicious_unit': 'critical',
    'dbus_suspicious_call': 'high',
    'new_listening_port': 'high',
    'new_usb': 'medium',
    'process_burst': 'medium',
    'new_module': 'medium',
    'new_unit': 'low',
    'new_process': 'low',
    'new_pci': 'low',
    # Audit
    'syscall': 'low',
    'execve': 'low',
    'file_access': 'low',
    'user_event': 'medium',
    # Journal
    'journal_event': 'medium',
    # Kernel
    'kernel_event': 'medium',
}


def _to_iso(value) -> str:
    """Her türlü timestamp'i ISO string'e çevir."""
    if isinstance(value, str):
        return value
    if isinstance(value, (int, float)):
        try:
            return datetime.fromtimestamp(value, tz=timezone.utc).isoformat()
        except (ValueError, OSError):
            return datetime.now(timezone.utc).isoformat()
    return datetime.now(timezone.utc).isoformat()


class HostMapper:
    def __init__(self, logger: Optional[logging.Logger] = None):
        self._logger = logger or logging.getLogger("satsuma.normalizer.host")
        self._hostname = socket.gethostname()

    def map(self, envelope: SatsumaEnvelope) -> Optional[SatsumaEvent]:
        raw = envelope.raw_data or {}
        try:
            return SatsumaEvent(
                event=self._build_event_block(raw, envelope),
                source=self._build_source_block(raw, envelope),
                raw=self._build_raw_block(envelope),
                host=self._build_host_block(),
                metadata=self._build_metadata_block(raw, envelope),
            )
        except Exception as exc:
            self._logger.error(f"HostMapper: map hatası -> {exc}")
            return None

    def _build_event_block(self, raw: Dict[str, Any], envelope: SatsumaEnvelope) -> EventBlock:
        kind = raw.get('kind', 'event')
        category = _KIND_TO_CATEGORY.get(kind, 'host')

        severity = None
        sev_name = _KIND_TO_SEVERITY.get(kind) or raw.get('severity')
        if sev_name:
            severity = Severity(level=sev_name, source=envelope.source_type)

        return EventBlock(
            id=str(uuid4()),
            timestamp=_to_iso(raw.get('timestamp', envelope.created_at)),
            ingested_at=datetime.now(timezone.utc).isoformat(),
            schema_version="1.0",
            category=category,
            action=kind,
            severity=severity,
        )

    def _build_source_block(self, raw: Dict[str, Any], envelope: SatsumaEnvelope) -> SourceBlock:
        return SourceBlock(
            type="linux",
            host=envelope.source_host or self._hostname,
            collector_id=envelope.source_type or 'sys_proc',
            raw_ref=envelope.envelope_id,
        )

    def _build_raw_block(self, envelope: SatsumaEnvelope) -> RawBlock:
        return RawBlock(format="json", data=envelope.raw_data)

    def _build_host_block(self) -> HostBlock:
        return HostBlock(name=self._hostname, os="linux")

    def _build_metadata_block(self, raw: Dict[str, Any], envelope: SatsumaEnvelope) -> MetadataBlock:
        extensions: Dict[str, Any] = {}
        for key, value in raw.items():
            if key not in ('timestamp', 'kind', 'severity', 'source'):
                extensions[f"host.{key}"] = value

        return MetadataBlock(
            tags=["host", envelope.source_type or "sys_proc"],
            labels={"host": envelope.source_host or self._hostname},
            extensions=extensions,
        )
