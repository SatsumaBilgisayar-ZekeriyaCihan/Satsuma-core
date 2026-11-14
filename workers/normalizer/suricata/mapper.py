"""
Satsuma Worker — Suricata Mapper
Görev: Suricata alanlarını Satsuma Unified Event alanlarına eşlemek.
Yapmaz: Yorumlama, puanlama, karar.
"""

import logging
from datetime import datetime, timezone
from typing import Any, Dict, Optional
from uuid import uuid4

from core.events.event import SatsumaEnvelope
from satsuma.process_attribution import attribute as _proc_attr
from core.schema.models import (
    SatsumaEvent,
    EventBlock,
    SourceBlock,
    RawBlock,
    NetworkBlock,
    PayloadBlock,
    MetadataBlock,
    Severity,
)


_SEVERITY_MAP = {
    1: "high",
    2: "medium",
    3: "low",
}


class SuricataMapper:
    def __init__(self, logger: logging.Logger):
        self._logger = logger

    def map(self, envelope: SatsumaEnvelope) -> Optional[SatsumaEvent]:
        raw = envelope.raw_data or {}

        try:
            return SatsumaEvent(
                event=self._build_event_block(raw, envelope),
                source=self._build_source_block(envelope),
                raw=self._build_raw_block(envelope),
                network=self._build_network_block(raw),
                payload=self._build_payload_block(raw),
                metadata=self._build_metadata_block(raw, envelope),
            )
        except Exception as exc:
            self._logger.error(f"SuricataMapper: map hatası -> {exc}")
            return None

    def _build_event_block(
        self, raw: Dict[str, Any], envelope: SatsumaEnvelope
    ) -> EventBlock:
        timestamp = raw.get("timestamp", envelope.created_at)
        event_type = raw.get("event_type", "unknown")
        severity = self._build_severity(raw)

        return EventBlock(
            id=str(uuid4()),
            timestamp=timestamp,
            ingested_at=datetime.now(timezone.utc).isoformat(),
            schema_version="1.0",
            category="network",
            action=event_type,
            severity=severity,
        )

    def _build_severity(self, raw: Dict[str, Any]) -> Optional[Severity]:
        alert = raw.get("alert")
        if not isinstance(alert, dict):
            return None

        raw_sev = alert.get("severity")
        if raw_sev is None:
            return None

        level = _SEVERITY_MAP.get(raw_sev)
        if level is None:
            return None

        return Severity(level=level, source="suricata")

    def _build_source_block(self, envelope: SatsumaEnvelope) -> SourceBlock:
        return SourceBlock(
            type="suricata",
            host=envelope.source_host,
            collector_id="suricata_collector",
            raw_ref=envelope.envelope_id,
            vendor="OISF",
            product="Suricata",
        )

    def _build_raw_block(self, envelope: SatsumaEnvelope) -> RawBlock:
        return RawBlock(format="eve", data=envelope.raw_data)

    def _build_network_block(
        self, raw: Dict[str, Any]
    ) -> Optional[NetworkBlock]:
        src_ip = raw.get("src_ip")
        dst_ip = raw.get("dest_ip")

        if not src_ip or not dst_ip:
            return None

        proto = raw.get("proto")
        if isinstance(proto, str):
            proto = proto.lower()

        return NetworkBlock(
            src_ip=src_ip,
            dst_ip=dst_ip,
            src_port=raw.get("src_port"),
            dst_port=raw.get("dest_port"),
            proto=proto,
        )

    def _build_payload_block(
        self, raw: Dict[str, Any]
    ) -> Optional[PayloadBlock]:
        alert = raw.get("alert")
        if not isinstance(alert, dict):
            return None

        signature = alert.get("signature")
        if not signature:
            return None

        return PayloadBlock(signature=signature)

    def _build_metadata_block(
        self, raw: Dict[str, Any], envelope: SatsumaEnvelope
    ) -> MetadataBlock:
        extensions: Dict[str, Any] = {}

        if "flow_id" in raw:
            extensions["suricata.flow_id"] = raw["flow_id"]

        alert = raw.get("alert")
        if isinstance(alert, dict):
            if "severity" in alert:
                extensions["suricata.severity_raw"] = alert["severity"]
            if "signature_id" in alert:
                extensions["suricata.signature_id"] = alert["signature_id"]
            if "gid" in alert:
                extensions["suricata.gid"] = alert["gid"]
            if "rev" in alert:
                extensions["suricata.rev"] = alert["rev"]

        tls = raw.get("tls")
        if isinstance(tls, dict) and "sni" in tls:
            extensions["suricata.tls.sni"] = tls["sni"]

        dns = raw.get("dns")
        if isinstance(dns, dict):
            # Query eventi: rrname + rrtype
            if "rrname" in dns:
                extensions["suricata.dns.query"] = dns["rrname"]
                extensions["suricata.dns.rrname"] = dns["rrname"]
            if "rrtype" in dns:
                extensions["suricata.dns.rrtype"] = dns["rrtype"]
            if "type" in dns:
                extensions["suricata.dns.type"] = dns["type"]
            if "rcode" in dns:
                extensions["suricata.dns.rcode"] = dns["rcode"]
            # Answer eventi: queries listesi
            if "queries" in dns and isinstance(dns["queries"], list):
                extensions["suricata.dns.queries"] = dns["queries"]
            # Cevap IP'leri
            if "answers" in dns and isinstance(dns["answers"], list):
                extensions["suricata.dns.answers"] = dns["answers"]

        # Process attribution (src_port -> PID/name)
        src_port = raw.get("src_port")
        proto = raw.get("proto", "udp").lower()
        if src_port and proto in ("udp", "tcp"):
            proc = _proc_attr(src_port, proto)
            if proc:
                extensions["satsuma.process.pid"] = proc["pid"]
                extensions["satsuma.process.name"] = proc["name"]

        return MetadataBlock(
            tags=["suricata"],
            labels={"sensor": envelope.source_host},
            extensions=extensions,
        )
