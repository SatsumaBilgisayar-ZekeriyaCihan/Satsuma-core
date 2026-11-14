"""Zincir korelasyonu: aynı güçlü kimliğe sahip bağımsız tespitleri tek bulguya yükseltir.

İlkeler (Satsuma Core Evidence-first sözleşmesiyle uyumlu):
  * Yalnızca GÜÇLÜ kimlik bağlar (varsayılan: ``event.process_key`` = boot|pid|starttime).
    Tek başına PID, IP, host veya zaman asla bulguları birleştirmez.
  * ``confirmed`` için en az ``min_families`` BAĞIMSIZ kaynak ailesi gerekir; aynı aileden
    gelen tekrarlar kendi kendini doğrulayamaz (en fazla ``likely``).
  * En az bir üye ``min_member_classification`` seviyesinde olmalıdır; yalnızca
    ``indicator`` bulgularından zincir kurulmaz.
  * Bastırılmış (suppressed) bulgular zincire katılmaz.
  * Zincir bulgusu yıkıcı aksiyon taşımaz; aksiyon kararı Core'un onay/politika yolunda kalır.
  * Üye bulgular değiştirilmez; yalnızca ``extensions.chain_ids`` ile işaretlenir.
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Iterable

from . import ENGINE_NAME, __version__
from .dedup import CLASSIFICATION_ORDER, FindingRecord
from .findings import FINDING_SCHEMA, SEVERITY_ORDER, event_fingerprint, event_source, severity_rank
from .util import deep_get, sha256_hex, truncate

DESTRUCTIVE_ACTIONS = frozenset({"kill_process", "block_ip", "quarantine_file", "user_disable", "network_isolate",
                                 "process_kill", "file_quarantine"})
MAX_EVIDENCE = 25


@dataclass
class ChainConfig:
    enabled: bool = True
    link_fields: tuple[str, ...] = ("event.process_key",)
    window_seconds: int = 1800
    min_rules: int = 2
    min_families: int = 2
    min_member_classification: str = "suspicious"
    rule_id: str = "SATSUMA-CHAIN-001"


def _class_rank(value: str) -> int:
    try:
        return CLASSIFICATION_ORDER.index(value)
    except ValueError:
        return 0


class ChainCorrelator:
    def __init__(self, config: ChainConfig | None = None, ruleset_hash: str = "") -> None:
        self.config = config or ChainConfig()
        self.ruleset_hash = ruleset_hash

    # -- yardımcılar --------------------------------------------------------
    def _link_values(self, event: dict[str, Any]) -> list[str]:
        out = []
        for path in self.config.link_fields:
            value = deep_get(event, path, None)
            if value not in (None, ""):
                out.append(f"{path}={value}")
        return out

    @staticmethod
    def _family(event: dict[str, Any]) -> str:
        return str(deep_get(event, "event.source_family", None) or event_source(event) or "unknown")

    def apply(self, records: list[FindingRecord], events: Iterable[tuple[int, dict[str, Any]]]) -> list[FindingRecord]:
        """Zincir bulgularını üretir, ``records`` listesine ekler ve eklenenleri döner."""
        cfg = self.config
        if not cfg.enabled:
            return []
        by_fp: dict[str, dict[str, Any]] = {}
        for line_no, event in events:
            by_fp[event_fingerprint(event, line_no)] = event
            by_fp.setdefault(event_fingerprint(event), event)

        # bağlantı anahtarı -> {rule_id: (record, families, link_events)}
        groups: dict[str, dict[str, dict[str, Any]]] = {}
        for record in records:
            if record.suppressed or record.finding.get("rule_id", "").startswith("SATSUMA-CHAIN"):
                continue
            seen_links: dict[str, list[dict[str, Any]]] = {}
            for fp in record.event_fingerprints:
                event = by_fp.get(fp)
                if not event:
                    continue
                for link in self._link_values(event):
                    seen_links.setdefault(link, []).append(event)
            for link, evs in seen_links.items():
                slot = groups.setdefault(link, {}).setdefault(
                    record.finding["rule_id"], {"record": record, "families": set(), "events": []})
                slot["families"].update(self._family(e) for e in evs)
                slot["events"].extend(evs)

        built: list[FindingRecord] = []
        for link in sorted(groups):
            members = groups[link]
            if len(members) < cfg.min_rules:
                continue
            recs = [m["record"] for m in members.values()]
            if max(_class_rank(r.finding.get("classification", "indicator")) for r in recs) < _class_rank(cfg.min_member_classification):
                continue
            epochs = [e for r in recs for e in (r.first_seen_epoch, r.last_seen_epoch) if e is not None]
            span = (max(epochs) - min(epochs)) if epochs else 0.0
            if epochs and span > cfg.window_seconds:
                continue
            built.append(self._build(link, members, recs, span))
        records.extend(built)
        return built

    def _build(self, link: str, members: dict[str, dict[str, Any]], recs: list[FindingRecord], span: float) -> FindingRecord:
        cfg = self.config
        recs = sorted(recs, key=lambda r: (r.first_seen_epoch is None, r.first_seen_epoch or 0, r.finding["rule_id"]))
        findings = [r.finding for r in recs]
        families = sorted({f for m in members.values() for f in m["families"]})
        independent = len(families) >= cfg.min_families
        top_class = max((f.get("classification", "indicator") for f in findings), key=_class_rank)
        classification = "confirmed" if independent else (top_class if _class_rank(top_class) >= _class_rank("likely") else "likely")
        severity = max((f.get("severity", "info") for f in findings), key=severity_rank)
        base = max(int(f.get("score", 0) or 0) for f in findings)
        modifiers = [{"reason": f"zincir: {len(findings)} farklı kural aynı süreçte", "delta": 5 * (len(findings) - 1)}]
        if independent:
            modifiers.append({"reason": f"bağımsız kaynak aileleri: {', '.join(families)}", "delta": 10})
        total = max(0, min(100, base + sum(m["delta"] for m in modifiers)))
        rule_ids = sorted(members)
        chain_id = "F-" + sha256_hex("chain", link, ",".join(rule_ids), length=16)

        mitre, seen = [], set()
        for f in findings:
            for m in f.get("mitre") or []:
                key = (m.get("tactic"), m.get("technique"))
                if key not in seen:
                    seen.add(key); mitre.append(dict(m))
        actions = []
        for f in findings:
            for a in f.get("actions") or []:
                if a not in DESTRUCTIVE_ACTIONS and a not in actions:
                    actions.append(a)
        if independent and "create_ticket" not in actions:
            actions.append("create_ticket")

        evidence: list[dict[str, Any]] = []
        for f in findings:
            evidence.append({"type": "correlation", "field": "rule_id", "value": f["rule_id"],
                             "detail": truncate(f"{f.get('title', '')} · {f.get('classification')} · {f.get('timestamp')}", 300)})
        for r in recs:
            for fp in r.event_fingerprints[:3]:
                if len(evidence) >= MAX_EVIDENCE:
                    break
                evidence.append({"type": "event", "event_fingerprint": fp, "detail": f"Üye bulgu: {r.finding['rule_id']}"})

        link_path, _, link_value = link.partition("=")
        first_ts = findings[0].get("timestamp")
        epochs = [e for r in recs for e in (r.first_seen_epoch, r.last_seen_epoch) if e is not None]
        title = "Zincirleme tespit: " + " → ".join(f.get("title", f["rule_id"]) for f in findings)
        reason = ("bağımsız kaynak aileleri aynı güçlü kimlikte örtüştü" if independent
                  else "aynı kaynak ailesi: kendi kendini doğrulayamaz, confirmed verilmedi")
        finding = {
            "schema": FINDING_SCHEMA,
            "finding_id": chain_id,
            "dedup_key": sha256_hex("chain", link, length=24),
            "rule_id": cfg.rule_id,
            "rule_title": "Aynı süreçte zincirleme tespit",
            "title": truncate(title, 300),
            "description": f"{len(findings)} farklı kural aynı güçlü süreç kimliğinde ({link_value}) tetiklendi; {reason}.",
            "severity": severity,
            "classification": classification,
            "confidence": "high" if independent else "medium",
            "category": "correlation",
            "tags": ["chain", "correlation"],
            "score": total,
            "score_breakdown": {"base": base, "modifiers": modifiers, "total": total},
            "host": findings[0].get("host") or "unknown",
            "timestamp": first_ts,
            "mitre": mitre,
            "entity": {"kind": link_path, "value": truncate(link_value, 200)},
            "evidence": evidence[:MAX_EVIDENCE],
            "observations": {"first_seen": first_ts, "last_seen": findings[-1].get("timestamp") or first_ts, "occurrences": 1},
            "actions": actions,
            "status": "open",
            "source": {"engine": ENGINE_NAME, "engine_version": __version__, "ruleset_hash": self.ruleset_hash},
            "extensions": {"chain": {"link": link, "rules": rule_ids, "families": families,
                                     "member_finding_ids": [f["finding_id"] for f in findings],
                                     "span_seconds": round(span, 3), "independent_families": independent, "reason": reason}},
        }
        if epochs:
            finding["timestamp_epoch"] = min(epochs)
        for f in findings:
            ids = f.setdefault("extensions", {}).setdefault("chain_ids", [])
            if chain_id not in ids:
                ids.append(chain_id)
        return FindingRecord(finding=finding, group="chain", window_seconds=cfg.window_seconds,
                             first_seen_epoch=min(epochs) if epochs else None, last_seen_epoch=max(epochs) if epochs else None,
                             occurrences=1, event_fingerprints=[fp for r in recs for fp in r.event_fingerprints[:1]])
