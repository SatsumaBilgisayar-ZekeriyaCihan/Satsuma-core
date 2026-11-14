"""Tarama motoru: kural eşleştirme, aggregation, tekilleştirme ve bastırma.

Akış:

  1. Kurallar ve olaylar yüklenir (JSONL).
  2. Her olay, her etkin kurala karşı değerlendirilir. `logsource` eşleşmesi
     kuralları önce daraltır (hızlı yol).
  3. Aggregation içeren kurallar pencere içinde biriktirilir; eşik aşılınca
     tek bulgu (veya `emit: per_event` ile her olay için bir bulgu) üretilir.
  4. Üretilen ham tespitler varlık + pencere anahtarıyla tekilleştirilir.
  5. Bastırma listesi uygulanır; bastırılanlar kaybolmaz, ayrı raporlanır.
  6. Sonuçlar `ScanResult` içinde istatistiklerle döner.

Motor deterministiktir: aynı girdi + aynı kural seti aynı `finding_id` değerlerini üretir.
"""

from __future__ import annotations

import time
from collections import deque
from dataclasses import dataclass, field as dc_field
from pathlib import Path
from typing import Any, Iterable

from .conditions import MISSING
from .chain import ChainConfig
from .dedup import Deduplicator, DedupConfig, FindingRecord  # noqa: F401  (FindingRecord tip olarak kullanılır)
from .findings import (
    enrich_finding,
    event_fingerprint,
    event_timestamp,
    host_of,
    mitre_summary,
    priority_of,
    severity_rank,
)
from .rule_model import Rule, load_events
from .suppression import SuppressionList
from .util import as_list, deep_get, iso, truncate


@dataclass
class ScanStats:
    """Tarama istatistikleri — tüm sayılar raporlanabilir."""

    rules_loaded: int = 0
    rules_enabled: int = 0
    rules_matched: int = 0
    rule_hits: dict[str, int] = dc_field(default_factory=dict)
    events_scanned: int = 0
    events_matched: int = 0
    evaluations: int = 0
    raw_detections: int = 0
    unique_findings: int = 0
    merged_events: int = 0
    suppressed_findings: int = 0
    aggregation_groups: int = 0
    chains: int = 0
    elapsed_ms: int = 0
    events_file: str = ""
    ruleset_hash: str = ""

    def as_dict(self) -> dict[str, Any]:
        return {
            "rules_loaded": self.rules_loaded,
            "rules_enabled": self.rules_enabled,
            "rules_matched": self.rules_matched,
            "events_scanned": self.events_scanned,
            "events_matched": self.events_matched,
            "evaluations": self.evaluations,
            "raw_detections": self.raw_detections,
            "unique_findings": self.unique_findings,
            "merged_events": self.merged_events,
            "suppressed_findings": self.suppressed_findings,
            "aggregation_groups": self.aggregation_groups,
            "chains": self.chains,
            "elapsed_ms": self.elapsed_ms,
            "events_file": self.events_file,
            "ruleset_hash": self.ruleset_hash,
            "top_rules": sorted(self.rule_hits.items(), key=lambda kv: (-kv[1], kv[0]))[:10],
        }


@dataclass
class SuppressedFinding:
    finding: dict[str, Any]
    suppression_id: str
    reason: str


@dataclass
class ScanResult:
    findings: list[FindingRecord] = dc_field(default_factory=list)
    suppressed: list[SuppressedFinding] = dc_field(default_factory=list)
    stats: ScanStats = dc_field(default_factory=ScanStats)
    rules: list[Rule] = dc_field(default_factory=list)
    suppressions: SuppressionList | None = None

    @property
    def reported(self) -> list[FindingRecord]:
        return [record for record in self.findings if not record.suppressed]

    def findings_as_dicts(self, include_suppressed: bool = False) -> list[dict[str, Any]]:
        records: Iterable[FindingRecord] = self.findings if include_suppressed else self.reported
        return [record.finding for record in records]

    def severity_counts(self) -> dict[str, int]:
        counts = {level: 0 for level in ("info", "low", "medium", "high", "critical")}
        for record in self.reported:
            counts[str(record.finding.get("severity", "info"))] = counts.get(str(record.finding.get("severity", "info")), 0) + 1
        return counts

    def priority_counts(self) -> dict[str, int]:
        counts: dict[str, int] = {}
        for record in self.reported:
            key = priority_of(record.finding)
            counts[key] = counts.get(key, 0) + 1
        return counts

    def mitre_rows(self) -> list[dict[str, Any]]:
        return mitre_summary(record.finding for record in self.reported)

    def summary_dict(self) -> dict[str, Any]:
        return {
            "generated_at": iso(),
            "stats": self.stats.as_dict(),
            "severity_counts": self.severity_counts(),
            "priority_counts": self.priority_counts(),
            "mitre": self.mitre_rows(),
            "suppressions": self.suppressions.summary() if self.suppressions else None,
        }


class AggregationState:
    """Tek bir aggregation kuralı için pencere durumu."""

    def __init__(self, rule: Rule) -> None:
        self.rule = rule
        config = rule.aggregation or {}
        self.threshold = int(config.get("threshold", 1))
        self.window = int(config.get("window_seconds", 60))
        self.mode = config.get("type", "threshold")
        self.distinct_field = config.get("count_distinct_field")
        self.emit = config.get("emit", "single")
        self.missing_label = str(config.get("missing_group_label", "(gruplanmamış)"))
        self.groups: dict[str, deque[tuple[float, int, dict[str, Any]]]] = {}
        self.last_emit: dict[str, float] = {}
        self.total_groups = 0

    def _group_value(self, event: dict[str, Any]) -> str:
        fields = as_list(self.rule.aggregation.get("group_by")) if self.rule.aggregation else []
        if not fields:
            return self.missing_label
        values = []
        for field in fields:
            value = deep_get(event, str(field), MISSING)
            values.append(self.missing_label if value is MISSING else str(value))
        return "|".join(values)

    def add(self, event: dict[str, Any], index: int, epoch: float | None) -> list[dict[str, Any]]:
        """Olayı pencereye ekler ve tetiklenen olayları döner."""
        epoch = epoch if epoch is not None else 0.0
        key = self._group_value(event)
        bucket = self.groups.setdefault(key, deque())
        bucket.append((epoch, index, event))
        while bucket and epoch - bucket[0][0] > self.window:
            bucket.popleft()

        if self.mode == "count_distinct" and self.distinct_field:
            counted = {str(deep_get(item[2], str(self.distinct_field), self.missing_label)) for item in bucket}
            current = len(counted)
        else:
            current = len(bucket)

        if current < self.threshold:
            return []

        self.total_groups = len(self.groups)
        previous = self.last_emit.get(key)
        if self.emit == "single":
            if previous is not None and epoch - previous < self.window:
                return []
            self.last_emit[key] = epoch
            return [self._synthetic_event(key, bucket, current)]
        self.last_emit[key] = epoch
        return [self._synthetic_event(key, bucket, current)]

    def _synthetic_event(self, group: str, bucket: deque[tuple[float, int, dict[str, Any]]], count: int) -> dict[str, Any]:
        """Aggregation sonucunu tek bir sentetik olaya indirger."""
        representative = bucket[-1][2]
        events = [item[2] for item in bucket]
        window_start, window_end = bucket[0][0], bucket[-1][0]
        mode_label = "farklı değer" if self.mode == "count_distinct" else "olay"
        synthetic = {
            "event": dict(representative.get("event") or {}),
            "metadata": dict(representative.get("metadata") or {}),
            "raw": dict(representative.get("raw") or {}),
            "aggregation": {
                "group": group,
                "count": count,
                "distinct_field": self.distinct_field,
                "window_seconds": self.window,
                "threshold": self.threshold,
                "window_start": iso_from_epoch(window_start),
                "window_end": iso_from_epoch(window_end),
                "event_fingerprints": [event_fingerprint(item) for item in events[-25:]],
                "summary": f"{count} {mode_label} / {self.window} sn (grup: {group})",
            },
        }
        synthetic["event"]["timestamp"] = iso_from_epoch(window_end) or (representative.get("event") or {}).get("timestamp")
        return synthetic

    def close(self, epoch: float | None) -> list[dict[str, Any]]:
        """Tarama sonunda kalan pencereler için tetiklenmemiş grupları raporlar."""
        leftovers: list[dict[str, Any]] = []
        for key, bucket in self.groups.items():
            if key in self.last_emit:
                continue
            if len(bucket) >= self.threshold:
                leftovers.append(self._synthetic_event(key, bucket, len(bucket)))
        return leftovers


def iso_from_epoch(value: float | None) -> str | None:
    from .util import epoch_to_iso

    return epoch_to_iso(value)


LOGSELECTOR_PATHS = {
    "source": ("event.source", "source", "event.raw.source", "metadata.source"),
    "host": ("event.host", "host", "metadata.host"),
    "kind": ("event.kind", "kind", "event.raw.kind"),
    "category": ("event.category", "category"),
    "action": ("event.action", "action"),
}


def resolve_logsource_value(event: dict[str, Any], key: str) -> str | None:
    for path in LOGSELECTOR_PATHS.get(key, (f"event.{key}", key)):
        value = deep_get(event, path, MISSING)
        if value is MISSING or value is None:
            continue
        if isinstance(value, dict):
            for inner in ("type", "name", "collector_id", "ip"):
                if inner in value and value[inner]:
                    return str(value[inner])
            continue
        return str(value)
    return None


def logsource_matches(rule: Rule, event: dict[str, Any]) -> bool:
    for key, expected in (rule.logsource or {}).items():
        allowed = {str(v) for v in as_list(expected)}
        actual = resolve_logsource_value(event, key)
        if actual not in allowed:
            return False
    return True


class Engine:
    """Tarama motoru."""

    def __init__(
        self,
        rules: list[Rule],
        suppressions: SuppressionList | None = None,
        dedup_config: DedupConfig | None = None,
        include_disabled: bool = False,
        chains: "ChainConfig | None" = None,
    ) -> None:
        self.rules = [rule for rule in rules if include_disabled or rule.enabled]
        self.disabled_rules = [rule for rule in rules if not rule.enabled]
        self.suppressions = suppressions or SuppressionList()
        self.deduplicator = Deduplicator(dedup_config)
        self.ruleset_hash = ""
        self.chains = chains

    def scan_file(self, path: Path) -> ScanResult:
        events = load_events(path)
        result = self.scan(events)
        result.stats.events_file = str(path)
        return result

    def scan(self, events: list[tuple[int, dict[str, Any]]]) -> ScanResult:
        start = time.perf_counter()
        stats = ScanStats(rules_loaded=len(self.rules) + len(self.disabled_rules), rules_enabled=len(self.rules))
        result = ScanResult(rules=self.rules, suppressions=self.suppressions)

        from .rule_model import LoadReport

        report = LoadReport(rules=self.rules)
        stats.ruleset_hash = report.ruleset_hash
        self.ruleset_hash = report.ruleset_hash

        aggregations = {rule.id: AggregationState(rule) for rule in self.rules if rule.aggregation}

        for line_no, event in events:
            stats.events_scanned += 1
            epoch, _stamp = event_timestamp(event)
            matched_any = False

            for rule in self.rules:
                if not logsource_matches(rule, event):
                    continue
                stats.evaluations += 1
                if not self._matches(rule, event):
                    continue

                matched_any = True
                stats.rule_hits[rule.id] = stats.rule_hits.get(rule.id, 0) + 1
                if rule.id in aggregations:
                    continue

                finding = self._make_finding(rule, event, line_no)
                self._register(finding, rule, epoch, result, stats)

            for rule in self.rules:
                if rule.id not in aggregations or not logsource_matches(rule, event):
                    continue
                if not self._matches(rule, event):
                    continue
                for synthetic in aggregations[rule.id].add(event, line_no, epoch):
                    finding = self._make_finding(rule, synthetic, line_no, aggregated=True)
                    self._register(finding, rule, epoch, result, stats)

            if matched_any:
                stats.events_matched += 1

        # Pencere sonunda kalan gruplar
        for state in aggregations.values():
            stats.aggregation_groups += max(state.total_groups, len(state.groups))
            for synthetic in state.close(None):
                finding = self._make_finding(state.rule, synthetic, None, aggregated=True)
                self._register(finding, state.rule, None, result, stats)

        result.stats = stats
        result.findings = self.deduplicator.records
        stats.unique_findings = self.deduplicator.new_count
        stats.merged_events = self.deduplicator.merged_count
        stats.suppressed_findings = sum(1 for record in result.findings if record.suppressed)
        if self.chains is not None:
            from .chain import ChainCorrelator

            stats.chains = len(ChainCorrelator(self.chains, self.ruleset_hash).apply(result.findings, events))
        stats.rules_matched = len(stats.rule_hits)
        stats.elapsed_ms = int((time.perf_counter() - start) * 1000)
        return result

    # ---- iç yardımcılar --------------------------------------------------
    def _matches(self, rule: Rule, event: dict[str, Any]) -> bool:
        try:
            return rule.logic.evaluate(event)
        except Exception as exc:
            raise RuntimeError('Rule evaluation failed: ' + str(getattr(rule, 'id', 'unknown'))) from exc

    def _make_finding(
        self,
        rule: Rule,
        event: dict[str, Any],
        line_no: int | None,
        aggregated: bool = False,
    ) -> dict[str, Any]:
        extra = []
        if aggregated and isinstance(event.get("aggregation"), dict):
            aggregation = event["aggregation"]
            extra.append(
                {
                    "type": "aggregation",
                    "detail": aggregation.get("summary", ""),
                    "value": aggregation.get("group"),
                }
            )
        if line_no is not None:
            extra.append({"type": "source_file", "detail": f"events.jsonl:{line_no}", "value": line_no})
        finding = enrich_finding(
            rule,
            event,
            event_index=line_no,
            extra_evidence=extra,
            ruleset_hash=self.ruleset_hash,
        )
        return finding

    def _register(
        self,
        finding: dict[str, Any],
        rule: Rule,
        epoch: float | None,
        result: ScanResult,
        stats: ScanStats,
    ) -> None:
        stats.raw_detections += 1
        record, _merged = self.deduplicator.add(rule, finding, epoch)
        if _merged:
            return

        # Kurala bağlı bastırma kimlikleri: bastırma kaydı bulgunun kural kimliğini
        # hedefliyorsa değerlendirme zaten eşleşir. `suppress` alanı burada bir
        # güvenlik ağıdır (kural, bastırma kimliğini kendisi bildirebilir).
        decision = self.suppressions.evaluate(record.finding, epoch)
        if decision is not None:
            record.suppressed = True
            record.suppression_id = decision.entry.id
            record.suppression_reason = decision.reason
            result.suppressed.append(
                SuppressedFinding(
                    finding=record.finding,
                    suppression_id=decision.entry.id,
                    reason=decision.reason,
                )
            )

    # ---- yardımcı çıktı --------------------------------------------------
    def rule_table(self) -> list[dict[str, Any]]:
        return [rule.summary_row() for rule in self.rules]

    def coverage(self, findings: Iterable[dict[str, Any]]) -> dict[str, Any]:
        fired = {str(finding.get("rule_id")) for finding in findings}
        never = sorted(rule.id for rule in self.rules if rule.id not in fired)
        return {
            "fired_rules": len(fired),
            "silent_rules": len(never),
            "silent_rule_ids": never,
        }


def sort_findings(findings: Iterable[dict[str, Any]]) -> list[dict[str, Any]]:
    """Bulguları önem sırasına göre sıralar (skor, severity, zaman)."""
    return sorted(
        findings,
        key=lambda f: (
            -int(f.get("score", 0) or 0),
            -severity_rank(str(f.get("severity", "info"))),
            str(f.get("timestamp", "")),
        ),
    )


def describe_finding_line(finding: dict[str, Any]) -> str:
    return (
        f"{finding.get('finding_id')}  {str(finding.get('severity', '')).upper():<8} "
        f"score={finding.get('score'):<3} {finding.get('rule_id'):<22} "
        f"{truncate(finding.get('host'), 22):<22} {truncate(finding.get('title'), 60)}"
    )


def host_label(event: dict[str, Any]) -> str:
    return host_of(event)
