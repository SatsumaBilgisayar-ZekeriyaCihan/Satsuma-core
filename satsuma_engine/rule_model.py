"""Kural modeli: yükleme, şema doğrulaması, anlam denetimi ve derleme.

İki katmanlı doğrulama uygulanır:
  1. **Şema doğrulaması** (`jsonschema`, `rule.schema.json`): tip/format/zorunlu alanlar.
  2. **Anlam denetimi**: şemanın ifade edemediği kurallar — tekil kimlik, geçerli regex,
     kullanılmayan alanlar, tutarsız aggregation, eksik MITRE kimlikleri.

Her iki katman da hataları okunabilir `Issue` nesneleri olarak döner; CLI bunları
`<dosya>:<yol>` biçiminde ve ipuçlarıyla birlikte gösterir.
"""

from __future__ import annotations

from dataclasses import dataclass, field as dc_field
from pathlib import Path
from typing import Any, Iterable

from . import RULE_API_VERSION
from .conditions import CompiledLogic
from .errors import Issue, RuleValidationError
from .mitre import enrich as enrich_mitre, validate_mitre
from .schema_store import validate_instance
from .util import (
    as_list,
    dedupe_preserve,
    load_structured,
    read_jsonl,
    relative_to,
    sha256_hex,
)

SEVERITY_BASE_SCORE = {"info": 10, "low": 25, "medium": 50, "high": 75, "critical": 90}

CLASSIFICATION_FROM_SEVERITY = {
    "info": "indicator",
    "low": "indicator",
    "medium": "suspicious",
    "high": "likely",
    "critical": "confirmed",
}

CONFIDENCE_FROM_CLASSIFICATION = {
    "indicator": "low",
    "suspicious": "medium",
    "likely": "high",
    "confirmed": "high",
}

VALID_ACTIONS = {
    "log_only",
    "create_ticket",
    "ask_user",
    "notify_admin",
    "kill_process",
    "block_ip",
    "quarantine_file",
    "isolate_host",
}

RULE_SUFFIXES = (".yaml", ".yml", ".json")


@dataclass
class Rule:
    """Doğrulanmış ve derlenmiş tek tespit kuralı."""

    data: dict[str, Any]
    source_path: Path
    logic: CompiledLogic
    issues: list[Issue] = dc_field(default_factory=list)

    # ---- temel alanlar ---------------------------------------------------
    @property
    def id(self) -> str:
        return self.data["id"]

    @property
    def title(self) -> str:
        return self.data["title"]

    @property
    def description(self) -> str:
        return self.data.get("description", "")

    @property
    def severity(self) -> str:
        return self.data["severity"]

    @property
    def classification(self) -> str:
        explicit = self.data.get("classification")
        return explicit or CLASSIFICATION_FROM_SEVERITY[self.severity]

    @property
    def confidence(self) -> str:
        explicit = self.data.get("confidence")
        return explicit or CONFIDENCE_FROM_CLASSIFICATION[self.classification]

    @property
    def category(self) -> str:
        return self.data.get("category", "")

    @property
    def tags(self) -> list[str]:
        return list(self.data.get("tags") or [])

    @property
    def actions(self) -> list[str]:
        return list(self.data.get("actions") or [])

    @property
    def log_only(self) -> bool:
        return self.actions == ["log_only"] or (not self.actions and self.classification == "indicator")

    @property
    def mitre(self) -> list[dict[str, str]]:
        return enrich_mitre(self.data.get("mitre"))

    @property
    def logsource(self) -> dict[str, Any]:
        return self.data.get("logsource") or {}

    @property
    def aggregation(self) -> dict[str, Any] | None:
        return self.data.get("aggregation")

    @property
    def suppression_refs(self) -> list[str]:
        return list(self.data.get("suppress") or [])

    @property
    def enabled(self) -> bool:
        return bool(self.data.get("enabled", True))

    @property
    def source_file(self) -> str:
        return str(self.source_path)

    # ---- skorlama --------------------------------------------------------
    @property
    def base_score(self) -> int:
        scoring = self.data.get("scoring") or {}
        return int(scoring.get("base", SEVERITY_BASE_SCORE[self.severity]))

    @property
    def score_bounds(self) -> tuple[int, int]:
        scoring = self.data.get("scoring") or {}
        return int(scoring.get("min", 0)), int(scoring.get("max", 100))

    @property
    def score_modifiers(self) -> list[dict[str, Any]]:
        return list((self.data.get("scoring") or {}).get("modifiers") or [])

    # ---- tekilleştirme ---------------------------------------------------
    @property
    def dedup_key_fields(self) -> list[str]:
        dedup = self.data.get("dedup") or {}
        return list(dedup.get("key") or self.data.get("entity") or [])

    @property
    def dedup_window_seconds(self) -> int:
        return int((self.data.get("dedup") or {}).get("window_seconds", 3600))

    @property
    def dedup_group(self) -> str:
        return self.data.get("dedup_group") or self.id

    def matched_fields(self) -> list[str]:
        return dedupe_preserve(self.logic.fields())

    def to_dict(self) -> dict[str, Any]:
        return self.data

    def summary_row(self) -> dict[str, Any]:
        """`rules list` komutu için özet satır üretir."""
        return {
            "id": self.id,
            "title": self.title,
            "severity": self.severity,
            "classification": self.classification,
            "confidence": self.confidence,
            "category": self.category,
            "enabled": self.enabled,
            "rules": 1,
            "aggregation": bool(self.aggregation),
            "actions": ",".join(self.actions) or "log_only",
            "mitre": ",".join(m["technique"] for m in self.mitre),
            "source_file": Path(self.source_file).name,
        }


@dataclass
class LoadReport:
    """Yükleme sonucu: geçerli kurallar + tüm uyarılar."""

    rules: list[Rule] = dc_field(default_factory=list)
    warnings: list[Issue] = dc_field(default_factory=list)
    errors: list[Issue] = dc_field(default_factory=list)
    files_scanned: int = 0
    files_failed: int = 0

    @property
    def ruleset_hash(self) -> str:
        return sha256_hex(*(rule.id for rule in sorted(self.rules, key=lambda r: r.id)), length=16)

    @property
    def ok(self) -> bool:
        return not self.errors


def discover_rule_files(paths: Iterable[Path]) -> list[Path]:
    """Verilen yol listesinden kural dosyalarını (yinelemeli) bulur."""
    files: list[Path] = []
    for path in paths:
        if path.is_dir():
            files.extend(sorted(p for p in path.rglob("*") if p.suffix.lower() in RULE_SUFFIXES))
        elif path.is_file():
            files.append(path)
        else:
            raise RuleValidationError(
                [Issue("io.missing", f"Yol bulunamadı: {path}", severity="error")],
                "Kural yolu okunamadı.",
            )
    return files


def _load_documents(path: Path) -> list[dict[str, Any]]:
    """Bir kural dosyasını okuyup kural sözlükleri listesine çevirir.

    Kabul edilen üst düzey biçimler:
      - Tek kural sözlüğü
      - Kural listesi
      - ``{rules: [...]}`` sarmalayıcısı
      - ``{suppressions: [...]}`` sarmalayıcısı (bastırma dosyası -> atlanır)
    """
    payload = load_structured(path)
    if payload is None:
        return []
    if isinstance(payload, dict):
        if "suppressions" in payload and "rules" not in payload:
            return []
        if "rules" in payload:
            payload = payload["rules"]
        else:
            payload = [payload]
    if not isinstance(payload, list):
        raise RuleValidationError(
            [Issue("rule.file_shape", "Kural dosyası sözlük, liste veya {rules: [...]} olmalı.", str(path))],
            "Kural dosyası biçimi geçersiz.",
        )
    return [item for item in payload if isinstance(item, dict)]


def _semantic_issues(data: dict[str, Any], location: str) -> list[Issue]:
    """Şemanın ifade edemediği anlam denetimleri."""
    issues: list[Issue] = []

    issues.extend(validate_mitre(data.get("mitre"), f"{location}.mitre"))

    actions = as_list(data.get("actions"))
    unknown = [a for a in actions if a not in VALID_ACTIONS]
    if unknown:
        issues.append(
            Issue(
                "rule.action_unknown",
                f"Tanınmayan aksiyon(lar): {', '.join(map(str, unknown))}",
                f"{location}.actions",
                hint=f"Geçerli aksiyonlar: {', '.join(sorted(VALID_ACTIONS))}",
            )
        )

    aggregation = data.get("aggregation")
    if aggregation:
        if aggregation.get("type") == "count_distinct" and not aggregation.get("count_distinct_field"):
            issues.append(
                Issue(
                    "rule.aggregation_count_distinct_field",
                    "`count_distinct` türü için `count_distinct_field` zorunludur.",
                    f"{location}.aggregation",
                )
            )
        if not aggregation.get("group_by"):
            issues.append(
                Issue(
                    "rule.aggregation_group_by",
                    "Aggregation kuralında `group_by` verilmemesi tüm olayları tek kovaya toplar.",
                    f"{location}.aggregation",
                    severity="warning",
                    hint="Örnek: `group_by: [event.src_ip]`",
                )
            )

    logic = data.get("match")
    if isinstance(logic, dict) and "field" in logic:
        other_keys = set(logic) - {"field", "ignore_case"}
        if not other_keys:
            issues.append(
                Issue(
                    "rule.condition_has_no_operator",
                    "Koşul yalnızca `field` içeriyor; karşılaştırma operatörü yok.",
                    f"{location}.match",
                    hint="Örn. `contains`, `equals`, `regex`, `exists` gibi bir operatör ekleyin.",
                )
            )

    dead = _dead_fields(data, location)
    issues.extend(dead)

    if data.get("enabled") is False:
        issues.append(
            Issue("rule.disabled", "Kural devre dışı (`enabled: false`).", location, severity="warning")
        )
    return issues


def _dead_fields(data: dict[str, Any], location: str) -> list[Issue]:
    """Etkisi olmayan alan kombinasyonlarını tespit eder (ürünün `context` boşluğunun tekrarını önler)."""
    issues: list[Issue] = []
    if data.get("dedup") and data.get("entity"):
        issues.append(
            Issue(
                "rule.dedup_conflict",
                "Hem `dedup.key` hem `entity` verilmiş; `dedup.key` öncelikli olur, `entity` yok sayılır.",
                f"{location}.dedup",
                severity="warning",
            )
        )
    if data.get("classification") == "confirmed" and "create_ticket" not in as_list(data.get("actions")):
        issues.append(
            Issue(
                "rule.confirmed_without_ticket",
                "`classification: confirmed` kuralı `create_ticket` aksiyonu içermiyor; otomatik müdahale tetiklenmez.",
                f"{location}.actions",
                severity="warning",
            )
        )
    return issues


def _compile_rule(data: dict[str, Any], path: Path) -> tuple[Rule | None, list[Issue]]:
    """Tek kuralı doğrular ve derler."""
    location = path.name
    problems: list[Issue] = []

    if data.get("schema") not in (None, RULE_API_VERSION):
        problems.append(
            Issue(
                "rule.schema_version",
                f"Desteklenmeyen sözleşme sürümü: {data.get('schema')!r}",
                f"{location}.schema",
                hint=f"Beklenen: {RULE_API_VERSION}",
            )
        )
        return None, problems

    # Şema doğrulaması için `schema` alanını tamamlayıp açıklama alanlarını normalize et.
    candidate = dict(data)
    candidate.setdefault("schema", RULE_API_VERSION)
    candidate.setdefault("title", str(data.get("name") or data.get("id") or "").strip() or "Untitled rule")
    candidate.setdefault("description", "")
    if "base_match" in candidate and "match" not in candidate:
        candidate["match"] = candidate.pop("base_match")

    schema_issues = validate_instance("rule", candidate, location)
    if schema_issues:
        return None, schema_issues

    problems.extend(_semantic_issues(candidate, location))

    logic = CompiledLogic.compile(candidate.get("match"), f"{location}.match")
    problems.extend(logic.issues)
    if any(issue.severity == "error" for issue in logic.issues):
        return None, problems

    rule = Rule(data=candidate, source_path=path, logic=logic, issues=problems)
    return rule, problems


def load_rules(paths: Iterable[Path], strict: bool = True) -> LoadReport:
    """Kural dosyalarını yükler.

    Args:
        paths: Kural dosyaları veya dizinleri.
        strict: ``True`` ise herhangi bir hata `RuleValidationError` yükseltir.

    Returns:
        `LoadReport` — geçerli kurallar, uyarılar ve hatalar.
    """
    files = discover_rule_files(paths)
    report = LoadReport(files_scanned=len(files))
    seen: dict[str, str] = {}

    for path in files:
        try:
            documents = _load_documents(path)
        except RuleValidationError as exc:
            report.errors.extend(exc.issues)
            report.files_failed += 1
            continue
        except Exception as exc:  # YAML/JSON ayrıştırma hatası
            report.errors.append(
                Issue("io.parse", f"Dosya ayrıştırılamadı: {exc}", relative_to(path, Path.cwd()))
            )
            report.files_failed += 1
            continue

        for data in documents:
            rule_id = str(data.get("id", "")).strip()
            if rule_id and rule_id in seen:
                report.errors.append(
                    Issue(
                        "rule.duplicate_id",
                        f"Tekil kural kimliği tekrar ediyor: {rule_id}",
                        f"{path.name}:{rule_id}",
                        hint=f"İlk tanım: {seen[rule_id]}",
                    )
                )
                continue

            rule, issues = _compile_rule(data, path)
            if rule is None:
                report.errors.extend(i for i in issues if i.severity == "error")
                report.warnings.extend(i for i in issues if i.severity != "error")
                report.files_failed += 1
                continue
            semantic_errors = [i for i in issues if i.severity == "error"]
            report.warnings.extend(i for i in issues if i.severity != "error")
            if semantic_errors:
                # Anlam denetiminden geçmeyen kural yüklenmez: eksik aggregation veya
                # operatörsüz koşul sessizce çalışırsa yanlış/eksik tespit üretir.
                report.errors.extend(semantic_errors)
                report.files_failed += 1
                continue
            if rule_id:
                seen[rule_id] = path.name
            report.rules.append(rule)

    if strict and report.errors:
        raise RuleValidationError(report.errors, "Kural doğrulaması başarısız.")
    return report


def load_ruleset(paths: Iterable[Path], strict: bool = True) -> tuple[list[Rule], list[Issue]]:
    report = load_rules(paths, strict=strict)
    return report.rules, report.warnings


def load_events(path: Path) -> list[tuple[int, dict[str, Any]]]:
    """JSONL olay dosyasını okur ve satır numaralarıyla döner."""
    from .errors import EventFormatError

    if not path.exists():
        raise EventFormatError(f"Olay dosyası bulunamadı: {path}")
    try:
        return list(read_jsonl(path))
    except Exception as exc:
        raise EventFormatError(f"Olay dosyası okunamadı ({path}): {exc}") from exc
