"""Koşul mantığı: derleme, güvenlik denetimi ve değerlendirme.

Kural ve bastırma dosyaları aynı mantık dilini paylaşır:

  Basit koşul:  ``{field: "event.cmd", contains: "nmap"}``
  Grup:         ``{all: [...]}``, ``{any: [...]}``, ``{none: [...]}``, ``{not: {...}}``

Tasarım kararları:
  - Alan yolları noktalı yoldur (``a.b.c``) ve iç içe sözlüklere/listelere erişir.
  - Eksik alan ``None`` kabul edilir; ``exists`` ve ``not_*`` operatörleri bunu ayırt eder.
  - Metin karşılaştırmaları varsayılan olarak büyük/küçük harf duyarlıdır;
    ``ignore_case: true`` ile duyarsız hâle gelir. ``regex`` için ``(?i)`` kullanılır.
  - Regex'ler derleme anında doğrulanır ve ReDoS açısından sezgisel olarak reddedilir.
"""

from __future__ import annotations

import ipaddress
import re
from dataclasses import dataclass, field as dc_field
from functools import lru_cache
from typing import Any, Iterable

from .errors import Issue
from .util import as_list, deep_get

MISSING = object()

# İç içe yineleyici ve katastrofik geri izleme (ReDoS) sezgisel desenleri.
_REDOS_PROBES = (
    re.compile(r"\([^()]{0,80}[+*]\)[+*]"),
    re.compile(r"\([^()]{0,80}\{\d+,\}\)[+*]"),
    re.compile(r"\.\*\.\*"),
    re.compile(r"\(\.\*\)[+*]"),
)


def check_regex_safety(pattern: str) -> str | None:
    """Deseni ReDoS/karmaşıklık açısından denetler; sorun varsa açıklama döner."""
    if len(pattern) > 512:
        return "Regex 512 karakter sınırını aşıyor."
    for probe in _REDOS_PROBES:
        if probe.search(pattern):
            return (
                "Regex iç içe yineleyici içeriyor ve katastrofik geri izleme (ReDoS) riski taşıyor. "
                "Deseni basitleştirin veya `contains_any` operatörünü kullanın."
            )
    return None


@lru_cache(maxsize=4096)
def compile_regex(pattern: str) -> re.Pattern[str]:
    return re.compile(pattern)


def _text_values(value: Any) -> list[str]:
    return [str(v) for v in as_list(value) if v is not None]


def _as_float(value: Any) -> float | None:
    if isinstance(value, bool):
        return None
    if isinstance(value, (int, float)):
        return float(value)
    if isinstance(value, str):
        try:
            return float(value.strip())
        except ValueError:
            return None
    return None


def _cmp_text(value: Any, other: Any, ignore_case: bool) -> bool:
    left, right = str(value), str(other)
    if ignore_case:
        return left.casefold() == right.casefold()
    return left == right


@dataclass
class CompiledLogic:
    """Derlenmiş mantık düğümü; ``evaluate`` ile olay üzerinde çalıştırılır."""

    raw: dict[str, Any]
    location: str = "match"
    field: str | None = None
    ignore_case: bool = False
    regexes: dict[str, re.Pattern[str]] = dc_field(default_factory=dict)
    groups: dict[str, list["CompiledLogic"]] = dc_field(default_factory=dict)
    negate: "CompiledLogic | None" = None
    issues: list[Issue] = dc_field(default_factory=list)

    # ---- derleme ---------------------------------------------------------
    @classmethod
    def compile(cls, raw: Any, location: str = "match") -> "CompiledLogic":
        if not isinstance(raw, dict):
            node = cls(raw={}, location=location)
            node.issues.append(
                Issue(
                    code="rule.logic_type",
                    message=f"Mantık bloğu sözlük olmalı, {type(raw).__name__} bulundu.",
                    location=location,
                    hint='Örnek: {"field": "event.cmd", "contains": "nmap"}',
                )
            )
            return node

        node = cls(raw=raw, location=location)
        node.field = raw.get("field")
        node.ignore_case = bool(raw.get("ignore_case", False))

        if node.field is None:
            for key in ("all", "any", "none"):
                if key in raw:
                    children = [cls.compile(item, f"{location}.{key}") for item in as_list(raw[key])]
                    node.groups[key] = children
                    for child in children:
                        node.issues.extend(child.issues)
            if "not" in raw:
                node.negate = cls.compile(raw["not"], f"{location}.not")
                node.issues.extend(node.negate.issues)
            if not node.groups and node.negate is None:
                node.issues.append(
                    Issue(
                        code="rule.logic_empty",
                        message="Mantık bloğu ne `field` ne de all/any/none/not içeriyor.",
                        location=location,
                    )
                )
            return node

        for key in ("regex", "not_regex"):
            if key in raw:
                pattern = raw[key]
                problem = check_regex_safety(pattern)
                if problem:
                    node.issues.append(
                        Issue("rule.regex_unsafe", problem, f"{location}.{key}", hint=f"desen: {pattern}")
                    )
                    continue
                try:
                    node.regexes[key] = compile_regex(pattern)
                except re.error as exc:
                    node.issues.append(
                        Issue("rule.regex_invalid", f"Regex derlenemedi: {exc}", f"{location}.{key}")
                    )
        return node

    # ---- değerlendirme ---------------------------------------------------
    def evaluate(self, event: dict[str, Any]) -> bool:
        if self.field is not None:
            return self._evaluate_condition(event)

        for key, children in self.groups.items():
            results = [child.evaluate(event) for child in children]
            if key == "all" and not all(results):
                return False
            if key == "any" and not any(results):
                return False
            if key == "none" and any(results):
                return False
        if self.negate is not None and self.negate.evaluate(event):
            return False
        return True

    def _evaluate_condition(self, event: dict[str, Any]) -> bool:
        raw = self.raw
        value = deep_get(event, self.field or "", MISSING)

        if "exists" in raw:
            present = value is not MISSING and value is not None
            if bool(raw["exists"]) != present:
                return False

        checks: list[bool] = []
        presence_checked = "exists" in raw

        if "equals" in raw:
            checks.append(value is not MISSING and any(_cmp_text(value, expected, self.ignore_case) for expected in _text_values(raw["equals"])))
            presence_checked = True
        if "in" in raw:
            checks.append(value is not MISSING and any(_cmp_text(value, expected, self.ignore_case) for expected in _text_values(raw["in"])))
            presence_checked = True
        if "not_equals" in raw:
            if value is not MISSING:
                checks.append(not any(_cmp_text(value, expected, self.ignore_case) for expected in _text_values(raw["not_equals"])))
        if "not_in" in raw:
            if value is not MISSING:
                checks.append(not any(_cmp_text(value, expected, self.ignore_case) for expected in _text_values(raw["not_in"])))

        text = None if value is MISSING or value is None else str(value)

        if "contains" in raw or "not_contains" in raw:
            needle = str(raw.get("contains", raw.get("not_contains", "")))
            hit = text is not None and self._substring(hit_source=text, needle=needle)
            checks.append(hit if "contains" in raw else not hit)
            presence_checked = True
        if "contains_any" in raw:
            checks.append(text is not None and any(self._substring(text, str(n)) for n in as_list(raw["contains_any"])))
            presence_checked = True
        if "contains_all" in raw:
            checks.append(text is not None and all(self._substring(text, str(n)) for n in as_list(raw["contains_all"])))
            presence_checked = True
        if "startswith" in raw:
            prefix = str(raw["startswith"])
            checks.append(text is not None and (text.casefold().startswith(prefix.casefold()) if self.ignore_case else text.startswith(prefix)))
            presence_checked = True
        if "endswith" in raw:
            suffix = str(raw["endswith"])
            checks.append(text is not None and (text.casefold().endswith(suffix.casefold()) if self.ignore_case else text.endswith(suffix)))
            presence_checked = True

        if "regex" in raw:
            pattern = self.regexes.get("regex")
            checks.append(text is not None and pattern is not None and pattern.search(text) is not None)
            presence_checked = True
        if "not_regex" in raw:
            pattern = self.regexes.get("not_regex")
            if text is not None and pattern is not None:
                checks.append(pattern.search(text) is None)

        if "cidr" in raw or "not_cidr" in raw:
            hit = value is not MISSING and self._in_cidr(value, as_list(raw.get("cidr", raw.get("not_cidr"))))
            checks.append(hit if "cidr" in raw else not hit)
            presence_checked = True

        numeric = _as_float(value)
        for op, compare in (("gt", lambda a, b: a > b), ("gte", lambda a, b: a >= b), ("lt", lambda a, b: a < b), ("lte", lambda a, b: a <= b)):
            if op in raw:
                bound = _as_float(raw[op])
                checks.append(numeric is not None and bound is not None and compare(numeric, bound))
                presence_checked = True

        if "length_gt" in raw or "length_lt" in raw:
            size = len(value) if isinstance(value, (str, list, tuple, dict)) else None
            if "length_gt" in raw:
                checks.append(size is not None and size > int(raw["length_gt"]))
            if "length_lt" in raw:
                checks.append(size is not None and size < int(raw["length_lt"]))
            presence_checked = True

        if not checks:
            # Yalnızca `exists` verilmişse sonucu o belirler.
            return presence_checked
        return all(checks)

    def _substring(self, hit_source: str, needle: str) -> bool:
        if self.ignore_case:
            return needle.casefold() in hit_source.casefold()
        return needle in hit_source

    @staticmethod
    def _in_cidr(value: Any, networks: Iterable[Any]) -> bool:
        try:
            address = ipaddress.ip_address(str(value).strip())
        except ValueError:
            return False
        for network in networks:
            try:
                if address in ipaddress.ip_network(str(network).strip(), strict=False):
                    return True
            except ValueError:
                continue
        return False

    # ---- yardımcılar -----------------------------------------------------
    def fields(self) -> list[str]:
        """Bu düğümde kullanılan alan yollarını döndürür (kanıt çıkarımı için)."""
        found: list[str] = []
        if self.field:
            found.append(self.field)
        for children in self.groups.values():
            for child in children:
                found.extend(child.fields())
        if self.negate is not None:
            found.extend(self.negate.fields())
        return found

    def operator_names(self) -> list[str]:
        return [key for key in self.raw if key not in {"field", "ignore_case"}]
