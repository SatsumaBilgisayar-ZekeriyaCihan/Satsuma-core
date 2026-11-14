"""Satsuma Engine hata tipleri ve kullanıcıya gösterilecek mesaj biçimleri."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Iterable


@dataclass
class Issue:
    """Tek bir doğrulama bulgusu (hata veya uyarı)."""

    code: str
    message: str
    location: str = ""
    severity: str = "error"
    hint: str = ""
    context: dict[str, Any] = field(default_factory=dict)

    def format(self) -> str:
        parts = []
        if self.location:
            parts.append(self.location)
        parts.append(f"[{self.code}]" if self.code else "")
        parts.append(self.message)
        line = " ".join(p for p in parts if p)
        if self.hint:
            line += f"\n    ipucu: {self.hint}"
        return line


class SatsumaEngineError(Exception):
    """Paket genelinde taban hata tipi."""

    exit_code = 1

    def __init__(self, message: str) -> None:
        super().__init__(message)
        self.message = message


class RuleValidationError(SatsumaEngineError):
    """Kural dosyaları şemaya/yarıyapıya uymadığında yükseltilir."""

    exit_code = 2

    def __init__(self, issues: Iterable[Issue], message: str = "Kural doğrulaması başarısız.") -> None:
        self.issues = list(issues)
        super().__init__(message)

    def render(self) -> str:
        lines = [self.message, ""]
        for issue in self.issues:
            lines.append(f"  - {issue.format()}")
        error_count = sum(1 for i in self.issues if i.severity == "error")
        warning_count = len(self.issues) - error_count
        lines.append("")
        lines.append(f"  toplam: {error_count} hata, {warning_count} uyarı")
        return "\n".join(lines)


class EventFormatError(SatsumaEngineError):
    """Olay (JSONL) verisi okunamadığında yükseltilir."""

    exit_code = 2


class SuppressionError(SatsumaEngineError):
    """Bastırma listesi okunamadığında/geçersiz olduğunda yükseltilir."""

    exit_code = 2


class ConfigurationError(SatsumaEngineError):
    """CLI/çalışma zamanı yapılandırması geçersiz olduğunda yükseltilir."""

    exit_code = 2
