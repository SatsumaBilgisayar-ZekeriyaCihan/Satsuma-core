"""Ortak yardımcılar: zaman ayrıştırma, JSONL okuma, hash, alan erişimi."""

from __future__ import annotations

import hashlib
import json
import re
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterable, Iterator

_TIMESTAMP_FORMATS = (
    "%Y-%m-%dT%H:%M:%S.%f%z",
    "%Y-%m-%dT%H:%M:%S%z",
    "%Y-%m-%dT%H:%M:%S.%f",
    "%Y-%m-%dT%H:%M:%S",
    "%Y-%m-%d %H:%M:%S.%f",
    "%Y-%m-%d %H:%M:%S",
    "%Y-%m-%dT%H:%M:%SZ",
)

_EPOCH_RE = re.compile(r"^-?\d+(\.\d+)?$")


def now_utc() -> datetime:
    return datetime.now(timezone.utc)


def iso(dt: datetime | None = None) -> str:
    """Zaman damgasını saniye hassasiyetinde `Z` sonlu ISO 8601 biçimine çevirir."""
    dt = dt or now_utc()
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return dt.astimezone(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")


def iso_ms(dt: datetime | None = None) -> str:
    dt = dt or now_utc()
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return dt.astimezone(timezone.utc).isoformat(timespec="milliseconds").replace("+00:00", "Z")


def parse_timestamp(value: Any) -> float | None:
    """Bir çok biçimi kabul ederek epoch saniyeye çevirir.

    Kabul edilenler: epoch (int/float/string), ISO 8601 (`Z` veya offset ile),
    `YYYY-MM-DD HH:MM:SS`. Ayrıştırılamazsa ``None`` döner.
    """
    if value is None:
        return None
    if isinstance(value, bool):
        return None
    if isinstance(value, (int, float)):
        return _normalize_epoch(float(value))
    if isinstance(value, str):
        text = value.strip()
        if not text:
            return None
        if _EPOCH_RE.match(text):
            return _normalize_epoch(float(text))
        candidate = text.replace("Z", "+00:00") if text.endswith("Z") else text
        try:
            dt = datetime.fromisoformat(candidate)
            if dt.tzinfo is None:
                dt = dt.replace(tzinfo=timezone.utc)
            return dt.timestamp()
        except ValueError:
            pass
        for fmt in _TIMESTAMP_FORMATS:
            try:
                dt = datetime.strptime(text, fmt)
                if dt.tzinfo is None:
                    dt = dt.replace(tzinfo=timezone.utc)
                return dt.timestamp()
            except ValueError:
                continue
    return None


def _normalize_epoch(value: float) -> float:
    if value > 1e17:
        return value / 1e9
    if value > 1e14:
        return value / 1e6
    if value > 1e11:
        return value / 1e3
    return value


def epoch_to_iso(value: float | None) -> str | None:
    if value is None:
        return None
    return iso(datetime.fromtimestamp(value, tz=timezone.utc))


def sha256_hex(*parts: Any, length: int | None = None) -> str:
    digest = hashlib.sha256()
    for part in parts:
        digest.update(b"\x1f")
        digest.update(str(part if part is not None else "").encode("utf-8"))
    hexdigest = digest.hexdigest()
    return hexdigest[:length] if length else hexdigest


def deep_get(data: Any, path: str, default: Any = None) -> Any:
    if not path:
        return default
    current = data
    for chunk in path.split("."):
        if isinstance(current, dict):
            if chunk in current:
                current = current[chunk]
                continue
            return default
        if isinstance(current, list):
            try:
                current = current[int(chunk)]
                continue
            except (ValueError, IndexError):
                return default
        return default
    return current


def read_jsonl(path: Path) -> Iterator[tuple[int, dict[str, Any]]]:
    with path.open("r", encoding="utf-8") as handle:
        for lineno, line in enumerate(handle, start=1):
            stripped = line.strip()
            if not stripped:
                continue
            yield lineno, json.loads(stripped)


def load_structured(path: Path) -> Any:
    text = path.read_text(encoding="utf-8")
    if path.suffix.lower() in {".json"}:
        return json.loads(text)
    import yaml
    return yaml.safe_load(text)


def dump_structured(path: Path, payload: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    if path.suffix.lower() == ".json":
        path.write_text(json.dumps(payload, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
        return
    import yaml
    path.write_text(
        yaml.safe_dump(payload, allow_unicode=True, sort_keys=False, default_flow_style=False),
        encoding="utf-8",
    )


def truncate(text: Any, limit: int = 400) -> str:
    value = "" if text is None else str(text)
    if len(value) <= limit:
        return value
    return value[: max(0, limit - 1)] + "…"


def as_list(value: Any) -> list[Any]:
    if value is None:
        return []
    if isinstance(value, (list, tuple, set)):
        return list(value)
    return [value]


def dedupe_preserve(items: Iterable[Any]) -> list[Any]:
    seen: set[Any] = set()
    result: list[Any] = []
    for item in items:
        marker = item if isinstance(item, (str, int, float, bool, type(None))) else json.dumps(item, sort_keys=True, default=str)
        if marker in seen:
            continue
        seen.add(marker)
        result.append(item)
    return result


def relative_to(path: Path, base: Path) -> str:
    try:
        return str(path.resolve().relative_to(base.resolve()))
    except ValueError:
        return str(path)


_MISSING_SENTINEL = object()


def missing_sentinel() -> object:
    return _MISSING_SENTINEL
