"""Satsuma Core -> Atom Engine adaptörü (salt okunur).

Core'un SQLite deposunu (``/var/lib/satsuma-core/core.db``) hiç yazmadan okur ve
Atom'un olay zarfına (``{"id", "source", "event": {...}}``) çevirir.

Kaynak tablolar (otomatik seçilir):
  1. ``evidence_v2``  — Satsuma Core 1.2.x (Evidence Core V2): değiştirilemez kanıt kayıtları.
  2. ``records``      — eski/1.3.0 yolu: ``kind`` + JSON ``body`` (normalize olay).

Güvenlik ilkeleri:
  - Veritabanı ``mode=ro`` ile açılır; Core'un tablolarına, bulgularına veya aksiyonlarına dokunulmaz.
  - Adaptör aksiyon üretmez. Atom çıktısı yalnızca öneridir.
  - Süreç kimliği (boot_id|pid|starttime) varsa olaya ``process_key`` olarak taşınır;
    tekilleştirme yalnızca bu güçlü kimliğe dayanmalıdır (tek başına PID zayıf kanıttır).

Kullanım::

    python -m satsuma_engine.adapters.satsuma_core --db /var/lib/satsuma-core/core.db \\
        --out events.jsonl --state cursor.json
"""
from __future__ import annotations

import argparse
import json
import sqlite3
import sys
from pathlib import Path
from typing import Any, Iterator

DEFAULT_DB = "/var/lib/satsuma-core/core.db"

# Core kaynak ailesi -> Atom/legacy kaynak adı (kurallar ``sys_proc`` gibi adlara alışkın)
_FAMILY_TO_SOURCE = {"process": "sys_proc", "audit": "sys_audit", "file": "sys_file", "journal": "sys_journal"}
_ATOM_KINDS = {"process", "file", "auth", "network", "dns"}


class CoreSourceError(RuntimeError):
    pass


def _loads(text: Any) -> dict[str, Any]:
    try:
        value = json.loads(text) if isinstance(text, (str, bytes)) else text
    except (TypeError, ValueError):
        return {}
    return value if isinstance(value, dict) else {}


def _pick(d: dict, *keys: str) -> Any:
    for k in keys:
        if d.get(k) not in (None, ""):
            return d[k]
    return None


def _set(target: dict, key: str, value: Any) -> None:
    if value not in (None, ""):
        target[key] = value


def _infer_kind(raw_kind: str, proc, file_, net, attrs: dict) -> str:
    explicit = str(attrs.get("kind") or "").lower()
    if explicit in _ATOM_KINDS:
        return explicit
    if file_ and file_.get("path"):  # dosya erişimi, süreç bilgisi olsa da `file` olayıdır
        return "file"
    if proc:
        return "process"
    if net:
        return "network"
    low = (raw_kind or "").lower()
    for k in _ATOM_KINDS:
        if k in low:
            return k
    return low or "observation"


def evidence_to_event(row_id: int, body: dict[str, Any], default_host: str = "") -> dict[str, Any]:
    """Tek bir Evidence V2 kaydını Atom olay zarfına çevirir."""
    attrs = body.get("attributes") or {}
    prov = body.get("provenance") or {}
    proc = body.get("process") or None
    file_ = body.get("file") or None
    net = body.get("network") or None
    family = str(body.get("source_family") or "unknown")

    ev: dict[str, Any] = {}
    ts = body.get("observed_at")
    ev["timestamp"] = ts if ts not in (None, "") else body.get("ingested_at") or "1970-01-01T00:00:00Z"
    _set(ev, "host", _pick(attrs, "host", "hostname") or prov.get("host") or default_host)
    ev["kind"] = _infer_kind(str(body.get("kind") or ""), proc, file_, net, attrs)
    _set(ev, "action", body.get("kind"))
    _set(ev, "severity", body.get("severity"))
    _set(ev, "source_family", family)

    if proc:
        _set(ev, "pid", proc.get("pid"))
        _set(ev, "ppid", proc.get("ppid"))
        _set(ev, "uid", proc.get("uid"))
        _set(ev, "gid", proc.get("gid"))
        _set(ev, "exe", proc.get("exe"))
        _set(ev, "process_key", proc.get("identity_key"))  # boot|pid|starttime (güçlü kimlik)
    _set(ev, "cmd", _pick(attrs, "cmd", "command", "cmdline", "args"))
    _set(ev, "parent_cmd", _pick(attrs, "parent_cmd", "parent"))
    _set(ev, "user", _pick(attrs, "user", "username"))
    _set(ev, "operation", _pick(attrs, "operation", "op", "syscall"))

    if file_:
        _set(ev, "file_path", file_.get("path"))
        _set(ev, "path", file_.get("path"))
        _set(ev, "file_sha256", file_.get("sha256"))
        _set(ev, "file_key", "|".join(str(file_.get(k)) for k in ("device", "inode") if file_.get(k) is not None) or None)
    if net:
        _set(ev, "src_ip", net.get("src_ip"))
        _set(ev, "dest_ip", net.get("dst_ip") or net.get("dest_ip"))
        _set(ev, "src_port", net.get("src_port"))
        _set(ev, "dest_port", net.get("dst_port") or net.get("dest_port"))
        _set(ev, "proto", net.get("proto"))

    # Kalan öznitelikleri `extra` altında koru; çakışma yaratmasın.
    known = {"host", "hostname", "cmd", "command", "cmdline", "args", "parent_cmd", "parent", "user", "username",
             "operation", "op", "syscall", "kind"}
    extra = {k: v for k, v in attrs.items() if k not in known}
    if extra:
        ev["extra"] = extra
    _set(ev, "audit_serial", body.get("audit_serial"))

    return {
        "id": body.get("evidence_id") or f"core-{row_id}",
        "raw_id": body.get("source_event_id"),
        "source": _FAMILY_TO_SOURCE.get(family, family),
        "cursor": row_id,
        "event": ev,
    }


def record_to_event(row_id: int, kind: str, created: float, body: dict[str, Any], default_host: str = "") -> dict[str, Any] | None:
    """Eski ``records`` satırı (normalize olay) -> Atom zarfı."""
    if isinstance(body.get("event"), dict):  # zaten zarf biçiminde
        env = dict(body)
        env.setdefault("id", f"core-rec-{row_id}")
        env["cursor"] = row_id
        env["event"].setdefault("host", default_host)
        return env
    flat = {k: v for k, v in body.items() if k not in ("source",)}
    if not flat:
        return None
    flat.setdefault("timestamp", created)
    flat.setdefault("kind", kind)
    if default_host:
        flat.setdefault("host", default_host)
    return {"id": f"core-rec-{row_id}", "source": body.get("source") or kind, "cursor": row_id, "event": flat}


class CoreSource:
    """Core veritabanını salt okunur açar ve olay üretir."""

    def __init__(self, db_path: str | Path = DEFAULT_DB, *, default_host: str = ""):
        self.path = Path(db_path)
        if not self.path.exists():
            raise CoreSourceError(f"Core veritabanı bulunamadı: {self.path}")
        self.default_host = default_host
        uri = f"file:{self.path}?mode=ro"
        try:
            self.db = sqlite3.connect(uri, uri=True, timeout=10.0)
            self.db.execute("PRAGMA query_only=ON")
            self.tables = {r[0] for r in self.db.execute("SELECT name FROM sqlite_master WHERE type='table'")}
        except sqlite3.Error as exc:
            raise CoreSourceError(f"Core veritabanı salt okunur açılamadı ({self.path}): {exc}") from exc
        if "evidence_v2" in self.tables:
            self.backend = "evidence_v2"
        elif "records" in self.tables:
            self.backend = "records"
        else:
            raise CoreSourceError("Tanınan tablo yok (evidence_v2 / records). Bu Core sürümü desteklenmiyor.")

    def close(self) -> None:
        self.db.close()

    def iter_events(self, after: int = 0, limit: int | None = None) -> Iterator[dict[str, Any]]:
        """``after`` rowid'inden sonraki kayıtları sırayla üretir (artımlı okuma)."""
        lim = f" LIMIT {int(limit)}" if limit else ""
        if self.backend == "evidence_v2":
            cur = self.db.execute(f"SELECT rowid, body FROM evidence_v2 WHERE rowid>? ORDER BY rowid{lim}", (after,))
            for rid, body in cur:
                yield evidence_to_event(rid, _loads(body), self.default_host)
        else:
            cur = self.db.execute(f"SELECT id, kind, created, body FROM records WHERE id>? ORDER BY id{lim}", (after,))
            for rid, kind, created, body in cur:
                env = record_to_event(rid, kind, created, _loads(body), self.default_host)
                if env:
                    yield env


def export_jsonl(db_path: str, out: Path, state: Path | None = None, limit: int | None = None, host: str = "") -> dict[str, Any]:
    """Yeni olayları JSONL'e ekler; imleci ``state`` dosyasında saklar."""
    after = 0
    if state and state.exists():
        after = int(_loads(state.read_text(encoding="utf-8")).get("cursor", 0))
    src = CoreSource(db_path, default_host=host)
    n = last = 0
    try:
        with out.open("a", encoding="utf-8") as fh:
            for env in src.iter_events(after, limit):
                last = env.pop("cursor")
                fh.write(json.dumps(env, ensure_ascii=False) + "\n")
                n += 1
    finally:
        backend = src.backend
        src.close()
    if state and n:
        state.write_text(json.dumps({"cursor": last, "backend": backend}), encoding="utf-8")
    return {"backend": backend, "exported": n, "cursor": last or after}


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(prog="satsuma-core-export", description="Satsuma Core -> Atom olay dışa aktarımı (salt okunur)")
    p.add_argument("--db", default=DEFAULT_DB)
    p.add_argument("--out", required=True, type=Path)
    p.add_argument("--state", type=Path, help="artımlı okuma imleci (JSON)")
    p.add_argument("--limit", type=int)
    p.add_argument("--host", default="", help="olayda host yoksa kullanılacak ad")
    a = p.parse_args(argv)
    try:
        r = export_jsonl(a.db, a.out, a.state, a.limit, a.host)
    except CoreSourceError as exc:
        print(f"HATA: {exc}", file=sys.stderr)
        return 2
    print(json.dumps(r, ensure_ascii=False))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
