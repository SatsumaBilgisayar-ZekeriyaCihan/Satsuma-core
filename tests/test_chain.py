"""Zincir korelasyonu testleri: kurulması VE kurulmaması gereken durumlar."""
from __future__ import annotations
import json
from pathlib import Path

import yaml

from satsuma_engine.chain import ChainConfig, DESTRUCTIVE_ACTIONS
from satsuma_engine.engine import Engine
from satsuma_engine.findings import validate_finding
from satsuma_engine.rule_model import load_ruleset
from satsuma_engine.suppression import SuppressionList

K = "boot-1|4242|111"


def _rule(rid, needle, classification="suspicious", actions=None):
    return {"schema": "satsuma/v1", "id": rid, "title": f"Kural {rid}", "severity": "high", "classification": classification,
            "confidence": "medium", "logsource": {"kind": "process"},
            "match": {"field": "event.cmd", "contains": needle}, "actions": actions or ["create_ticket"]}


def _ev(eid, cmd, ts, family="process", key=K, pid=4242, host="h1"):
    e = {"timestamp": ts, "host": host, "kind": "process", "cmd": cmd, "pid": pid, "source_family": family}
    if key:
        e["process_key"] = key
    return {"id": eid, "source": family, "event": e}


def _scan(tmp_path, rules, events, chains=True, suppressions=None, **cfg):
    rf = tmp_path / "r.yaml"; rf.write_text(yaml.safe_dump(rules, allow_unicode=True), encoding="utf-8")
    ef = tmp_path / "e.jsonl"; ef.write_text("\n".join(json.dumps(e) for e in events) + "\n", encoding="utf-8")
    rs, _ = load_ruleset([rf], strict=False)
    engine = Engine(rs, suppressions=suppressions, chains=ChainConfig(**cfg) if chains else None)
    return engine.scan_file(ef)


def _chains(result):
    return [f for f in result.findings_as_dicts() if f["rule_id"] == "SATSUMA-CHAIN-001"]


RULES = [_rule("T-A", "marker-a", actions=["create_ticket", "kill_process", "block_ip"]), _rule("T-B", "marker-b")]


def test_independent_families_on_same_process_become_confirmed(tmp_path):
    r = _scan(tmp_path, RULES, [_ev("1", "x marker-a", "2026-10-10T09:00:00Z", "process"),
                                _ev("2", "y marker-b", "2026-10-10T09:00:08Z", "audit")])
    (c,) = _chains(r)
    assert c["classification"] == "confirmed" and c["confidence"] == "high"
    assert c["extensions"]["chain"]["families"] == ["audit", "process"]
    assert validate_finding(c) == []
    assert r.stats.chains == 1


def test_chain_never_carries_destructive_actions(tmp_path):
    r = _scan(tmp_path, RULES, [_ev("1", "x marker-a", "2026-10-10T09:00:00Z", "process"),
                                _ev("2", "y marker-b", "2026-10-10T09:00:08Z", "audit")])
    (c,) = _chains(r)
    assert not (set(c["actions"]) & DESTRUCTIVE_ACTIONS)
    assert "create_ticket" in c["actions"]


def test_same_family_repeats_cannot_self_confirm(tmp_path):
    r = _scan(tmp_path, RULES, [_ev("1", "x marker-a", "2026-10-10T09:00:00Z", "process"),
                                _ev("2", "y marker-b", "2026-10-10T09:00:08Z", "process")])
    (c,) = _chains(r)
    assert c["classification"] != "confirmed"
    assert c["extensions"]["chain"]["independent_families"] is False


def test_pid_reuse_with_different_identity_never_chains(tmp_path):
    r = _scan(tmp_path, RULES, [_ev("1", "x marker-a", "2026-10-10T09:00:00Z", "process", key="boot-1|4242|111"),
                                _ev("2", "y marker-b", "2026-10-10T09:00:08Z", "audit", key="boot-1|4242|999")])
    assert _chains(r) == []


def test_pid_alone_is_weak_and_never_chains(tmp_path):
    r = _scan(tmp_path, RULES, [_ev("1", "x marker-a", "2026-10-10T09:00:00Z", "process", key=None),
                                _ev("2", "y marker-b", "2026-10-10T09:00:08Z", "audit", key=None)])
    assert _chains(r) == []


def test_single_rule_is_not_a_chain(tmp_path):
    r = _scan(tmp_path, RULES, [_ev("1", "x marker-a", "2026-10-10T09:00:00Z"), _ev("2", "z marker-a", "2026-10-10T09:00:05Z", "audit")])
    assert _chains(r) == []


def test_only_indicator_members_do_not_chain(tmp_path):
    rules = [_rule("T-A", "marker-a", "indicator"), _rule("T-B", "marker-b", "indicator")]
    r = _scan(tmp_path, rules, [_ev("1", "x marker-a", "2026-10-10T09:00:00Z"), _ev("2", "y marker-b", "2026-10-10T09:00:08Z", "audit")])
    assert _chains(r) == []


def test_events_outside_window_do_not_chain(tmp_path):
    r = _scan(tmp_path, RULES, [_ev("1", "x marker-a", "2026-10-10T09:00:00Z", "process"),
                                _ev("2", "y marker-b", "2026-10-10T11:00:00Z", "audit")], window_seconds=600)
    assert _chains(r) == []


def test_suppressed_member_is_excluded(tmp_path):
    sup = tmp_path / "s.yaml"
    sup.write_text(yaml.safe_dump({"schema": "satsuma/v1", "suppressions": [
        {"id": "SUP-1", "reason": "Beklenen bakım", "rule_ids": ["T-B"]}]}, allow_unicode=True, sort_keys=False), encoding="utf-8")
    r = _scan(tmp_path, RULES, [_ev("1", "x marker-a", "2026-10-10T09:00:00Z", "process"),
                                _ev("2", "y marker-b", "2026-10-10T09:00:08Z", "audit")], suppressions=SuppressionList.load(sup))
    assert len(r.suppressed) == 1, "ön koşul: T-B bastırılmış olmalı"
    assert _chains(r) == []


def test_chains_are_off_by_default(tmp_path):
    r = _scan(tmp_path, RULES, [_ev("1", "x marker-a", "2026-10-10T09:00:00Z", "process"),
                                _ev("2", "y marker-b", "2026-10-10T09:00:08Z", "audit")], chains=False)
    assert _chains(r) == [] and r.stats.chains == 0


def test_chain_is_deterministic_and_members_stay_unchanged(tmp_path):
    evs = [_ev("1", "x marker-a", "2026-10-10T09:00:00Z", "process"), _ev("2", "y marker-b", "2026-10-10T09:00:08Z", "audit")]
    a = _chains(_scan(tmp_path, RULES, evs))[0]["finding_id"]
    (tmp_path / "again").mkdir()
    r2 = _scan(tmp_path / "again", RULES, evs)
    assert _chains(r2)[0]["finding_id"] == a
    members = [f for f in r2.findings_as_dicts() if f["rule_id"] in ("T-A", "T-B")]
    assert all(m["classification"] == "suspicious" for m in members)
    assert all(a in m["extensions"]["chain_ids"] for m in members)
