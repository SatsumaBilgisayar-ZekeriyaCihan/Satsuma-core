"""Satsuma Engine test paketi.

Kapsam:
  - kural şeması + anlam denetimi (şema dışı alan, tekil kimlik, güvensiz regex)
  - koşul operatörleri (contains/any/all/none/cidr/ignore_case)
  - tarama determinizmi, tekilleştirme, bastırma
  - aggregation (eşik tabanlı) davranışı
  - skorlama değiştiricileri
  - bulgu şeması uygunluğu ve üç rapor biçimi
  - CLI çıkış kodları

Çalıştırma::

    cd satsuma-engine && python3 -m pytest tests -q
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest
import yaml

from satsuma_engine.cli import main
from satsuma_engine.conditions import CompiledLogic
from satsuma_engine.engine import Engine
from satsuma_engine.findings import validate_finding
from satsuma_engine.reporters import build_json_report, build_sarif_report, write_html_report
from satsuma_engine.rule_model import load_events, load_rules, load_ruleset
from satsuma_engine.suppression import SuppressionList

ROOT = Path(__file__).resolve().parent.parent
ENGINE_ROOT = ROOT / "satsuma_engine"
RULES_DIR = ENGINE_ROOT / "rules"
EVENTS = ENGINE_ROOT / "samples" / "events.jsonl"
ALLOWLIST = ROOT / "tests" / "fixtures" / "engine_allowlist.yaml"


# ---------------------------------------------------------------------------
# Yardımcılar
# ---------------------------------------------------------------------------
def base_rule(**overrides):
    rule = {
        "schema": "satsuma/v1",
        "id": "TEST-001",
        "title": "Test kuralı",
        "severity": "medium",
        "match": {"field": "event.cmd", "contains": "satsuma-test"},
    }
    rule.update(overrides)
    return rule


def write_rules(tmp_path: Path, rules) -> Path:
    path = tmp_path / "rules.yaml"
    path.write_text(yaml.safe_dump(rules, allow_unicode=True, sort_keys=False), encoding="utf-8")
    return path


def event(cmd: str, ts: str = "2026-10-02T09:00:00Z", host: str = "srv-test-01", **extra):
    payload = {
        "id": ts,
        "source": "sys_proc",
        "event": {"timestamp": ts, "host": host, "kind": "process", "cmd": cmd},
    }
    payload["event"].update(extra)
    return payload


def write_events(tmp_path: Path, events) -> Path:
    path = tmp_path / "events.jsonl"
    path.write_text(
        "\n".join(json.dumps(item, ensure_ascii=False) for item in events) + "\n",
        encoding="utf-8",
    )
    return path


def run_scan(rule_file: Path, events_file: Path, suppressions: SuppressionList | None = None):
    rules, _warnings = load_ruleset([rule_file], strict=False)
    engine = Engine(rules, suppressions=suppressions)
    return engine, engine.scan_file(events_file)


# ---------------------------------------------------------------------------
# Kural doğrulama
# ---------------------------------------------------------------------------
def test_repo_ruleset_is_valid_and_unique():
    report = load_rules([RULES_DIR], strict=False)
    assert report.errors == []
    assert len(report.rules) >= 20, "örnek kural seti yeterince zengin olmalı"
    ids = [rule.id for rule in report.rules]
    assert len(ids) == len(set(ids))
    assert all(rule.mitre for rule in report.rules), "her kuralda MITRE eşlemesi olmalı"


def test_unknown_field_is_rejected(tmp_path):
    path = write_rules(tmp_path, [base_rule(severity_level="high")])
    report = load_rules([path], strict=False)
    assert report.errors
    assert any(issue.code.startswith("schema.") for issue in report.errors)


def test_missing_operator_is_reported(tmp_path):
    path = write_rules(tmp_path, [base_rule(match={"field": "event.cmd"})])
    report = load_rules([path], strict=False)
    assert report.errors, "operatörsüz koşul kabul edilmemeli"
    assert report.rules == [], "geçersiz kural yüklenmemeli"
    assert any(issue.code.startswith("schema.") for issue in report.errors)
    assert any("event.cmd" in issue.message for issue in report.errors)


def test_aggregation_requires_group_by_warning(tmp_path):
    # `count_distinct` kuralında `group_by` verilmemesi tüm olayları tek kovaya toplar.
    path = write_rules(
        tmp_path,
        [
            base_rule(
                aggregation={
                    "type": "count_distinct",
                    "count_distinct_field": "event.src_ip",
                    "threshold": 2,
                    "window_seconds": 60,
                }
            )
        ],
    )
    report = load_rules([path], strict=False)
    assert report.errors == []
    assert [issue.code for issue in report.warnings] == ["rule.aggregation_group_by"]


def test_aggregation_count_distinct_without_field_is_rejected(tmp_path):
    path = write_rules(
        tmp_path,
        [base_rule(aggregation={"type": "count_distinct", "threshold": 2, "window_seconds": 60})],
    )
    report = load_rules([path], strict=False)
    assert [issue.code for issue in report.errors] == ["rule.aggregation_count_distinct_field"]
    assert report.rules == []


def test_duplicate_rule_id_is_rejected(tmp_path):
    path = write_rules(tmp_path, [base_rule(), base_rule(title="Kopya kural")])
    report = load_rules([path], strict=False)
    assert any(issue.code == "rule.duplicate_id" for issue in report.errors)


def test_unsafe_regex_is_rejected(tmp_path):
    path = write_rules(tmp_path, [base_rule(match={"field": "event.cmd", "regex": "(a+)+$"})])
    report = load_rules([path], strict=False)
    assert any(issue.code == "rule.regex_unsafe" for issue in report.errors)


def test_unknown_mitre_technique_is_warning_not_error(tmp_path):
    path = write_rules(
        tmp_path,
        [base_rule(mitre=[{"tactic": "execution", "technique": "T9999"}])],
    )
    report = load_rules([path], strict=False)
    assert report.errors == []
    assert any(issue.code == "rule.mitre_unknown_technique" for issue in report.warnings)


def test_aggregation_requires_group_by_warning(tmp_path):
    path = write_rules(
        tmp_path,
        [
            base_rule(
                aggregation={"type": "count_distinct", "threshold": 2, "window_seconds": 60}
            )
        ],
    )
    report = load_rules([path], strict=False)
    codes = {issue.code for issue in report.errors + report.warnings}
    assert "rule.aggregation_count_distinct_field" in codes
    assert "rule.aggregation_group_by" in codes


def test_rule_schema_documents_are_exportable():
    from satsuma_engine.schema_store import SCHEMA_FILES, load_schema

    for kind in SCHEMA_FILES:
        schema = load_schema(kind)
        assert schema["$schema"].startswith("https://json-schema.org")
        assert schema["title"]


# ---------------------------------------------------------------------------
# Koşul motoru
# ---------------------------------------------------------------------------
def test_condition_group_semantics():
    logic = CompiledLogic.compile(
        {
            "all": [
                {"field": "event.cmd", "contains_any": ["curl", "wget"]},
                {"field": "event.src_ip", "cidr": ["10.0.0.0/8"]},
                {"none": [{"field": "event.uid", "equals": 0}]},
            ]
        }
    )
    matching = {"event": {"cmd": "curl http://x", "src_ip": "10.1.2.3", "uid": 1000}}
    assert logic.evaluate(matching) is True
    assert logic.evaluate({"event": {"cmd": "curl http://x", "src_ip": "10.1.2.3", "uid": 0}}) is False
    assert logic.evaluate({"event": {"cmd": "curl http://x", "src_ip": "192.168.1.1", "uid": 1000}}) is False


def test_ignore_case_and_missing_field():
    logic = CompiledLogic.compile({"field": "event.user", "equals": "ROOT", "ignore_case": True})
    assert logic.evaluate({"event": {"user": "root"}}) is True
    assert logic.evaluate({"event": {}}) is False


def test_exists_operator_distinguishes_missing():
    logic = CompiledLogic.compile({"field": "event.path", "exists": False})
    assert logic.evaluate({"event": {}}) is True
    assert logic.evaluate({"event": {"path": "/etc/passwd"}}) is False


# ---------------------------------------------------------------------------
# Tarama / dedup / bastırma
# ---------------------------------------------------------------------------
def test_scan_is_deterministic(tmp_path):
    rule_file = write_rules(tmp_path, [base_rule()])
    events_file = write_events(tmp_path, [event("curl satsuma-test")])
    _engine, first = run_scan(rule_file, events_file)
    _engine, second = run_scan(rule_file, events_file)
    assert [r.finding["finding_id"] for r in first.reported] == [
        r.finding["finding_id"] for r in second.reported
    ]
    assert first.stats.as_dict() | {"elapsed_ms": 0} == second.stats.as_dict() | {"elapsed_ms": 0}


def test_dedup_merges_same_entity_inside_window(tmp_path):
    rule_file = write_rules(
        tmp_path,
        [base_rule(dedup={"key": ["event.src_ip"], "window_seconds": 600})],
    )
    events_file = write_events(
        tmp_path,
        [
            event("curl satsuma-test", ts="2026-10-02T09:00:00Z", src_ip="10.0.0.9"),
            event("curl satsuma-test", ts="2026-10-02T09:05:00Z", src_ip="10.0.0.9"),
        ],
    )
    _engine, result = run_scan(rule_file, events_file)
    assert len(result.reported) == 1
    assert result.reported[0].finding["observations"]["occurrences"] == 2
    assert result.stats.merged_events == 1
    assert result.reported[0].finding["dedup_key"]


def test_dedup_splits_outside_window(tmp_path):
    rule_file = write_rules(
        tmp_path,
        [base_rule(dedup={"key": ["event.src_ip"], "window_seconds": 60})],
    )
    events_file = write_events(
        tmp_path,
        [
            event("curl satsuma-test", ts="2026-10-02T09:00:00Z", src_ip="10.0.0.9"),
            event("curl satsuma-test", ts="2026-10-02T09:30:00Z", src_ip="10.0.0.9"),
        ],
    )
    _engine, result = run_scan(rule_file, events_file)
    assert len(result.reported) == 2
    assert result.stats.merged_events == 0


def test_suppression_hides_but_reports(tmp_path):
    rule_file = write_rules(tmp_path, [base_rule()])
    events_file = write_events(tmp_path, [event("curl satsuma-test")])
    suppression_file = tmp_path / "allowlist.yaml"
    suppression_file.write_text(
        yaml.safe_dump(
            {
                "schema": "satsuma/v1",
                "suppressions": [
                    {"id": "SUP-1", "reason": "Beklenen test davranışı", "rule_ids": ["TEST-001"]}
                ],
            },
            allow_unicode=True,
            sort_keys=False,
        ),
        encoding="utf-8",
    )
    suppressions = SuppressionList.load(suppression_file)
    _engine, result = run_scan(rule_file, events_file, suppressions)
    assert result.reported == []
    assert len(result.suppressed) == 1
    assert result.suppressed[0].suppression_id == "SUP-1"
    assert result.stats.suppressed_findings == 1


def test_expired_suppression_is_ignored(tmp_path):
    rule_file = write_rules(tmp_path, [base_rule()])
    events_file = write_events(tmp_path, [event("curl satsuma-test", ts="2026-10-02T09:00:00Z")])
    suppression_file = tmp_path / "allowlist.yaml"
    suppression_file.write_text(
        yaml.safe_dump(
            {
                "schema": "satsuma/v1",
                "suppressions": [
                    {
                        "id": "SUP-OLD",
                        "reason": "Süresi dolmuş kayıt",
                        "rule_ids": ["TEST-001"],
                        "expires_at": "2026-01-01T00:00:00Z",
                    }
                ],
            },
            allow_unicode=True,
            sort_keys=False,
        ),
        encoding="utf-8",
    )
    suppressions = SuppressionList.load(suppression_file)
    assert suppressions.warnings, "süresi dolmuş kayıt uyarı üretmeli"
    _engine, result = run_scan(rule_file, events_file, suppressions)
    assert len(result.reported) == 1
    assert result.suppressed == []


def test_aggregation_threshold_emits_single_finding(tmp_path):
    rule_file = write_rules(
        tmp_path,
        [
            base_rule(
                aggregation={
                    "type": "threshold",
                    "group_by": ["event.src_ip"],
                    "threshold": 3,
                    "window_seconds": 300,
                    "emit": "single",
                }
            )
        ],
    )
    events_file = write_events(
        tmp_path,
        [
            event("curl satsuma-test", ts=f"2026-10-02T09:0{i}:00Z", src_ip="10.0.0.44")
            for i in range(4)
        ],
    )
    _engine, result = run_scan(rule_file, events_file)
    assert len(result.reported) == 1
    finding = result.reported[0].finding
    assert any(item.get("type") == "aggregation" for item in finding["evidence"])
    assert finding["observations"]["occurrences"] >= 1


def test_scoring_modifier_changes_score(tmp_path):
    rule_file = write_rules(
        tmp_path,
        [
            base_rule(
                scoring={
                    "base": 40,
                    "modifiers": [
                        {"if": {"field": "event.uid", "equals": 0}, "delta": 15, "comment": "root"}
                    ],
                }
            )
        ],
    )
    events_file = write_events(
        tmp_path,
        [
            event("curl satsuma-test", ts="2026-10-02T09:00:00Z", host="a", uid=0),
            event("curl satsuma-test", ts="2026-10-02T09:01:00Z", host="b", uid=1000),
        ],
    )
    _engine, result = run_scan(rule_file, events_file)
    scores = {rec.finding["host"]: rec.finding["score"] for rec in result.reported}
    assert scores["a"] == 55
    assert scores["b"] == 40
    breakdown = next(r.finding["score_breakdown"] for r in result.reported if r.finding["host"] == "a")
    assert breakdown["modifiers"][0]["delta"] == 15


def test_logsource_filters_events(tmp_path):
    rule_file = write_rules(
        tmp_path,
        [base_rule(logsource={"kind": "auth"}, match={"field": "event.action", "equals": "login_failed"})],
    )
    events_file = write_events(
        tmp_path,
        [
            {"id": 1, "event": {"timestamp": "2026-10-02T09:00:00Z", "host": "h1", "kind": "auth", "action": "login_failed"}},
            {"id": 2, "event": {"timestamp": "2026-10-02T09:01:00Z", "host": "h1", "kind": "process", "action": "login_failed"}},
        ],
    )
    _engine, result = run_scan(rule_file, events_file)
    assert len(result.reported) == 1
    assert result.stats.events_matched == 1


# ---------------------------------------------------------------------------
# Örnek veri seti üzerinde uçtan uca
# ---------------------------------------------------------------------------
@pytest.fixture(scope="module")
def repo_scan():
    rules, _warnings = load_ruleset([RULES_DIR], strict=False)
    engine = Engine(rules, suppressions=SuppressionList.load(ALLOWLIST))
    return engine, engine.scan_file(EVENTS)


def test_repo_scan_covers_every_rule(repo_scan):
    engine, result = repo_scan
    coverage = engine.coverage(rec.finding for rec in result.reported)
    assert coverage["silent_rules"] == 0, f"hiç tetiklenmeyen kural: {coverage['silent_rule_ids']}"
    assert result.stats.ruleset_hash


def test_repo_scan_all_findings_valid(repo_scan):
    _engine, result = repo_scan
    assert result.findings, "örnek veri bulgu üretmeli"
    for record in result.findings:
        issues = validate_finding(record.finding)
        assert not issues, [issue.format() for issue in issues]


def test_repo_scan_reports_and_counts(repo_scan):
    _engine, result = repo_scan
    assert result.stats.raw_detections >= len(result.findings)
    assert result.stats.merged_events >= 1
    assert result.stats.suppressed_findings == len(result.suppressed) >= 1

    payload = build_json_report(result)
    assert payload["schema"] == "satsuma-report/v1"
    assert len(payload["findings"]) == len(result.reported)
    assert len(payload["suppressed"]) == len(result.suppressed)

    sarif = build_sarif_report(result)
    assert sarif["version"] == "2.1.0"
    run = sarif["runs"][0]
    assert len(run["results"]) == len(result.reported)
    assert run["results"][0]["locations"][0]["physicalLocation"]["artifactLocation"]["uri"].endswith(
        "events.jsonl"
    )
    assert all(item["ruleId"] for item in run["results"])


def test_html_report_is_self_contained(repo_scan, tmp_path):
    _engine, result = repo_scan
    target = write_html_report(result, tmp_path / "report.html")
    text = target.read_text(encoding="utf-8")
    assert text.startswith("<!DOCTYPE html>")
    assert "src=" not in text and "href=" not in text, "HTML dış kaynak yüklememeli"
    assert text.count('class="finding"') == len(result.reported)


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------
def test_cli_validate_returns_zero():
    assert main(["rules", "validate", str(RULES_DIR)]) == 0


def test_cli_list_json(tmp_path, capsys):
    exit_code = main(["rules", "list", str(RULES_DIR), "--format", "json"])
    assert exit_code == 0
    payload = json.loads(capsys.readouterr().out)
    assert payload["count"] >= 20
    assert payload["rules"][0]["id"]


def test_cli_scan_fail_on_threshold():
    assert main(["scan", "--rules", str(RULES_DIR), "--events", str(EVENTS), "--quiet", "--fail-on", "critical"]) == 1


def test_cli_verify_writes_reports(tmp_path):
    exit_code = main(
        [
            "verify",
            "--rules",
            str(RULES_DIR),
            "--events",
            str(EVENTS),
            "--suppression",
            str(ALLOWLIST),
            "--out-dir",
            str(tmp_path),
        ]
    )
    assert exit_code == 0
    for name in ("report.json", "report.sarif", "report.html"):
        assert (tmp_path / name).exists()


def test_cli_schema_export(tmp_path):
    target = tmp_path / "rule.schema.json"
    assert main(["rules", "schema", "--kind", "rule", "--out", str(target)]) == 0
    assert json.loads(target.read_text(encoding="utf-8"))["$id"].endswith("rule.schema.json")


def test_cli_missing_events_reports_error(tmp_path, capsys):
    exit_code = main(["scan", "--rules", str(RULES_DIR), "--events", str(tmp_path / "yok.jsonl")])
    assert exit_code == 2
    assert "HATA" in capsys.readouterr().err


def test_events_loader_reads_sample():
    events = load_events(EVENTS)
    assert len(events) >= 30
    assert events[0][0] == 1
