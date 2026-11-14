"""OPNsense telemetry must never operate either firewall automatically."""
from pathlib import Path

import pytest

from workers.opnsense.worker import WorkerOpnsense
from satsuma.opnsense_advisory import candidate, finding_for, is_opnsense_advisory
from satsuma.auto_network import respond
from satsuma.response_policy import authorize_destructive


def event(src="8.8.8.8", direction="in", action="block", scope="opnsense"):
    return {
        "source": {"collector_id": "opnsense", "host": "firewall1", "type": "firewall"},
        "target_scope": scope,
        "category": "firewall", "action": action,
        "network": {"src_ip": src, "dst_ip": "192.168.1.3",
                    "direction": direction, "protocol": "udp"}
    }


@pytest.mark.parametrize("src", ["127.0.0.1", "192.168.1.5", "::1",
                                  "169.254.1.2", "224.0.0.1", "8.8.8.0/24"])
def test_only_single_public_addresses_are_candidates(src):
    assert candidate(event(src=src)) is None


def test_inbound_firewall_drops_propose_but_never_execute():
    e = event()
    assert candidate(e) == "8.8.8.8"
    assert candidate(event(direction="out")) is None
    assert candidate(event(action="pass")) is None
    item = finding_for(e, "8.8.8.8", 3, now=20.0)
    assert item["target_scope"] == "opnsense"
    assert item["action"]["executed"] is False
    assert item["operator_review_required"] is True
    assert is_opnsense_advisory(item)


def test_local_findings_remain_eligible_for_host_policy():
    config = {
        "response_enabled": True,
        "destructive_response_enabled": True,
        "auto_action_network_enabled": True,
        "destructive_allowed_actions": ["network_isolate"],
    }
    local = {"classification": "confirmed",
             "source": "suricata", "sources": ["suricata", "audit"],
             "target_ip": "8.8.8.8"}
    context = {"target_ip": "8.8.8.8", "automated": True}
    assert authorize_destructive("network_isolate", local, config, context).allowed
    remote = dict(local, source="OPNSENSE", target_scope="opnsense")
    auth = authorize_destructive("network_isolate", remote, config, context)
    assert not auth.allowed
    assert "remote_advisory_only" in auth.reasons


def test_remote_response_is_denied_before_any_host_effect():
    class NeverUseResponse:
        @property
        def store(self):
            raise AssertionError("a remote event reached host response")
    result = respond(NeverUseResponse(), event(), "8.8.8.8", "remote alert")
    assert result["status"] == "remote_advisory_only"
    assert result["executed"] is False


class MemoryStore:
    def __init__(self):
        self.state = {}
        self.records = []
    def get(self, key, default=None):
        return self.state.get(key, default)
    def set(self, key, value):
        self.state[key] = value
    def add(self, kind, event):
        self.records.append((kind, event))


def test_repeated_remote_drops_generate_only_a_finding(tmp_path):
    store = MemoryStore()
    worker = WorkerOpnsense(store, {"opnsense_log_path": str(tmp_path / "syslog")})
    # Exercise recommendation logic independently of syslog transports.
    assert worker._record_advisories([event(), event()]) == 0
    assert worker._record_advisories([event()]) == 1
    assert worker._record_advisories([event()]) == 0
    findings = [r for k, r in store.records if k == "findings"]
    assert len(findings) == 1
    assert findings[0]["target_scope"] == "opnsense"
    assert findings[0]["action"]["executed"] is False
    assert not [r for k, r in store.records if k == "actions"]


def test_file_cursor_recovers_after_rotation(tmp_path):
    store = MemoryStore()
    path = tmp_path / "opnsense.log"
    path.write_text("line1\nline2\n", encoding="utf-8")
    worker = WorkerOpnsense(store, {"opnsense_log_path": str(path)})
    assert worker._collect_file(max_lines=1) == ["line1"]
    assert store.get(worker.cursor_key) is None
    # Simulate successful downstream persistence before acknowledging progress.
    store.set(worker.cursor_key, worker.pending_cursor)
    assert worker._collect_file(max_lines=1) == ["line2"]
    store.set(worker.cursor_key, worker.pending_cursor)
    assert worker._collect_file(max_lines=1) == []
    previous = tmp_path / "previous.log"
    path.rename(previous)
    path.write_text("line3\n", encoding="utf-8")
    assert worker._collect_file(max_lines=10) == ["line3"]
    store.set(worker.cursor_key, worker.pending_cursor)
    assert isinstance(store.get(worker.cursor_key), dict)


def test_real_filterlog_line_reaches_advisory_mapper():
    from workers.normalizer.opnsense.mapper import map_syslog_line
    line = ("filterlog: 10,,,1000000103,igb0,match,block,in,4,0x0,,"
            "64,0,0,DF,17,udp,40,8.8.8.8,192.168.1.10,12345,53,20")
    normalized = map_syslog_line(line)
    assert normalized is not None
    assert normalized["source"]["collector_id"] == "opnsense"
    assert candidate(normalized) == "8.8.8.8"


def test_dashboard_surfaces_remote_review_not_host_action():
    from satsuma.dashboard_api import _normalize_core_finding
    report = finding_for(event(), "8.8.8.8", 3, now=123.0)
    row = _normalize_core_finding(
        {"event":{"category":"finding"}, "metadata":{"finding":report}},
        42, {})
    assert row["source"] == "OPNSENSE"
    assert row["target_scope"] == "opnsense"
    assert "OPNsense" in row["recommendation"]
    assert row["raw"]["action"]["executed"] is False


def test_ipv6_filterlog_preserves_correct_source_and_no_subnet():
    from workers.normalizer.opnsense.mapper import map_syslog_line
    line = ("filterlog: 10,,,1000000103,igb0,match,block,in,6,"
            "0x0,0x0,64,udp,17,40,2001:4860:4860::8888,"
            "2001:db8::1,12345,53,20")
    normalized = map_syslog_line(line)
    assert normalized is not None
    assert normalized["network"]["src_ip"] == "2001:4860:4860::8888"
    assert normalized["network"]["src_port"] == 12345
    assert candidate(normalized) == "2001:4860:4860::8888"


def test_malformed_filterlog_is_not_guessed_as_an_attack_source():
    from workers.normalizer.opnsense.mapper import map_syslog_line
    for line in (
        "filterlog: 10,,,10,igb0,match,block,in,4",
        "filterlog: 10,,,10,igb0,match,block,in,4,0x0,,64,0,0,DF,17,udp,40,NOT_AN_IP,192.168.1.2",
    ):
        assert candidate(map_syslog_line(line)) is None
