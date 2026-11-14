"""Retired RAM ClamAV detections must not advertise automatic enforcement."""
import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
CATALOG = ROOT / 'schemas/rule-response-catalog-v1.json'
ARCHIVE = ROOT / 'schemas/retired-ram-clamav-rules.json'


def test_retired_ram_rules_fail_closed_in_catalog():
    rows = json.loads(ARCHIVE.read_text())['rules']
    active_ids = {entry['rule_id'] for entry in json.loads(CATALOG.read_text())['rules']}
    assert not active_ids.intersection({'SATSUMA-RAM-106','SATSUMA-RAM-107'})
    for rid in ('SATSUMA-RAM-106', 'SATSUMA-RAM-107'):
        entry = next(row for row in rows if row['rule_id'] == rid)
        flags = entry['current_automatic_eligibility']
        assert flags['enforcement_eligible'] is False
        assert flags['automatic_allowed'] is False
        assert flags['conditional_on_existing_policy'] is False
        assert entry['proposed_response']['applied'] is False
        assert entry['proposed_response']['requested_action'] == 'none_retired_engine'
        assert entry['proposed_response']['review_state'] == 'retired_no_automatic_enforcement'


def test_other_memory_rules_remain_in_catalog():
    rows = json.loads(CATALOG.read_text())['rules']
    ids = {row['rule_id'] for row in rows}
    assert {'SATSUMA-RAM-001','SATSUMA-RAM-009'} <= ids
