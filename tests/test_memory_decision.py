"""The shared memory decision equals the Linux rule engine's policy, for every memory rule.

Ortak bellek kararı, her bellek kuralı için Linux kural motorunun politikasıyla aynıdır.
"""
import yaml
from pathlib import Path

from satsuma import enforcement, memory_decision

ROOT = Path(__file__).resolve().parents[1]


def test_every_memory_rule_is_loaded_and_decided_as_enforcement_decides():
    rules = memory_decision.load_rules()
    count = 0
    for name in memory_decision.RULE_FILES:
        for rule in yaml.safe_load((ROOT / 'rules' / name).read_text(encoding='utf-8')):
            action = rule['base_match']['action']
            decision = memory_decision.decide(action, rules)
            assert decision['rule_id'] == rule['id']
            assert decision['stop'] is enforcement.eligible({**rule, 'rule_id': rule['id']}), rule['id']
            count += 1
    assert count == len(rules) >= 7  # RAM-106/107 retired


def test_owner_decisions_hold_on_both_platforms():
    rules = memory_decision.load_rules()
    assert memory_decision.decide('anonymous_rwx', rules)['stop'] is True
    assert memory_decision.decide('writable_dir_code_mapping', rules)['stop'] is True
    assert memory_decision.decide('executable_code_mismatch', rules)['stop'] is True
    assert memory_decision.decide('no_such_indicator', rules) is None


def test_linux_worker_indicators_all_have_a_rule():
    source = (ROOT / 'satsuma' / 'worker_memory.py').read_text()
    rules = memory_decision.load_rules()
    for word in ('anonymous_rwx', 'memfd_executable', 'memfd_mapping', 'deleted_executable',
                 'writable_dir_code_mapping', 'process_traced', 'executable_code_mismatch'):
        assert "'" + word + "'" in source and word in rules, word


def test_signed_or_approved_setup_code_in_a_writable_folder_is_recorded_unsigned_is_stopped():
    """Owner's decision 2026-11-11. Sahibinin kararı: imzalı kaydedilir, imzasız durdurulur, Satsuma kurulumu çalışır."""
    rules = memory_decision.load_rules()
    assert memory_decision.decide('writable_dir_code_mapping', rules)['stop'] is True
    signed = memory_decision.decide('writable_dir_code_mapping', rules, signed=True)
    assert signed['stop'] is False and signed['kept'] == 'signed_publisher'
    setup = memory_decision.decide('writable_dir_code_mapping', rules, approved_setup=True)
    assert setup['stop'] is False and setup['kept'] == 'approved_satsuma_setup'
    # A signature never excuses writable+executable memory without a file.
    assert memory_decision.decide('anonymous_rwx', rules, signed=True, approved_setup=True)['stop'] is True


def test_windows_rwx_stops_only_when_code_runs_from_it_or_the_program_is_misplaced():
    """Owner's decision 2026-11-11; Linux (no facts) keeps stopping on the indicator alone."""
    rules = memory_decision.load_rules()
    assert memory_decision.decide('anonymous_rwx', rules)['stop'] is True
    kept = memory_decision.decide('anonymous_rwx', rules, executing=False, expected_location=True)
    assert kept['stop'] is False and kept['kept'] == 'no_thread_from_fileless_memory'
    running = memory_decision.decide('anonymous_rwx', rules, executing=True, expected_location=True)
    assert running['stop'] is True and running['stop_reason'] == 'thread_started_from_fileless_memory'
    misplaced = memory_decision.decide('anonymous_rwx', rules, executing=False, expected_location=False)
    assert misplaced['stop'] is True and misplaced['stop_reason'] == 'program_not_in_expected_location'
