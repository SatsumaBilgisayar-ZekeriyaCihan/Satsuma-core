"""Audit G4: the environment cannot point the rule engine at another directory.

A systemd drop-in setting SATSUMA_RULES_DIR to an empty directory used to
switch every rule off without a warning.

Denetim G4: ortam değişkeni kural motorunu başka bir dizine yönlendiremez.
Boş bir dizini gösteren SATSUMA_RULES_DIR ayarı eskiden bütün kuralları
uyarısız kapatıyordu.
"""
from pathlib import Path

from satsuma import smart_rules
from satsuma.smart_rules import SmartRuleEngine

ROOT = Path(__file__).parents[1]


def test_environment_variable_cannot_empty_the_rule_set(monkeypatch, tmp_path):
    monkeypatch.setattr(smart_rules, 'BUNDLED_RULES_DIR', ROOT / 'rules')
    monkeypatch.setenv('SATSUMA_RULES_DIR', str(tmp_path))
    engine = SmartRuleEngine()
    assert engine.rules_dir == ROOT / 'rules'
    assert len(engine.rules) == 231  # RAM-106/107 retired
    # The attempt is reported, so health shows DEGRADED instead of RUNNING.
    assert {'file': str(tmp_path), 'error': 'SATSUMA_RULES_DIR ignored (audit G4)'} in engine.load_errors
    assert engine.stats()['invalid_files'] >= 1


def test_variable_naming_the_real_directory_is_not_reported(monkeypatch):
    monkeypatch.setattr(smart_rules, 'BUNDLED_RULES_DIR', ROOT / 'rules')
    monkeypatch.setenv('SATSUMA_RULES_DIR', str(ROOT / 'rules'))
    assert SmartRuleEngine().load_errors == []


def test_an_empty_rule_set_is_never_a_quiet_success(tmp_path):
    engine = SmartRuleEngine(tmp_path)
    assert engine.rules == []
    assert engine.load_errors == [{'file': str(tmp_path), 'error': 'no_rules_loaded'}]


def test_units_no_longer_set_the_variable():
    for unit in (ROOT / 'systemd').glob('*.service'):
        assert 'SATSUMA_RULES_DIR' not in unit.read_text(), unit.name
