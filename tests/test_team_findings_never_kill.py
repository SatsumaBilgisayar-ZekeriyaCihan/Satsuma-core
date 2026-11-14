"""Team correlation findings are evidence only: they carry no process identity and never stop a program.

Giving them one would make the privilege-escalation rule (a non-root user running
sudo, su or pkexec, classified suspicious) stop every ordinary sudo command.

Takım korelasyon bulguları yalnızca kanıttır: süreç kimliği taşımazlar ve hiçbir
programı durdurmazlar. Onlara kimlik vermek, ayrıcalık yükseltme kuralının (root
olmayan kullanıcının sudo, su ya da pkexec çalıştırması, sınıfı şüpheli) her sıradan
sudo komutunu durdurmasına yol açardı.
"""
import time

import pytest

from satsuma.auto_action import AutoActionEngine
from satsuma.store import Store
from satsuma.teams.identity_team.rules import PrivilegeEscalationRule
from satsuma.teams.host_team.rules import ProcessChainRule

CONFIG = dict(response_enabled=True, destructive_response_enabled=True,
              destructive_allowed_actions=['process_kill'], auto_action_process_enabled=True)


class FakeResponse:
    def __init__(self):
        self.calls = []

    def terminate_process(self, *args, **kwargs):
        self.calls.append((args, kwargs))
        return {'status': 'terminated', 'signal_sent': True, 'exit_verified': True}


def sudo_event():
    return {'id': 7, 'action': 'new_process', 'category': 'process', 'timestamp': int(time.time()),
            'source': {'collector_id': 'sys_proc'},
            'metadata': {'extensions': {'host.cmd': '/usr/bin/sudo -n true', 'host.exe': '/usr/bin/sudo',
                                        'host.uid': '1000', 'host.pid': 4321, 'host.starttime': 99999,
                                        'host.ppid': 1000}}}


@pytest.fixture
def store(tmp_path):
    s = Store(tmp_path / 'data', test=True)
    yield s
    s.close()


def test_the_privilege_escalation_finding_is_suspicious_and_would_be_enforced_if_it_had_an_identity():
    from satsuma import enforcement
    finding = PrivilegeEscalationRule().match([sudo_event()])[0]
    assert finding['classification'] == 'suspicious'
    assert enforcement.eligible(finding)          # the only thing between sudo and a kill is the missing identity


def test_a_team_finding_never_reaches_a_process_kill(store):
    finding = PrivilegeEscalationRule().match([sudo_event()])[0]
    assert 'event' not in finding                  # no process identity travels with it
    fake = FakeResponse()
    outcome = AutoActionEngine(store, dict(CONFIG), response=fake).process(finding)['process_response']
    assert fake.calls == [] and outcome['signal_sent'] is False
    assert 'missing_event_process_identity' in outcome['reasons']


def test_the_process_chain_finding_does_not_kill_either(store):
    events = [{'id': 1, 'action': 'StartTransientUnit', 'timestamp': 1000, 'metadata': {'extensions': {}}}]
    events += [{'id': 2 + i, 'action': 'new_process', 'timestamp': 1000, 'metadata': {'extensions': {
        'host.pid': 500 + i, 'host.exe': '/usr/bin/bash', 'host.starttime': 10 + i}}} for i in range(2)]
    finding = ProcessChainRule().match(events)[0]
    fake = FakeResponse()
    outcome = AutoActionEngine(store, dict(CONFIG), response=fake).process(finding)['process_response']
    assert fake.calls == [] and outcome['signal_sent'] is False
