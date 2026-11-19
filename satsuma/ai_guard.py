"""Limits on DeepSeek (AI) rules, so a rule cannot hang, blind or turn Satsuma against the machine (2.2.59).

Owner, 2026-11-19: "DeepSeek çok iyi bir özellik ama istismara açık bir alan; kötü niyetli
saldırgan buradan kural yükleyerek ürünü sonsuz döngüye sokabilir." An AI rule passes
through the operator's approval, but its content comes from a model that read text an
attacker may have written. Each limit below holds whatever the rule says:

* load:   every regex must be linear (tested on 64 KiB built from its own words), at most
          16 patterns of 512 characters per matcher; a rule failing this is not loaded;
* breadth: a rule matching more than 2 % of an everyday command corpus, or any command of
          Satsuma, systemd, polkit, D-Bus or the desktop, is refused at validation;
* run:    AI rules run after the bundled rules, each with its own 20 ms CPU budget, so it can
          never use the budget of the bundled rules (blinding detection); a rule that runs
          out three times in ten minutes is suspended and raises a critical alarm;
* stop:   an AI rule never stops PID 1, Satsuma, systemd, polkit, D-Bus, the login manager or
          the desktop session, nor the owner's interactive admin tools (sudo, su, pkexec, gdb,
          strace...: alarm only, the owner and an attacker look the same there); its memory
          rules keep the RAM-001 rule for trusted programs' JIT memory (Firefox...);
          at most 5 stops per rule in ten minutes, then the rule reports only for an hour;
* owner:  each AI rule can be set to report only or disabled (admin password).

DeepSeek kuralları için sınırlar: doğrusal regex, genişlik testi, ayrı CPU bütçesi ve
askıya alma, korunan hedefler (Satsuma, systemd, masaüstü, sudo/gdb), durdurma sınırı.
"""
import re
import time
from pathlib import Path

AI_PREFIX = 'SATSUMA-AI-'
REGEX_KEYS = ('cmd_regex', 'cmd_regex_cs', 'cmd_not_regex', 'exe_regex')
MAX_PATTERNS = 16
MAX_PATTERN_LENGTH = 512
LINEAR_SIZE = 65536
LINEAR_SECONDS = 0.05
LINEAR_TIMEOUT = 2.0
RULE_BUDGET_SECONDS = 0.02
STRIKES = 3
STRIKE_WINDOW = 600.0
STOP_LIMIT = 5
STOP_WINDOW = 600.0
STOP_COOLDOWN = 3600.0
MAX_ACTIVE = 100
BREADTH_LIMIT = 0.02
OVERRIDES_KEY = 'ai_rule_overrides'
MODES = ('report_only', 'disabled')

# The owner's interactive administration tools: the owner and an attacker who knows the
# password look the same; Satsuma's own sudo rules decide, AI rules only report.
INTERACTIVE_TOOLS = frozenset({'sudo', 'su', 'pkexec', 'doas', 'run0', 'gdb', 'lldb', 'strace', 'ltrace',
                               'perf', 'bpftrace', 'systemd-run', 'machinectl'})
# Units and programs an AI rule never stops (the machine or the session would go down).
PROTECTED_UNIT = re.compile(r'^(?:satsuma[\w@.-]*|systemd-[\w@.-]+|dbus(?:-broker)?|polkit|cosmic-greeter|gdm|sddm|'
                            r'NetworkManager|auditd|chronyd|rpm-ostreed|firewalld|nftables)\.service$')
PROTECTED_EXE = frozenset({'systemd', 'polkitd', 'dbus-broker', 'dbus-broker-launch', 'dbus-daemon', 'cosmic-comp',
                           'cosmic-session', 'cosmic-greeter', 'Xwayland', 'gnome-shell', 'kwin_wayland', 'sshd',
                           'systemd-logind', 'auditd', 'NetworkManager'})

# Everyday commands: a rule matching more than BREADTH_LIMIT of these is too broad.
CORPUS = (
    'ls -la', 'cd /tmp', 'cat /etc/os-release', 'grep -r foo .', 'find . -name "*.py"', 'cp a b', 'mv a b',
    'rm -f a.txt', 'mkdir -p x/y', 'tar -xzf a.tar.gz', 'unzip a.zip', 'less README', 'vim notes.txt',
    'nano /etc/hosts', 'python3 script.py', 'python3 -m venv .venv', 'pip install requests', 'git status',
    'git pull', 'git commit -m fix', 'ssh user@host', 'scp a user@host:', 'curl -sSL https://example.com',
    'wget https://example.com/a.iso', 'ping -c 3 1.1.1.1', 'ip addr', 'ss -tlnp', 'top', 'htop', 'ps aux',
    'journalctl -b', 'systemctl status sshd', 'systemctl --user restart pipewire', 'flatpak update',
    'rpm-ostree status', 'rpm-ostree upgrade', 'toolbox enter', 'podman ps', 'podman run -it fedora bash',
    'make -j8', 'gcc -O2 a.c -o a', 'cargo build', 'node app.js', 'npm install', 'code .', 'firefox',
    '/usr/bin/bash', '-bash', 'bash -l', 'zsh', 'sh -c "echo hi"', 'sleep 60', 'date', 'df -h', 'du -sh .',
    'free -m', 'uname -a', 'whoami', 'id', 'env', 'clear', 'history', 'man ls', 'xdg-open .',
    '/usr/libexec/gvfsd', '/usr/bin/pipewire', '/usr/bin/wireplumber', 'cosmic-comp', 'cosmic-panel',
    '/usr/lib/systemd/systemd --user', '/usr/lib/polkit-1/polkitd --no-debug', 'dbus-broker-launch --scope user',
    '/usr/bin/python3 -X pycache_prefix=/run/satsuma-python-cache -I -B /opt/satsuma-core/run_satsuma_teams.py',
    '/usr/bin/python3 -X pycache_prefix=/run/satsuma-python-cache -E -s -B -m satsuma.dnsmasq_control',
    '/usr/bin/python3 -m satsuma.dashboard_qt', '/usr/sbin/nft list ruleset', '/usr/bin/systemctl show satsuma-core.service',
)
PROTECTED_COMMANDS = frozenset(c for c in CORPUS if c.startswith(('/usr/lib/systemd', '/usr/lib/polkit', 'dbus-broker',
                                                                   'cosmic-', '/usr/bin/python3 -X', '/usr/bin/python3 -m satsuma',
                                                                   '/usr/sbin/nft', '/usr/bin/systemctl show satsuma')))


def is_ai(rule_id):
    return str(rule_id or '').startswith(AI_PREFIX)


# -- load and validation -------------------------------------------------------
_linear_cache = {}


def _own_words(pattern):
    plain = re.sub(r'\\[sSbBdDwW]', ' ', pattern)
    plain = re.sub(r'\\(.)', r'\1', plain)
    words = list(dict.fromkeys(re.findall(r'[A-Za-z0-9_./=-]{2,}|[|>&$(:]', plain)))[:24]
    units = []
    for i, word in enumerate(words):
        units += [word + ' ', word]
        units += [word + ' ' + nxt + ' ' for nxt in words[i + 1:i + 3]]
    # Single characters and generic runs too: (a+)+$ or (\w+\s?)+$ blow up on 'aaaa…!'.
    letters = list(dict.fromkeys(re.findall(r'[A-Za-z0-9]', plain)))[:8]
    return [*units, *letters, 'a', 'a ', ' ', '0', '/', '-', 'ab', 'a/', 'a.', '\t']


_PROBE = r"""
import json, re, sys, time
spec = json.loads(sys.stdin.read())
compiled = re.compile(spec['pattern'], spec['flags'])
for unit in spec['units']:
    for size in (256, 4096, spec['size']):
        body = (unit * (size // len(unit) + 1))[:size]
        for text in (body, body + '!', body + '\n!'):
            started = time.thread_time()
            compiled.search(text)
            if time.thread_time() - started > spec['limit']:
                print('0'); sys.exit(0)
print('1')
"""


def linear(pattern, flags=re.IGNORECASE, runner=None):
    """True when the pattern runs in bounded time on long input built from its own words.

    Tested in a child process with a hard timeout: one catastrophic search cannot be
    interrupted inside this process and would hang the caller (the rule engine).
    Alt süreçte, kesin süre sınırıyla denenir; üstel bir arama bu süreci kilitlemez.
    """
    key = (pattern, flags)
    if key in _linear_cache:
        return _linear_cache[key]
    try:
        re.compile(pattern, flags)
    except re.error:
        _linear_cache[key] = False
        return False
    import json
    import subprocess
    import sys
    spec = json.dumps({'pattern': pattern, 'flags': flags, 'units': _own_words(pattern)[:60],
                       'size': LINEAR_SIZE, 'limit': LINEAR_SECONDS})
    run = runner or subprocess.run
    try:
        done = run([sys.executable, '-I', '-S', '-c', _PROBE], input=spec, capture_output=True, text=True,
                   timeout=LINEAR_TIMEOUT)
        verdict = done.returncode == 0 and done.stdout.strip() == '1'
    except subprocess.TimeoutExpired:
        verdict = False
    except OSError:
        verdict = False
    if len(_linear_cache) > 4096:
        _linear_cache.clear()
    _linear_cache[key] = verdict
    return verdict


def regex_issues(detection):
    issues = []
    match = (detection or {}).get('base_match') or {}
    for key in REGEX_KEYS:
        patterns = match.get(key)
        if patterns is None:
            continue
        patterns = patterns if isinstance(patterns, list) else [patterns]
        if len(patterns) > MAX_PATTERNS:
            issues.append(f'ai_guard_too_many_patterns:{key}')
        for pattern in patterns[:MAX_PATTERNS]:
            text = str(pattern)
            if len(text) > MAX_PATTERN_LENGTH:
                issues.append(f'ai_guard_pattern_too_long:{key}')
            elif not linear(text, 0 if key == 'cmd_regex_cs' else re.IGNORECASE):
                issues.append(f'ai_guard_regex_not_linear:{key}:{text[:60]}')
    return issues


def breadth_issues(detection):
    """A rule that matches everyday commands or any protected command is refused."""
    match = (detection or {}).get('base_match') or {}
    if match.get('source') not in (None, 'sys_proc'):
        return []
    import tempfile
    from .smart_rules import SmartRuleEngine
    with tempfile.TemporaryDirectory(prefix='satsuma-ai-breadth-') as folder:
        engine = SmartRuleEngine(folder)
        hits, protected = 0, []
        for index, cmd in enumerate(CORPUS):
            exe = '/usr/bin/' + cmd.split()[0].rsplit('/', 1)[-1].lstrip('-')
            event = {'source': 'sys_proc', 'action': 'new_process', 'cmd': cmd, 'exe': exe, 'pid': 1000 + index}
            try:
                matched = engine._matches(match, event)
            except Exception:
                matched = False
            if matched:
                hits += 1
                if cmd in PROTECTED_COMMANDS:
                    protected.append(cmd[:60])
    issues = []
    if protected:
        issues.append('ai_guard_matches_protected_command:' + protected[0])
    if hits / len(CORPUS) > BREADTH_LIMIT:
        issues.append(f'ai_guard_too_broad:{hits}/{len(CORPUS)}')
    return issues


def validation_issues(detection):
    return [*regex_issues(detection), *breadth_issues(detection)]


# -- owner settings --------------------------------------------------------------
def overrides(store):
    value = store.get(OVERRIDES_KEY, None) if store is not None else None
    return {k: v for k, v in (value or {}).items() if is_ai(k) and v in MODES} if isinstance(value, dict) else {}


def set_override(store, rule_id, mode):
    if not is_ai(rule_id):
        raise ValueError('not_an_ai_rule')
    current = dict(overrides(store))
    if mode in MODES:
        current[rule_id] = mode
    elif mode in (None, 'stop', 'durdur'):
        current.pop(rule_id, None)
    else:
        raise ValueError('unknown_mode')
    store.set(OVERRIDES_KEY, current)
    return current


# -- run time ---------------------------------------------------------------------
class RuntimeGuard:
    """Per-engine accounting: strikes and suspension of AI rules that burn CPU."""

    def __init__(self, clock=time.monotonic):
        self.clock = clock
        self.strikes = {}
        self.suspended = {}
        self.alarms = []

    def active(self, rule_id):
        return rule_id not in self.suspended

    def strike(self, rule_id):
        now = self.clock()
        recent = [t for t in self.strikes.get(rule_id, []) if now - t < STRIKE_WINDOW] + [now]
        self.strikes[rule_id] = recent
        if len(recent) >= STRIKES and rule_id not in self.suspended:
            self.suspended[rule_id] = now
            self.alarms.append(rule_id)
        return rule_id in self.suspended

    def take_alarms(self):
        out, self.alarms = self.alarms, []
        return out


def suspended_finding(rule_id):
    return {'finding_id': 'ai_guard:suspended:' + rule_id, 'rule_id': 'SATSUMA-AI-GUARD-001', 'severity': 'critical',
            'classification': 'indicator', 'source': 'ai_guard', 'suspended_rule': rule_id, 'timestamp': time.time(),
            'title': 'DeepSeek kuralı askıya alındı: ' + rule_id,
            'summary': f'Kural {STRIKE_WINDOW / 60:.0f} dakikada {STRIKES} kez kendi işlemci bütçesini aştı; '
                       'motoru yavaşlatmasın diye çalıştırılmıyor. İçeriğini inceleyin.',
            'enforcement_eligible': False}


# -- stopping -----------------------------------------------------------------------
def _unit(pid, proc_root='/proc'):
    from .trusted_process import system_service
    try:
        return system_service(Path(proc_root, str(int(pid)), 'cgroup').read_text())
    except (OSError, ValueError, TypeError):
        return ''


def _recent_stops(store):
    memory = getattr(store, '_satsuma_ai_stops', None)
    if memory is None:
        memory = {'stops': {}, 'tripped': {}}
        try:
            setattr(store, '_satsuma_ai_stops', memory)
        except (AttributeError, TypeError):
            pass
    return memory


def stop_block(finding, store, pid, exe, *, memory_rule=False, proc_root='/proc', clock=time.monotonic):
    """Why this AI finding may not stop its process (a reason), or None."""
    rule_id = str(finding.get('rule_id') or '')
    if not is_ai(rule_id):
        return None
    mode = overrides(store).get(rule_id)
    if mode:
        return 'ai_rule_owner_' + mode
    name = str(exe or '').rsplit('/', 1)[-1].removesuffix(' (deleted)')
    try:
        if int(pid) <= 1:
            return 'ai_rule_protected_target'
    except (TypeError, ValueError):
        return 'ai_rule_target_unknown'
    if name in INTERACTIVE_TOOLS:
        return 'ai_rule_interactive_admin_tool'
    if name in PROTECTED_EXE or PROTECTED_UNIT.match(_unit(pid, proc_root) or '-'):
        return 'ai_rule_protected_target'
    if memory_rule:
        from .trusted_process import trusted_path, trusted_running_program
        path = str(exe or '')
        if 'memfd:' not in path and (trusted_path(path.removesuffix(' (deleted)'))
                                     or trusted_running_program(pid, proc_root)):
            return 'ai_rule_trusted_program_jit_memory'
    memory = _recent_stops(store)
    now = clock()
    tripped = memory['tripped'].get(rule_id)
    if tripped is not None and now - tripped < STOP_COOLDOWN:
        return 'ai_rule_stop_limit'
    history = [t for t in memory['stops'].get(rule_id, []) if now - t < STOP_WINDOW]
    memory['stops'][rule_id] = history
    if len(history) >= STOP_LIMIT:
        # A rule that stops this much is more likely wrong (or planted) than an attack this large.
        memory['tripped'][rule_id] = now
        return 'ai_rule_stop_limit'
    return None


def count_stop(finding, store, clock=time.monotonic):
    rule_id = str(finding.get('rule_id') or '')
    if is_ai(rule_id):
        _recent_stops(store)['stops'].setdefault(rule_id, []).append(clock())
