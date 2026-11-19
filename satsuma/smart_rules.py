"""Satsuma Core — Smart Rule Engine v2.

Principles:
- An unknown matcher is never ignored silently; the rule is invalid.
- A single command-line match is never a "confirmed" attack.
- Short words are matched as argv tokens, not substrings.
- Regex, negative matches, audit operations and file globs are supported.
- Rule load errors are visible through health/stats.
- The rules directory never comes from the environment (audit G4).
- A kernel-reported execve also meets the process rules (audit K4).
- Wrappers (sudo, env, nohup, timeout, busybox, su -c, ...) are unwrapped and
  every stage is matched; the real executable stands in for a disguised
  argv[0] (audit K5). A shell -c script is split into its simple commands.
- cmd_arg_contains finds an address, host or path in any argument of any
  stage, except in text tools (grep, rg, echo, ...).
- Satsuma's own fixed read-only probes (exact argv, root) do not raise
  log-only discovery findings, and Satsuma's own RPM scriptlets do not
  raise service-stop/start findings for satsuma* units (field 2026-11-04).
- No command line can stall the engine (audit K1): argv parsing is done
  once per command, regexes see whitespace runs collapsed, and each event
  has a regex time budget. An event that exhausts it raises its own
  finding instead of silently skipping rules.

Satsuma Core — Akıllı Kural Motoru v2.

Temel ilkeler:
- Tanınmayan matcher sessizce yok sayılmaz; kural geçersiz sayılır.
- Tek komut satırı eşleşmesi "confirmed" saldırı değildir.
- Kısa kelimelerde substring yerine token/kelime sınırı kullanılır.
- Regex, negatif eşleşme, audit operation ve dosya glob'ları desteklenir.
- Kural yükleme hataları health/stats üzerinden görülebilir.
- Satsuma'nın kendi sabit, salt okunur yoklamaları (birebir argv, root)
  yalnızca kayıt amaçlı keşif bulgusu üretmez; kendi RPM betiklerinin
  satsuma* birimlerine dokunan komutları servis durdurma/başlatma bulgusu
  üretmez (saha 2026-11-04).
- Kural dizini hiçbir zaman ortam değişkeninden alınmaz (denetim G4).
- Çekirdeğin bildirdiği execve de süreç kurallarından geçer (denetim K4).
- Sarmalayıcılar (sudo, env, nohup, timeout, busybox, su -c, ...) açılır ve
  her katman eşlenir; gizlenmiş argv[0] yerine gerçek çalıştırılabilir dosya
  kullanılır (denetim K5). Kabuk -c betiği basit komutlarına ayrılır.
- cmd_arg_contains bir adresi, ana makine adını ya da yolu herhangi bir
  katmanın herhangi bir argümanında arar; metin araçları (grep, rg, echo, ...)
  hariç.
- Hiçbir komut satırı motoru kilitleyemez (denetim K1): argv ayrıştırması
  komut başına bir kez yapılır, düzenli ifadeler boşluk dizileri tek boşluğa
  indirilmiş metni görür ve her olayın bir düzenli ifade zaman bütçesi
  vardır. Bütçeyi tüketen olay kuralları sessizce atlamaz, kendi bulgusunu
  üretir.
"""
from __future__ import annotations

import fnmatch
import functools
import hashlib
import os
import re
import shlex
import time
from pathlib import Path
from typing import Any

import yaml


BUNDLED_RULES_DIR = Path(__file__).resolve().parents[1] / "rules"
SYSTEM_RULES_DIR = Path("/etc/satsuma-core/rules")

# Kural OLMAYAN YAML dosyaları (bilgi tabanı / metadata).
# smart_rules motoru bunları yüklemez; investigation gibi modüller okur.
NON_RULE_YAML = {"attack_roles.yaml"}

_ALLOWED_MATCH_KEYS = {
    "source",
    "action",
    "kind",
    "category",
    "cmd_contains",
    "cmd_not_contains",
    "cmd_arg_contains",
    "cmd_regex",
    "cmd_regex_cs",
    "cmd_not_regex",
    "exe_contains",
    "exe_regex",
    "file_path",
    "file_path_not",
    "operation",
    "env_contains",
    "uid",
    "uid_not",
    "parent_contains",
}
_ALLOWED_SEVERITY = {"info", "low", "medium", "high", "critical"}
_ALLOWED_RULE_KEYS = {
    "id", "name", "severity", "classification", "confidence",
    "base_match", "actions", "category", "mitre", "dedup_group",
    "scoring", "threshold", "base_score", "context",
    "schema_version", "implementation_status", "requires",
    "proof_level", "false_positives", "references",
}
_ALLOWED_CLASSIFICATION = {"indicator", "suspicious", "likely", "confirmed"}
_CLASSIFICATION_RANK = {"indicator": 0, "suspicious": 1, "likely": 2, "confirmed": 3}

# Rule YAML action names.  Legacy names are accepted because the bundled
# 178-rule set predates the action contract, but every unknown name is a
# load-time error.  Destructive legacy names are inventory-only and are never
# dispatched by the rule engine itself.
_ALLOWED_ACTIONS = {
    # safe contract
    "record", "evidence", "ticket", "bpf_inventory", "bpffs_inventory",
    "process_inventory", "network_inventory", "capability_inventory",
    "kernel_posture_snapshot", "correlation_request", "watch_file",
    # legacy aliases
    "log_only", "create_ticket", "ask_user", "kill_process", "block_ip",
    "notify_admin", "quarantine_file",
}
_DESTRUCTIVE_RULE_ACTIONS = {
    "kill_process", "block_ip", "quarantine_file", "user_disable",
    "process_kill", "network_isolate", "file_quarantine",
    "bpf_detach", "map_delete", "map_update",
    "xdp_detach", "tc_filter_delete", "session_terminate",
}


# Audit K1: per-event wall-clock budget for all regex matchers together.
# Denetim K1: bir olaydaki bütün düzenli ifadeler için toplam süre bütçesi.
REGEX_BUDGET_SECONDS = 0.5
REGEX_BUDGET_RULE_ID = "SATSUMA-ENGINE-001"


# 2.2.57: Satsuma's own exact command lines, never findings of these rules. The panel's
# desktop enrollment runs pkexec with a fixed root-owned program whose own option is --user
# (field 18.11 18:22: taken for "pkexec --user"). Only this exact form; any extra word,
# shell or other path still matches. Kendi tam komutlarımız; fazladan her şey yine yakalanır.
OWN_COMMANDS = {
    'SATSUMA-PRIV-003': [r'^(?:/usr/bin/)?pkexec\s+/usr/bin/satsuma-enroll-desktop'
                         r'(?:\s+--user\s+[a-z_][a-z0-9_.-]{0,31}|\s+--password-stdin)*\s*$'],
}


class RuleValidationError(ValueError):
    pass


class _RegexBudgetExceeded(RuntimeError):
    pass


def _as_list(value: Any) -> list[Any]:
    if isinstance(value, (list, tuple, set)):
        return list(value)
    return [value]


def _string(value: Any) -> str:
    return "" if value is None else str(value)


def _normalize_source(value: Any) -> str:
    if isinstance(value, dict):
        return _string(value.get("type") or value.get("collector_id"))
    return _string(value)


@functools.lru_cache(maxsize=512)
def _argv(command: str) -> tuple[str, ...]:
    # shlex is pure Python; parsing a long command line once per rule was the
    # bulk of K1's stall. Parse each command once.
    try:
        return tuple(shlex.split(command, posix=True))
    except ValueError:
        return tuple(command.split())


def _safe_shlex(command: str) -> list[str]:
    return list(_argv(command))


@functools.lru_cache(maxsize=512)
def _regex_text(text: str) -> str:
    """Collapse every whitespace run, newlines included, into one space.

    Padding then buys an attacker no CPU time, and splitting a command over
    lines no longer hides it from rules whose ``.`` stops at a newline. The
    bundled patterns rely on this single-line text: ``^(?>.*?A).*B`` tries
    only the first ``A`` on the line, which is linear and, because ``.*``
    follows, finds every match ``A.*B`` would.
    """
    return re.sub(r"\s+", " ", text)


def _is_text_tool(command: str) -> bool:
    tokens = _argv(command)
    if not tokens:
        return False
    name = tokens[0].rsplit("/", 1)[-1]
    return name in {"grep", "rg"} or (name in {"echo", "printf"} and len(tokens) <= 2)


_ARG_ALIASES = {'--all': '-a', '--decode': '-d', '--non-interactive': '-n', '--stdin': '-S', '--login': '-i', '--shell': '-s', '--chroot': '-R', '--upload-file': '-T'}


def _alias(tokens) -> tuple[str, ...]:
    expanded = []
    for token in tokens:
        if token.startswith('-o') and not token.startswith('--') and len(token) > 2:
            expanded.extend(['-o', token[2:]])
        else:
            expanded.append(token)
    return tuple(_ARG_ALIASES.get(t, t) for t in expanded)


@functools.lru_cache(maxsize=512)
def _aliased_argv(command: str) -> tuple[str, ...]:
    return _alias(_argv(command))


@functools.lru_cache(maxsize=512)
def _argument_set(command: str) -> frozenset[str]:
    return frozenset(_aliased_argv(command)[1:])


# Audit K5: programs that run another program given on their command line.
# name -> (options that take a value, positional values before the command,
#          options whose value is itself a shell command string).
# Komut satırında verilen başka bir programı çalıştıran sarmalayıcılar.
_WRAPPERS = {
    'sudo': ({'-u', '-g', '-h', '-p', '-C', '-D', '-R', '-T', '-U', '-r', '-t', '--user', '--group',
              '--host', '--prompt', '--close-from', '--chdir', '--chroot', '--command-timeout',
              '--other-user', '--role', '--type'}, 0, set()),
    'doas': ({'-u', '-C'}, 0, set()),
    'env': ({'-u', '--unset', '-C', '--chdir', '-S', '--split-string'}, 0, set()),
    'nohup': (set(), 0, set()),
    'timeout': ({'-k', '--kill-after', '-s', '--signal'}, 1, set()),
    'setsid': (set(), 0, set()),
    'nice': ({'-n', '--adjustment'}, 0, set()),
    'ionice': ({'-c', '--class', '-n', '--classdata'}, 0, set()),
    'stdbuf': ({'-i', '-o', '-e', '--input', '--output', '--error'}, 0, set()),
    'chrt': (set(), 1, set()),
    'taskset': (set(), 1, set()),
    'xargs': ({'-a', '--arg-file', '-d', '--delimiter', '-E', '-e', '-I', '-L', '-l', '-n', '--max-args',
               '-P', '--max-procs', '-s', '--max-chars', '--process-slot-var'}, 0, set()),
    'busybox': (set(), 0, set()), 'toybox': (set(), 0, set()),
    'command': (set(), 0, set()),
    'exec': ({'-a'}, 0, set()),
    'time': ({'-f', '--format', '-o', '--output'}, 0, set()),
    'chroot': ({'--userspec', '--groups'}, 1, set()),
    'su': ({'-g', '--group', '-G', '--supp-group', '-s', '--shell', '-w', '--whitelist-environment'}, 0, {'-c', '--command'}),
    'runuser': ({'-u', '--user', '-g', '--group', '-G', '--supp-group', '-s', '--shell'}, 0, {'-c', '--command'}),
    'unshare': ({'-S', '--setuid', '-G', '--setgid', '-R', '--root', '-w', '--wd', '--propagation',
                 '--map-user', '--map-group', '--map-users', '--map-groups'}, 0, set()),
    'nsenter': ({'-t', '--target', '-S', '--setuid', '-G', '--setgid', '-r', '--root', '-w', '--wd'}, 0, set()),
    'setpriv': ({'--reuid', '--regid', '--ruid', '--rgid', '--euid', '--egid', '--groups', '--inh-caps',
                 '--ambient-caps', '--bounding-set', '--securebits', '--selinux-label', '--apparmor-profile'}, 0, set()),
    'strace': ({'-o', '-e', '-p', '-s', '-u', '-a', '-E', '-O', '-P', '-S', '-X', '-b'}, 0, set()),
    'ltrace': ({'-o', '-e', '-p', '-s', '-u', '-a', '-n', '-A', '-D', '-F', '-l', '-x'}, 0, set()),
    'flock': ({'-w', '--timeout', '-E', '--conflict-exit-code'}, 1, {'-c', '--command'}),
    'watch': ({'-n', '--interval', '-d', '--differences', '-q', '--equexit'}, 0, set()),
    'script': ({'-I', '-O', '-B', '-T', '--log-in', '--log-out', '--log-io', '--log-timing', '-E', '-m'}, 0, {'-c', '--command'}),
    'systemd-run': ({'-u', '--unit', '-p', '--property', '-E', '--setenv', '--description', '--slice',
                     '--uid', '--gid', '--nice', '-H', '--host', '-M', '--machine', '--working-directory'}, 0, set()),
    'firejail': (set(), 0, set()),
    'proxychains': ({'-f'}, 0, set()), 'proxychains4': ({'-f'}, 0, set()),
    'torsocks': ({'-u', '-p', '-a', '-P'}, 0, set()), 'tsocks': (set(), 0, set()),
}
_SHELLS = {'sh', 'bash', 'dash', 'zsh', 'ksh', 'ash', 'busybox-sh'}
# A wrapper used this way runs nothing: listing, lookup, or a pid target.
_NO_COMMAND = {('sudo', '-l'), ('sudo', '-v'), ('sudo', '-k'), ('sudo', '-K'), ('command', '-v'),
               ('command', '-V'), ('taskset', '-p'), ('ionice', '-p'), ('chrt', '-p'), ('strace', '-p'),
               ('ltrace', '-p')}


def _unwrap(tokens):
    """The command a wrapper runs: (tokens, None), (None, shell string) or None."""
    name = tokens[0].rsplit('/', 1)[-1]
    if name in _SHELLS:
        if '-c' in tokens[1:]:
            index = tokens.index('-c')
            return (None, tokens[index + 1]) if index + 1 < len(tokens) else None
        return None
    spec = _WRAPPERS.get(name)
    if spec is None:
        return None
    takes_value, positional, shell_value = spec
    index, dashdash, user_given = 1, False, False
    while index < len(tokens):
        token = tokens[index]
        option = token.split('=', 1)[0]
        if (name, option) in _NO_COMMAND:
            return None
        if token == '--':
            index += 1
            dashdash = True
            break
        if token == '-':  # su - USER: a login shell
            index += 1
            continue
        if option in ('-u', '--user'):
            user_given = True
        if option in shell_value:
            value = token.split('=', 1)[1] if '=' in token else (tokens[index + 1] if index + 1 < len(tokens) else '')
            return (None, value) if value else None
        if name == 'env' and option in {'-S', '--split-string'}:
            value = token.split('=', 1)[1] if '=' in token else (tokens[index + 1] if index + 1 < len(tokens) else '')
            return (None, value) if value else None
        if name == 'env' and '=' in token and not token.startswith('-'):
            index += 1
            continue
        if token.startswith('-') and len(token) > 1:
            if option in takes_value and '=' not in token:
                index += 2
            elif (not token.startswith('--') and len(token) > 2 and token[:2] in takes_value):
                index += 1  # value attached: -uroot, -oL
            elif name == 'nice' and token[1:].isdigit():
                index += 1  # nice -10 cmd
            else:
                index += 1
            continue
        break
    index += positional
    if index + 1 < len(tokens) and tokens[index] in shell_value:
        return (None, tokens[index + 1])  # flock FILE -c "command"
    if (name in ('su', 'runuser') and not dashdash and not user_given
            and index < len(tokens) and not tokens[index].startswith('-')):
        return None  # su USER without -c: an interactive shell, not a command
    rest = tokens[index:]
    if name == 'xargs' and not rest:
        rest = ('echo',)
    return (tuple(rest), None) if rest else None


_SCRIPT_OPERATORS = set(';&|()')


@functools.lru_cache(maxsize=512)
def _split_script(script: str) -> tuple[str, ...]:
    """Split a shell -c string into its simple commands, quotes respected."""
    lexer = shlex.shlex(script, posix=True, punctuation_chars=';&|()')
    lexer.whitespace_split = True
    commands, current = [], []
    try:
        for token in lexer:
            if token and set(token) <= _SCRIPT_OPERATORS:
                if current:
                    commands.append(shlex.join(current))
                current = []
            else:
                current.append(token)
    except ValueError:
        return (script,)
    if current:
        commands.append(shlex.join(current))
    return tuple(commands) or (script,)


# Programs whose arguments are text being searched or printed, not acted on.
_TEXT_TOOLS = {'grep', 'egrep', 'fgrep', 'zgrep', 'rg', 'ag', 'ack', 'echo', 'printf', 'man', 'apropos'}


def _arg_in_command(command: str, needle: str, exe: str = '') -> bool:
    """Any argument of any stage contains ``needle`` (text tools excluded)."""
    for tokens, _ in _stages(command, exe):
        if tokens and tokens[0].rsplit('/', 1)[-1] not in _TEXT_TOOLS and any(needle in t for t in tokens):
            return True
    return False


@functools.lru_cache(maxsize=1024)
def _stages(command: str, exe: str = '', depth: int = 0) -> tuple:
    """Every command a command line runs, outermost first, as (tokens, argument set).

    A shell's own ``-c`` stage is replaced by the command it runs, as before;
    a wrapper stays as a stage too, so rules about the wrapper keep working.
    The real executable reported by the kernel stands in for argv[0] when the
    two differ (``exec -a`` or a renamed link), so a disguised name is seen
    through.
    """
    raw = _argv(command)
    if not raw or depth > 8:
        return ()
    found, tokens = [], raw
    if exe and depth == 0:
        real = exe.rsplit('/', 1)[-1]
        if real and real != tokens[0].rsplit('/', 1)[-1]:
            disguised = (exe, *tokens[1:])
            found.append((_alias(disguised), frozenset(_alias(disguised)[1:])))
    for _ in range(16):
        inner = _unwrap(tokens)
        if inner is None or tokens[0].rsplit('/', 1)[-1] not in _SHELLS:
            found.append((_alias(tokens), frozenset(_alias(tokens)[1:])))
        if inner is None:
            break
        if inner[1] is not None:
            # Each simple command of the script is its own stage:
            # "a | b; c && d" runs a, b, c and d.
            for simple in _split_script(inner[1]):
                found.extend(_stages(simple, '', depth + 1))
            break
        tokens = inner[0]
    return tuple(found)


@functools.lru_cache(maxsize=512)
def _stage_texts(command: str, exe: str = '') -> tuple[str, ...]:
    """The command line and each unwrapped stage, as text for regex rules."""
    texts = [command]
    for tokens, _ in _stages(command, exe):
        text = ' '.join(tokens)
        if text not in texts:
            texts.append(text)
    return tuple(texts)


@functools.lru_cache(maxsize=1024)
def _wanted(term: str) -> tuple[str, ...]:
    try:
        wanted = shlex.split(term.strip())
    except ValueError:
        wanted = shlex.split(term.strip() + ("'" if term.count("'") % 2 else '"'))
    return tuple(_ARG_ALIASES.get(t, t) for t in wanted)


def _term_in_command(command: str, term: str, exe: str = '') -> bool:
    """Case-sensitive argv matching; never treat documentation arguments as commands.

    Every stage of the command line is tried: the command itself, what each
    wrapper (sudo, env, nohup, timeout, busybox, ...) runs, and what a shell
    ``-c`` string runs (audit K5).
    """
    wanted = _wanted(term)
    if not wanted:
        return False
    return any(_stage_has_term(tokens, arguments, wanted) for tokens, arguments in _stages(command, exe))


def _own_option_end(tokens) -> int:
    """Where a wrapper's or shell's own options end; the rest belongs to the command it runs.

    Field 2026-11-04: "sh -c -- ps --no-header -p 28956" matched "sh -p"
    (SUID shell) and "sudo journalctl -n 30" matched "sudo -n": the -p and
    -n belonged to ps and journalctl. Other programs keep all arguments.
    Sarmalayıcının ya da kabuğun kendi seçeneklerinin bittiği yer; gerisi
    çalıştırdığı komutundur. Saha 2026-11-04: ps'in -p'si "sh -p", journalctl'ın
    -n'si "sudo -n" sayılıyordu.
    """
    name = tokens[0].rsplit('/', 1)[-1]
    if name in _SHELLS:
        for index in range(1, len(tokens)):
            if tokens[index] == '--' or not tokens[index].startswith('-'):
                return index
        return len(tokens)
    if name in _WRAPPERS:
        inner = _unwrap(tokens)
        if inner is None:
            return len(tokens)
        if inner[0] is not None:
            return len(tokens) - len(inner[0])
        script = inner[1]
        return max(i for i, token in enumerate(tokens) if token == script) if script in tokens else len(tokens)
    return len(tokens)


def _stage_has_term(tokens, arguments, wanted) -> bool:
    if not tokens or tokens[0].rsplit('/', 1)[-1] != wanted[0].rsplit('/', 1)[-1]:
        return False
    if len(wanted) == 1:
        return True
    own_end = _own_option_end(tokens)
    arguments = frozenset(tokens[1:own_end]) | frozenset(t for t in arguments if not t.startswith('-'))
    def equal(actual, expected):
        if actual == expected:
            return True
        if ' ' in expected and actual.startswith(expected):
            return True
        if expected == '-p' and actual.startswith('-p') and len(actual)>2:
            return True
        if expected.startswith('-') and len(expected) == 2 and actual.startswith('-') and not actual.startswith('--') and expected[1] in actual[1:] and len(actual) <= 5:
            return True
        if expected in {'/dev/sd', '/dev/nvme'}:
            return bool(re.fullmatch(re.escape(expected) + r'[A-Za-z0-9]+', actual))
        if expected.startswith('/'):
            return actual.startswith(expected) if expected.endswith('/') else actual.startswith(expected + '/')
        if expected.startswith('--') and '=' not in expected:
            return actual.startswith(expected + '=')
        # Short option bundles are case sensitive (-vfz == -v -f -z).
        if expected.startswith('-') and not expected.startswith('--') and len(expected) > 2:
            return (actual.startswith('-') and not actual.startswith('--') and sorted(actual[1:]) == sorted(expected[1:])) or all('-' + flag in arguments for flag in expected[1:])
        return False
    cursor = 1
    for expected in wanted[1:]:
        # An option after the term's command word ("sudo su -") is that command's own.
        limit = own_end if expected.startswith('-') and cursor <= own_end else len(tokens)
        for index in range(cursor, limit):
            if equal(tokens[index], expected):
                cursor = index + 1
                break
        else:
            return False
    return True


class SmartRuleEngine:
    def __init__(self, rules_dir: str | os.PathLike[str] | None = None, *, include_managed=None):
        # Audit G4: the rules directory is never taken from the environment.
        # A systemd drop-in pointing SATSUMA_RULES_DIR at an empty directory
        # silently disabled every rule; the variable is now only reported.
        env_dir = os.environ.get("SATSUMA_RULES_DIR")
        if rules_dir is not None:
            selected = Path(rules_dir)
        elif BUNDLED_RULES_DIR.exists():
            selected = BUNDLED_RULES_DIR
        else:
            selected = SYSTEM_RULES_DIR

        self.rules_dir = selected
        self._managed_enabled = rules_dir is None if include_managed is None else include_managed
        self._managed_checked = 0.0
        self.rules: list[dict[str, Any]] = []
        self.load_errors: list[dict[str, str]] = []
        self._ids: set[str] = set()
        if env_dir and rules_dir is None and Path(env_dir) != selected:
            self.load_errors.append({"file": env_dir, "error": "SATSUMA_RULES_DIR ignored (audit G4)"})
        self.regex_budget_exceeded = 0
        self._regex_deadline: float | None = None
        self._load_rules()

    # ------------------------------------------------------------------
    # Yükleme / doğrulama
    # ------------------------------------------------------------------
    def _load_rules(self) -> None:
        if not self.rules_dir.exists():
            self.load_errors.append({"file": str(self.rules_dir), "error": "rules_dir_missing"})
            return
        self._load_rule_files()
        if self._managed_enabled:
            self.refresh_managed_rules(force=True)
        if not self.rules and not self.load_errors:
            # An empty rule set is never a quiet success.
            self.load_errors.append({"file": str(self.rules_dir), "error": "no_rules_loaded"})

    def _load_rule_files(self, paths=None) -> None:
        for yaml_file in sorted(self.rules_dir.rglob("*.yaml") if paths is None else paths):
            if yaml_file.name in NON_RULE_YAML:
                continue
            category_from_file = yaml_file.stem
            try:
                with yaml_file.open(encoding="utf-8") as stream:
                    loaded = yaml.safe_load(stream)
                if loaded is None:
                    continue
                if not isinstance(loaded, list):
                    raise RuleValidationError("YAML root must be a list")
                signed = None
                from .rule_signing import MANAGED_RULES_DIR, verify_installed_rule
                managed = MANAGED_RULES_DIR in yaml_file.parents
                ai = any(isinstance(r, dict) and str(r.get('id', '')).startswith('SATSUMA-AI-') for r in loaded)
                if managed or ai or 'generated' in yaml_file.parts:
                    signed = verify_installed_rule(yaml_file, loaded)
                for index, raw_rule in enumerate(loaded, 1):
                    try:
                        rule = self._validate_rule(raw_rule, yaml_file, index, category_from_file)
                        from .ai_rule_package import digest
                        rule['_content_hash'] = digest({k:v for k,v in rule.items() if not k.startswith('_')})
                        if signed:
                            rule['_content_hash'] = signed['detection_hash']
                            rule['_ai_package_digest'] = signed['package_hash']
                            rule['_response_proposal'] = signed['response_proposal']
                        self.rules.append(rule)
                    except Exception as exc:
                        self.load_errors.append({
                            "file": str(yaml_file),
                            "error": f"rule #{index}: {type(exc).__name__}: {exc}"[:500],
                        })
            except Exception as exc:
                self.load_errors.append({
                    "file": str(yaml_file),
                    "error": f"{type(exc).__name__}: {exc}"[:500],
                })

    def refresh_managed_rules(self, *, force=False):
        if not self._managed_enabled or (not force and time.monotonic() - self._managed_checked < 10):
            return
        self._managed_checked = time.monotonic()
        from .rule_signing import MANAGED_RULES_DIR
        from .ai_rule_package import AI_ID
        root = MANAGED_RULES_DIR
        self.rules = [r for r in self.rules if root not in Path(r.get('_file', '')).parents]
        self._ids = {r['_id'] for r in self.rules}
        self.load_errors = [e for e in self.load_errors if not str(e.get('file', '')).startswith(str(root) + '/')]
        if root.exists():
            paths = [d / 'rule.yaml' for d in root.iterdir() if AI_ID.fullmatch(d.name)]
            self._load_rule_files(paths)

    def _validate_rule(self, raw_rule: Any, path: Path, index: int, category: str) -> dict[str, Any]:
        if not isinstance(raw_rule, dict):
            raise RuleValidationError(f"rule #{index} must be a mapping")

        unknown_rule_keys = sorted(set(raw_rule) - _ALLOWED_RULE_KEYS)
        if unknown_rule_keys:
            raise RuleValidationError(
                "unknown rule key(s): " + ", ".join(unknown_rule_keys)
            )
        status = raw_rule.get("implementation_status")
        if status is not None and status != "CURRENT_TELEMETRY":
            raise RuleValidationError(
                f"{raw_rule.get('id', '?')}: only CURRENT_TELEMETRY rules may be active"
            )

        rule = dict(raw_rule)
        rule_id = _string(rule.get("id")).strip()
        if not rule_id:
            raise RuleValidationError(f"rule #{index} missing id")
        if rule_id in self._ids:
            raise RuleValidationError(f"duplicate rule id: {rule_id}")

        severity = _string(rule.get("severity", "medium")).lower()
        if severity not in _ALLOWED_SEVERITY:
            raise RuleValidationError(f"{rule_id}: invalid severity {severity}")

        classification = _string(rule.get("classification") or self._default_classification(severity)).lower()
        if classification not in _ALLOWED_CLASSIFICATION:
            raise RuleValidationError(f"{rule_id}: invalid classification {classification}")
        if classification == "confirmed":
            # A single rule/regex/process event cannot manufacture CONFIRMED.
            # Correlation is a separate multi-source stage.
            raise RuleValidationError(
                f"{rule_id}: confirmed classification requires multi-source correlation"
            )

        actions = self._normalize_actions(rule.get("actions", []))
        if not actions:
            raise RuleValidationError(f"{rule_id}: actions must be a non-empty list")
        unknown_actions = sorted(set(actions) - _ALLOWED_ACTIONS)
        if unknown_actions:
            raise RuleValidationError(
                f"{rule_id}: unknown or unsupported action(s): {', '.join(unknown_actions)}"
            )

        base_match = rule.get("base_match")
        if not isinstance(base_match, dict) or not base_match:
            raise RuleValidationError(f"{rule_id}: base_match must be a non-empty mapping")
        unknown = sorted(set(base_match) - _ALLOWED_MATCH_KEYS)
        if unknown:
            raise RuleValidationError(f"{rule_id}: unknown matcher(s): {', '.join(unknown)}")

        # Regex'leri yükleme anında doğrula.
        for key in ("cmd_regex", "cmd_regex_cs", "cmd_not_regex", "exe_regex"):
            if key in base_match:
                for pattern in _as_list(base_match[key]):
                    try:
                        re.compile(_string(pattern), flags=0 if key == "cmd_regex_cs" else re.IGNORECASE)
                    except re.error as exc:
                        raise RuleValidationError(f"{rule_id}: invalid {key}: {exc}") from exc

        threshold = rule.get("threshold")
        if threshold is not None and (type(threshold) not in (int, float)):
            raise RuleValidationError(f"{rule_id}: threshold must be numeric")
        base_score = rule.get("base_score")
        if base_score is not None and type(base_score) not in (int, float):
            raise RuleValidationError(f"{rule_id}: base_score must be numeric")

        if rule_id in OWN_COMMANDS:
            # The original rule files stay byte for byte; Satsuma's own exact commands are added here.
            base_match = rule["base_match"] = dict(base_match)
            base_match["cmd_not_regex"] = [*_as_list(base_match.get("cmd_not_regex") or []), *OWN_COMMANDS[rule_id]]
        rule["_file"] = str(path)
        rule["_id"] = rule_id
        rule["severity"] = severity
        rule["classification"] = classification
        rule.setdefault("category", category)
        rule.setdefault("confidence", self._default_confidence(classification))
        self._ids.add(rule_id)
        return rule

    @staticmethod
    def _default_classification(severity: str) -> str:
        # Severity etkiyi, classification ise kanıt gücünü anlatır.
        return "suspicious" if severity in {"high", "critical"} else "indicator"

    @staticmethod
    def _default_confidence(classification: str) -> str:
        return {
            "indicator": "low",
            "suspicious": "medium",
            "likely": "high",
            "confirmed": "high",
        }[classification]

    # ------------------------------------------------------------------
    # Event alanları
    # ------------------------------------------------------------------
    def _extensions(self, event: dict[str, Any]) -> dict[str, Any]:
        # One event is read by every rule; merge its extensions once
        # (2.2.32: this merge was 40% of the rule engine's time).
        memo = getattr(self, "_ext_memo", None)
        if memo is not None and memo[0] is event:
            return memo[1]
        out = self._merge_extensions(event)
        self._ext_memo = (event, out)
        return out

    def _merge_extensions(self, event: dict[str, Any]) -> dict[str, Any]:
        out: dict[str, Any] = {}
        metadata = event.get("metadata")
        if isinstance(metadata, dict):
            ext = metadata.get("extensions")
            if isinstance(ext, dict):
                out.update(ext)

        raw = event.get("raw")
        if isinstance(raw, dict):
            raw_meta = raw.get("metadata")
            if isinstance(raw_meta, dict):
                ext = raw_meta.get("extensions")
                if isinstance(ext, dict):
                    out.update(ext)
        return out

    def _cmd(self, event: dict[str, Any]) -> str:
        ext = self._extensions(event)
        raw = event.get("raw") if isinstance(event.get("raw"), dict) else {}
        return _string(
            event.get("cmd")
            or ext.get("host.cmd")
            or raw.get("cmd")
            or raw.get("command_line")
            or raw.get("a0")
        )

    def _exe(self, event: dict[str, Any]) -> str:
        ext = self._extensions(event)
        raw = event.get("raw") if isinstance(event.get("raw"), dict) else {}
        return _string(event.get("exe") or ext.get("host.exe") or raw.get("exe"))

    def _file_path(self, event: dict[str, Any]) -> str:
        ext = self._extensions(event)
        raw = event.get("raw") if isinstance(event.get("raw"), dict) else {}
        return _string(
            event.get("file_path")
            or event.get("path")
            or ext.get("host.file_path")
            or ext.get("host.path")
            or raw.get("file_path")
            or raw.get("path")
        )

    def _operation(self, event: dict[str, Any]) -> str:
        ext = self._extensions(event)
        raw = event.get("raw") if isinstance(event.get("raw"), dict) else {}
        return _string(
            event.get("operation")
            or ext.get("host.operation")
            or raw.get("operation")
            or raw.get("syscall_name")
        ).lower()

    def _uid(self, event: dict[str, Any]) -> Any:
        ext = self._extensions(event)
        raw = event.get("raw") if isinstance(event.get("raw"), dict) else {}
        return event.get("uid", ext.get("host.uid", raw.get("uid")))


    @staticmethod
    def _normalize_actions(value: Any) -> list[str]:
        """YAML action spec'ini canonical action isimlerine cevir."""
        out: list[str] = []
        def walk(item: Any) -> None:
            if isinstance(item, str):
                for token in re.split(r"[+,]", item):
                    token = token.strip()
                    if token and token not in out:
                        out.append(token)
            elif isinstance(item, dict):
                for nested in item.values():
                    walk(nested)
            elif isinstance(item, (list, tuple, set)):
                for nested in item:
                    walk(nested)
        walk(value)
        return out

    # ------------------------------------------------------------------
    # Eşleşme
    # ------------------------------------------------------------------
    def match(self, event: dict[str, Any]) -> list[dict[str, Any]]:
        self.refresh_managed_rules()
        self.load_errors = [item for item in self.load_errors if not str(item.get('error', '')).startswith('runtime ')]
        findings: list[dict[str, Any]] = []
        starved: list[str] = []
        # 2.2.54 (field 2026-11-19): measured in this thread's CPU time, not wall-clock.
        # On a busy machine "ps --no-header -p N o pid" ran out of a wall-clock budget
        # and every remaining rule was skipped for that event; an attacker could load
        # the machine to blind detection. A regex that really burns CPU still stops.
        # Süre, duvar saatiyle değil bu iş parçacığının işlemci süresiyle ölçülür.
        self._regex_deadline = time.thread_time() + REGEX_BUDGET_SECONDS
        self._ext_memo = None
        view = self._view(event)
        for rule, compiled in self._candidates(view):
            try:
                try:
                    if not self._matches_compiled(compiled, view):
                        continue
                except _RegexBudgetExceeded:
                    starved.append(rule["_id"])
                    continue
                if self._own_package_transaction(rule, event) or self._own_readonly_probe(rule, event):
                    continue
                score = self._score(rule, event)
                threshold = rule.get("threshold")
                if threshold is not None and score < threshold:
                    continue

                raw_actions = rule.get("actions", []) or []
                actions = self._normalize_actions(raw_actions)
                log_only = "log_only" in actions and "create_ticket" not in actions
                event_id = event.get("id") or event.get("raw_id") or event.get("pid") or event.get("timestamp") or "0"
                fingerprint = hashlib.sha256(
                    f"{rule['_id']}|{event_id}".encode("utf-8", errors="replace")
                ).hexdigest()[:24]

                findings.append({
                    "rule_id": rule["_id"],
                    "rule_name": rule.get("name", ""),
                    "rule_content_hash": rule.get("_content_hash"),
                    **({"ai_package_digest": rule["_ai_package_digest"], "response_proposal": rule["_response_proposal"]}
                       if rule.get("_ai_package_digest") else {}),
                    "severity": rule["severity"],
                    "classification": rule["classification"],
                    "category": rule.get("category", "unknown"),
                    "mitre": rule.get("mitre", {}),
                    "score": score,
                    "threshold": threshold,
                    "actions": actions,
                    "action_spec": raw_actions,
                    "log_only": log_only,
                    "event": event,
                    "timestamp": int(time.time()),
                    "finding_id": f"smart_{fingerprint}",
                    "type": rule.get("category", "unknown"),
                    "summary": rule.get("name", ""),
                    "confidence": _string(rule.get("confidence") or self._default_confidence(rule["classification"])),
                    "attribution": "smart-rule-v2",
                    "rule_file": rule.get("_file"),
                    "dedup_group": rule.get("dedup_group", rule["_id"]),
                    "matched_rules": [rule["_id"]],
                })
            except Exception as exc:
                # Runtime matcher hatası bir rule-load problemi kadar ciddi değil,
                # fakat sessizce tüm motoru düşürmez.
                self.load_errors.append({
                    "file": rule.get("_file", "?"),
                    "error": f"runtime {rule.get('_id')}: {type(exc).__name__}: {exc}"[:500],
                })
        self._regex_deadline = None
        if starved:
            self.regex_budget_exceeded += 1
            findings.append(self._budget_finding(event, starved))
        runtime_errors = [item for item in self.load_errors if str(item.get('error', '')).startswith('runtime ')]
        if runtime_errors:
            raise RuntimeError('Smart rule evaluation failed: ' + runtime_errors[-1]['error'])
        # 2.2.38 (owner, 2026-11-18): a write to /etc/passwd or /etc/shadow is
        # judged by what it changed, once per event (satsuma.account_change).
        # Yazma, neyi değiştirdiğine göre değerlendirilir; olay başına bir kez.
        from . import account_change
        if any(account_change.applies(f) for f in findings):
            result = account_change.TRACKER.check() if self.account_tracker is None else self.account_tracker.check()
            for finding in findings:
                account_change.apply(finding, result)
        return self._deduplicate(findings)

    # Tests and the teams service may give their own tracker; None uses the shared one.
    account_tracker = None

    def _budget_finding(self, event: dict[str, Any], starved: list[str]) -> dict[str, Any]:
        # Rules that ran out of time are named, never silently dropped: a
        # command line built to exhaust the budget is itself the signal.
        event_id = event.get("id") or event.get("raw_id") or event.get("pid") or event.get("timestamp") or "0"
        fingerprint = hashlib.sha256(f"{REGEX_BUDGET_RULE_ID}|{event_id}".encode("utf-8", errors="replace")).hexdigest()[:24]
        name = "Rule engine regex budget exhausted; command line may be built to blind detection"
        return {
            "rule_id": REGEX_BUDGET_RULE_ID,
            "rule_name": name,
            "severity": "medium",
            "classification": "suspicious",
            "category": "defense_evasion",
            "mitre": {"technique": "T1562"},
            "score": 0,
            "threshold": None,
            "actions": ["record", "evidence"],
            "action_spec": ["record", "evidence"],
            "log_only": False,
            "event": event,
            "timestamp": int(time.time()),
            "finding_id": f"smart_{fingerprint}",
            "type": "defense_evasion",
            "summary": name,
            "confidence": "medium",
            "attribution": "smart-rule-v2",
            "rule_file": None,
            "dedup_group": REGEX_BUDGET_RULE_ID,
            "matched_rules": [REGEX_BUDGET_RULE_ID],
            "unevaluated_rules": starved,
        }

    def _deduplicate(self, findings: list[dict[str, Any]]) -> list[dict[str, Any]]:
        """Aynı event üzerindeki eşdeğer kural ailelerini tek bulguda birleştir."""
        grouped: dict[tuple[str, str], dict[str, Any]] = {}
        severity_rank = {"info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}
        for finding in findings:
            event = finding.get("event", {})
            event_id = _string(event.get("id") or event.get("raw_id") or event.get("pid") or event.get("timestamp") or "0")
            group = _string(finding.get("dedup_group") or finding.get("rule_id"))
            key = (event_id, group)
            current = grouped.get(key)
            if current is None:
                grouped[key] = finding
                continue

            # Daha güçlü classification/severity ana bulgu olsun, ama tüm rule id'leri koru.
            cur_strength = (
                _CLASSIFICATION_RANK.get(_string(current.get("classification")), -1),
                severity_rank.get(_string(current.get("severity")), -1),
            )
            new_strength = (
                _CLASSIFICATION_RANK.get(_string(finding.get("classification")), -1),
                severity_rank.get(_string(finding.get("severity")), -1),
            )
            if new_strength > cur_strength:
                finding["matched_rules"] = list(dict.fromkeys(current.get("matched_rules", []) + finding.get("matched_rules", [])))
                grouped[key] = finding
            else:
                current["matched_rules"] = list(dict.fromkeys(current.get("matched_rules", []) + finding.get("matched_rules", [])))
        return list(grouped.values())

    # Cheap conditions are checked first, regular expressions last; a rule
    # is the AND of its conditions, so the order never changes the verdict.
    # Ucuz koşullar önce, düzenli ifadeler en son denetlenir; kural
    # koşullarının VE'sidir, sıra sonucu değiştirmez.
    _KEY_ORDER = {key: i for i, key in enumerate((
        "source", "action", "kind", "category", "operation", "uid", "uid_not", "exe_contains",
        "file_path", "file_path_not", "parent_contains", "env_contains", "cmd_contains",
        "cmd_arg_contains", "cmd_not_contains", "exe_regex", "cmd_not_regex", "cmd_regex_cs", "cmd_regex"))}
    _SET_KEYS = frozenset({"source", "action", "kind", "category", "uid", "uid_not"})

    @classmethod
    def _compile_spec(cls, match_spec: dict[str, Any]) -> tuple:
        compiled = []
        for key, value in match_spec.items():
            values = [_string(v) for v in _as_list(value)]
            if key == "operation":
                prepared: Any = frozenset(v.lower() for v in values)
            elif key in cls._SET_KEYS:
                prepared = frozenset(values)
            else:
                prepared = tuple(values)
            compiled.append((cls._KEY_ORDER.get(key, -1), key, prepared))
        compiled.sort(key=lambda item: item[0])
        return tuple((key, prepared) for _, key, prepared in compiled)

    def _compiled_base(self, rule: dict[str, Any]) -> tuple:
        cache = getattr(self, "_compiled", None)
        if cache is None:
            cache = self._compiled = {}
        hit = cache.get(id(rule))
        if hit is not None and hit[0] is rule:
            return hit[1]
        if len(cache) > 4 * max(len(self.rules), 64):
            cache.clear()
        compiled = self._compile_spec(rule["base_match"])
        cache[id(rule)] = (rule, compiled)
        return compiled

    # 2.2.55: the coverage_gaps rules match by regex, so the cmd_contains index could not
    # place them and every event tried all of them (engine speed requirement 0.2 ms,
    # owner 2026-11-04). Each names the programs whose stage it can match; "*" stands for
    # the shells and wrappers that run a script or another command. Rules not listed stay
    # generic (tried on every event). Program names are also looked up without a version
    # suffix (python3.15 -> python).
    # Regex ile eşleşen yeni kurallar yalnızca adı geçen programların olaylarında denenir.
    PROGRAM_HINTS = {
        'SATSUMA-GAP-001': ('python', 'python3', 'python2', '*'),
        'SATSUMA-GAP-002': ('perl', '*'), 'SATSUMA-GAP-003': ('php', '*'),
        'SATSUMA-GAP-004': ('nc', 'ncat', 'netcat', '*'), 'SATSUMA-GAP-005': ('mkfifo', 'mknod', '*'),
        'SATSUMA-GAP-006': ('openssl', '*'), 'SATSUMA-GAP-007': ('curl', 'wget', '*'),
        'SATSUMA-GAP-012': ('*',), 'SATSUMA-GAP-014': ('systemd-run', '*'),
        'SATSUMA-GAP-016': ('useradd', 'usermod', '*'), 'SATSUMA-GAP-017': ('usermod', 'gpasswd', '*'),
        'SATSUMA-GAP-018': ('tee', 'echo', 'printf', '*'), 'SATSUMA-GAP-019': ('chmod', '*'),
        'SATSUMA-GAP-020': ('setcap', '*'), 'SATSUMA-GAP-021': ('auditctl', '*'),
        'SATSUMA-GAP-022': ('pkill', 'killall', '*'), 'SATSUMA-GAP-023': ('nft', '*'),
        'SATSUMA-GAP-024': ('journalctl', '*'), 'SATSUMA-GAP-025': ('chattr', '*'),
        'SATSUMA-GAP-026': ('mount', '*'), 'SATSUMA-GAP-029': ('cat', 'dd', 'hexdump', 'xxd', 'od', 'tee', 'python', 'perl', 'evtest', '*'),
        'SATSUMA-GAP-030': ('unshadow', 'john', 'hashcat', 'cat', 'less', 'more', 'head', 'tail', 'cp', 'base64', 'xxd', 'strings', '*'),
        'SATSUMA-GAP-031': ('hydra', 'medusa', 'ncrack', 'patator', 'crowbar', '*'),
        'SATSUMA-GAP-032': ('nmap', 'masscan', 'zmap', 'rustscan', 'naabu', '*'),
        'SATSUMA-GAP-033': ('chisel', 'ngrok', 'frpc', 'frps', 'ligolo', 'ligolo-ng', 'rathole', 'bore', 'cloudflared', '*'),
        'SATSUMA-GAP-034': ('ssh', '*'), 'SATSUMA-GAP-035': ('rm', '*'),
        'SATSUMA-GAP-036': ('rpm-ostree', 'dnf', 'yum', 'rpm', 'dnf5', '*'),
        'SATSUMA-GAP-037': ('rm', 'shred', 'truncate', 'mv', 'dd', 'sqlite3', '*'),
        'SATSUMA-GAP-038': ('docker', 'podman', 'nerdctl', '*'), 'SATSUMA-GAP-039': ('*',),
        'SATSUMA-GAP-041': ('*',), 'SATSUMA-GAP-042': ('useradd', 'adduser', 'newusers', '*'),
        'SATSUMA-GAP-043': ('sudo', '*'), 'SATSUMA-GAP-044': ('strace', 'ltrace', '*'),
        'SATSUMA-GAP-046': ('ostree', 'rpm-ostree', '*'), 'SATSUMA-GAP-048': ('touch', '*'),
        'SATSUMA-GAP-049': ('shred', 'wipe', 'srm', '*'), 'SATSUMA-GAP-050': ('chattr', '*'),
        'SATSUMA-GAP-051': ('ccencrypt', 'ccrypt', '7z', '7za', 'gpg', 'gpg2', 'openssl', '*'),
        'SATSUMA-GAP-052': ('update-ca-trust', 'update-ca-certificates', 'certctl', 'trust', 'cp', 'mv', 'install', 'tee', 'ln', '*'),
        'SATSUMA-GAP-054': ('tee', 'echo', 'printf', 'python', '*'), 'SATSUMA-GAP-055': ('trap', 'export', '*'),
        'SATSUMA-GAP-056': ('tcpdump', 'tshark', 'dumpcap', 'ettercap', 'bettercap', 'arpspoof', 'dsniff', 'ngrep', 'responder', '*'),
        'SATSUMA-GAP-057': ('sed', 'perl', 'awk', 'tee', 'cp', 'mv', 'install', 'ln', 'echo', 'printf', '*'),
        'SATSUMA-GAP-058': ('auditctl', '*'),
        'SATSUMA-GAP-059': ('cat', 'less', 'more', 'strings', 'tail', 'head', 'cp', 'base64', 'tac', 'awk', 'sed', '*'),
        'SATSUMA-GAP-060': ('xwd', 'import', 'ffmpeg', '*'),
        'SATSUMA-GAP-061': ('gcc', 'cc', 'clang', 'g++', 'c++', 'clang++', 'tcc', 'go', '*'),
        'SATSUMA-GAP-063': ('*',), 'SATSUMA-GAP-064': ('kill', 'pkill', 'killall', 'echo', '*'),
        'SATSUMA-GAP-065': ('tor', 'torsocks', 'torify', 'proxychains', 'proxychains4', 'systemctl', 'ssh', '*'),
        'SATSUMA-GAP-066': ('sshpass', 'chpasswd', 'passwd', '*'), 'SATSUMA-GAP-067': ('mkdir', '*'),
        'SATSUMA-GAP-068': ('python', 'perl', 'ruby', 'node', '*'),
        'SATSUMA-GAP-070': ('cp', 'cat', 'find', 'sqlite3', 'tar', 'zip', '7z', '7za', 'rsync', 'scp', 'base64', 'strings', 'dd', '*'),
        'SATSUMA-GAP-071': ('rm', 'cp', 'mv', 'shred', 'truncate', 'tar', '*'),
        'SATSUMA-GAP-073': ('insmod', 'modprobe', 'kmod', '*'),
        'SATSUMA-GAP-075': ('rpm-ostree', '*'),
    }

    @staticmethod
    def _hint_names(names) -> set:
        out = set()
        for name in names:
            if name == '*':
                out |= _SHELLS | set(_WRAPPERS) | {'busybox', 'xargs', 'watch', 'flock', 'script', 'su', 'runuser', 'pkexec'}
            else:
                out.add(name)
        return out

    def _rule_index(self) -> tuple:
        """Rules grouped by the program their cmd_contains needs.

        A cmd_contains term matches only a stage whose program has the
        term's first word as its name (_stage_has_term), so a rule whose
        terms name none of the event's programs can never match; it is not
        tried. Rules without cmd_contains are always tried. Rebuilt whenever
        the rule list changes.

        cmd_contains terimi yalnızca adı terimin ilk sözcüğü olan programın
        aşamasıyla eşleşir; terimleri olayın programlarından hiçbirini
        anmayan kural asla eşleşemez, denenmez. Kural listesi değişince
        yeniden kurulur.
        """
        rules = self.rules
        index = getattr(self, "_index_cache", None)
        if index is not None and index[0] is rules and index[1] == len(rules):
            return index
        entries, generic, by_program = [], [], {}
        for position, rule in enumerate(rules):
            compiled = self._compiled_base(rule)
            entries.append((rule, compiled))
            terms = next((values for key, values in compiled if key == "cmd_contains"), None)
            names = set()
            for term in terms or ():
                wanted = _wanted(term)
                names.add(wanted[0].rsplit("/", 1)[-1] if wanted else None)
            hint = self.PROGRAM_HINTS.get(rule.get("_id"))
            if hint and not terms:
                for name in self._hint_names(hint):
                    by_program.setdefault(name, []).append(position)
            elif not terms or None in names:
                generic.append(position)
            else:
                for name in names:
                    by_program.setdefault(name, []).append(position)
        index = self._index_cache = (rules, len(rules), entries, tuple(generic), by_program)
        return index

    def _candidates(self, view: dict[str, Any]) -> list:
        _, _, entries, generic, by_program = self._rule_index()
        if not by_program:
            return entries
        picked = set(generic)
        # The command line's own program and the kernel's executable count too: a shell
        # running a -c script is replaced by the script's commands in _stages, but the
        # regex rules are also tried on the whole command line.
        outer = [(_argv(view["cmd"])[:1] or [""])[0], view["exe"]]
        for tokens in [*(t for t, _ in _stages(view["cmd"], view["exe"])), *([o] for o in outer if o)]:
            if tokens:
                name = tokens[0].rsplit("/", 1)[-1]
                picked.update(by_program.get(name, ()))
                bare = name.rstrip("0123456789.")
                if bare != name:
                    picked.update(by_program.get(bare, ()))
        return [entries[i] for i in sorted(picked)]

    def _view(self, event: dict[str, Any]) -> dict[str, Any]:
        """Every field the conditions read, taken from the event once."""
        action = _string(event.get("action"))
        raw = event.get("raw")
        env = _string(event.get("env") or (raw or {}).get("env") if isinstance(raw, dict) else event.get("env"))
        ext = self._extensions(event)
        return {
            "source": _normalize_source(event.get("source")),
            "action": action,
            "kind": _string(event.get("kind") or action),
            "category": _string(event.get("category")),
            "cmd": self._cmd(event),
            "exe": self._exe(event),
            "path": self._file_path(event),
            "operation": self._operation(event),
            "env": env or _string(ext.get("host.env")),
            "uid": _string(self._uid(event)),
            "parent": _string(event.get("parent_cmd") or ext.get("host.parent_cmd")),
        }

    def _matches(self, match_spec: dict[str, Any], event: dict[str, Any]) -> bool:
        self._ext_memo = None
        return self._matches_compiled(self._compile_spec(match_spec), self._view(event))

    def _matches_compiled(self, compiled: tuple, view: dict[str, Any]) -> bool:
        cmd, exe = view["cmd"], view["exe"]
        for key, values in compiled:
            if key == "source":
                source = view["source"]
                # Audit K4: a kernel-reported execve is a process observation,
                # so process rules see every start, not a 10 s /proc snapshot.
                if source not in values and not (source == "audit" and view["kind"] == "execve" and "sys_proc" in values):
                    return False
            elif key in ("action", "kind", "category"):
                if view[key] not in values:
                    return False
            elif key == "operation":
                if view["operation"] not in values:
                    return False
            elif key == "uid":
                if view["uid"] not in values:
                    return False
            elif key == "uid_not":
                if view["uid"] in values:
                    return False
            elif key == "cmd_contains":
                if not any(_term_in_command(cmd, v, exe) for v in values):
                    return False
            elif key == "cmd_arg_contains":
                # An address, host or path anywhere in the arguments.
                if not any(_arg_in_command(cmd, v, exe) for v in values):
                    return False
            elif key == "cmd_not_contains":
                if any(_term_in_command(cmd, v, exe) for v in values):
                    return False
            elif key == "cmd_regex_cs":
                if _is_text_tool(cmd):
                    return False
                if not any(self._search(v, text, 0) for v in values for text in self._stages(view)):
                    return False
            elif key == "cmd_regex":
                if _is_text_tool(cmd):
                    return False
                if not any(self._search(v, text, re.IGNORECASE) for v in values for text in self._stages(view)):
                    return False
            elif key == "cmd_not_regex":
                if any(self._search(v, cmd, re.IGNORECASE) for v in values):
                    return False
            elif key == "exe_contains":
                if not any(v in exe for v in values):
                    return False
            elif key == "exe_regex":
                if not any(self._search(v, exe, re.IGNORECASE) for v in values):
                    return False
            elif key == "file_path":
                path = view["path"]
                if not path or not any(self._path_match(path, v) for v in values):
                    return False
            elif key == "file_path_not":
                path = view["path"]
                if path and any(self._path_match(path, v) for v in values):
                    return False
            elif key == "env_contains":
                env = view["env"]
                if not any(re.search(r'(?:^|[\s\x00])' + re.escape(v) + r'=', env) for v in values):
                    return False
            elif key == "parent_contains":
                if not any(_term_in_command(view["parent"], v) for v in values):
                    return False
            else:
                # Bu nokta validation sonrası ulaşılamaz. Güvenli tarafta kal.
                return False
        return True

    @staticmethod
    def _stages(view: dict[str, Any]) -> list[str]:
        stages = view.get("_stages")
        if stages is None:
            stages = view["_stages"] = list(_stage_texts(view["cmd"], view["exe"]))
        return stages

    def _search(self, pattern: str, text: str, flags: int) -> bool:
        deadline = self._regex_deadline
        if deadline is not None and time.thread_time() > deadline:
            raise _RegexBudgetExceeded(pattern)
        return re.search(pattern, _regex_text(text), flags=flags) is not None

    # 2.2.54 (field 2026-11-19): on Fedora Atomic /home, /root and /usr/local are links
    # to /var/home, /var/roothome and /var/usrlocal, and audit reports the real path.
    # Rules written for /home/*/.ssh/authorized_keys never matched /var/home/u/.ssh/...
    # A path is also tried under its conventional name. Atomic'te gerçek yollar /var
    # altındadır; kurallar her iki adla da eşleşir.
    PATH_ALIASES = (("/var/home/", "/home/"), ("/var/roothome/", "/root/"), ("/var/usrlocal/", "/usr/local/"))

    @classmethod
    def _path_forms(cls, path: str) -> tuple:
        forms = [path]
        for real, usual in cls.PATH_ALIASES:
            if path.startswith(real):
                forms.append(usual + path[len(real):])
            elif path == real.rstrip("/"):
                forms.append(usual.rstrip("/"))
        return tuple(forms)

    @classmethod
    def _path_match(cls, path: str, pattern: str) -> bool:
        # ~ sadece current user'a göre expand edilmez; audit path için "*/.ssh/..."
        # şekline çevrilir ki root servisin HOME'u sonucu etkilemesin.
        if pattern.startswith("~/"):
            pattern = "*/" + pattern[2:]
        return any(fnmatch.fnmatchcase(form, pattern) for form in cls._path_forms(path))

    # ------------------------------------------------------------------
    # Skor
    # ------------------------------------------------------------------
    def _score(self, rule: dict[str, Any], event: dict[str, Any]) -> int:
        # base_match kuralin ana kanitidir. Threshold tanimli eski kurallarda
        # base_score verilmemisse threshold kadar temel puan kabul edilir;
        # scoring girdileri baglamsal bonus/ceza olarak calisir.
        default_base = rule.get('threshold', 0) if rule.get('threshold') is not None else 0
        score = int(rule.get('base_score', default_base) or 0)
        for item in rule.get("scoring", []) or []:
            if not isinstance(item, dict):
                continue
            if self._eval_condition(_string(item.get("if")), event):
                try:
                    score += int(item.get("add", 0))
                except (TypeError, ValueError):
                    continue
        return score

    _OWN_UNIT = re.compile(r"\bsystemctl\s+(?:stop|disable|mask|restart|try-restart|start|enable|reload)\s+(?:--\S+\s+)*(?:satsuma[\w@.-]*\s*)+$")
    # Groups and rules a package scriptlet trips while it manages satsuma* units.
    _PACKAGE_GROUPS = frozenset({"security_disable", "systemd_persist"})
    _PACKAGE_RULES = frozenset({"SATSUMA-IMP-004"})
    # Exact argv of Satsuma's own periodic read-only checks (network_identity,
    # remote_containment, worker_systemd_dbus).
    OWN_READONLY_PROBES = frozenset({
        "/usr/sbin/ip -j address show dev lo",
        "/usr/bin/systemctl list-units --all --plain --no-legend --no-pager",
        "systemctl list-units --type=service --no-pager --no-legend --plain",
    })

    def _own_package_transaction(self, rule: dict[str, Any], event: dict[str, Any]) -> bool:
        """Satsuma's own RPM scriptlets manage Satsuma units during an upgrade (field log 2026-11-04).

        Only a command that touches nothing but satsuma* units, while rpm/dnf is
        running or within 15 minutes of satsuma-core's rpm install time (events
        can be evaluated after dnf has finished), is skipped for the
        security-disable, systemd-persistence and
        service-stop rules; stopping auditd, suricata or a firewall still
        matches. Satsuma'nın kendi RPM betikleri güncellemede yalnız satsuma*
        birimlerini durdurur/başlatır; bu atlanır, başka güvenlik araçlarını
        durdurmak yine yakalanır.
        """
        if rule.get("dedup_group") not in self._PACKAGE_GROUPS and rule.get("_id") not in self._PACKAGE_RULES:
            return False
        if not self._OWN_UNIT.search(self._cmd(event).strip()):
            return False
        try:
            from .kernel_guard import package_manager_running
            if package_manager_running():
                return True
        except Exception:
            pass
        # Field 2026-11-04: events were evaluated long after dnf had finished, so
        # "rpm is running now" missed Satsuma's own upgrade. The rpm database's
        # install time of satsuma-core within 15 minutes of the event counts too.
        stamp = self._event_epoch(event)
        installed = self._satsuma_install_time()
        return stamp is not None and installed is not None and abs(stamp - installed) <= 900

    @staticmethod
    def _event_epoch(event: dict[str, Any]) -> float | None:
        value = event.get("timestamp")
        try:
            if isinstance(value, (int, float)) and not isinstance(value, bool):
                return float(value)
            from datetime import datetime
            return datetime.fromisoformat(str(value).replace("Z", "+00:00")).timestamp()
        except (TypeError, ValueError, OverflowError):
            return None

    _install_cache: tuple[float, float | None] = (0.0, None)

    @classmethod
    def _satsuma_install_time(cls) -> float | None:
        """satsuma-core's install time from the rpm database, cached for a minute."""
        checked, value = cls._install_cache
        if time.monotonic() - checked < 60:
            return value
        try:
            import subprocess
            out = subprocess.run(["/usr/bin/rpm", "-q", "--qf", "%{INSTALLTIME}", "satsuma-core"],
                                 capture_output=True, text=True, timeout=10)
            value = float(out.stdout.strip()) if out.returncode == 0 and out.stdout.strip().isdigit() else None
        except (OSError, ValueError, subprocess.SubprocessError):
            value = None
        cls._install_cache = (time.monotonic(), value)
        return value

    def _own_readonly_probe(self, rule: dict[str, Any], event: dict[str, Any]) -> bool:
        """A log-only rule ignores Satsuma's own fixed read-only probe run as root.

        The field export (2026-11-04) showed 5,200 discovery findings a day from
        these exact commands. Rules with any other action still see them.
        Yalnızca kayıt yapan kural, Satsuma'nın root olarak çalıştırdığı sabit
        salt okunur yoklamayı (birebir komut) bulgu saymaz; başka eylemli
        kurallar bu komutları yine görür.
        """
        if self._normalize_actions(rule.get("actions", []) or []) != ["log_only"]:
            return False
        if " ".join(self._cmd(event).split()) not in self.OWN_READONLY_PROBES:
            return False
        return str(self._uid(event)) == "0"

    @staticmethod
    def supported_condition(cond: str) -> bool:
        """True when _eval_condition understands ``cond``; anything else is always false there."""
        cond = _string(cond)
        return (any(text in cond for text in ("tty NOT in", "time NOT in", "parent NOT in"))
                or bool(re.fullmatch(r"uid\s*!=\s*(-?\d+)", cond))
                or bool(re.fullmatch(r"ppid\s*==\s*(-?\d+)", cond))
                or bool(re.fullmatch(r"parent_cmd\s*==\s*(.+)", cond)))

    def _eval_condition(self, cond: str, event: dict[str, Any]) -> bool:
        ext = self._extensions(event)
        tty = _string(event.get("tty") or ext.get("host.tty"))
        parent = _string(event.get("parent_cmd") or ext.get("host.parent_cmd"))
        uid = self._uid(event)
        ppid = event.get("ppid", ext.get("host.ppid"))

        try:
            if cond == "tty NOT in known_ttys" or "tty NOT in" in cond:
                return tty not in {"/dev/pts/0", "/dev/pts/1", "/dev/pts/2"}
            if cond == "time NOT in work_hours" or "time NOT in" in cond:
                hour = time.localtime().tm_hour
                return not (8 <= hour <= 22)
            if cond == "parent NOT in normal_shells" or "parent NOT in" in cond:
                return parent.rsplit("/", 1)[-1] not in {"bash", "zsh", "sh", "fish", "xfce4-terminal"}
            m = re.fullmatch(r"uid\s*!=\s*(-?\d+)", cond)
            if m:
                return int(uid) != int(m.group(1))
            m = re.fullmatch(r"ppid\s*==\s*(-?\d+)", cond)
            if m:
                return int(ppid) == int(m.group(1))
            m = re.fullmatch(r"parent_cmd\s*==\s*(.+)", cond)
            if m:
                return parent.rsplit("/", 1)[-1] == m.group(1).strip().strip("'\"")
        except (TypeError, ValueError):
            return False
        return False

    # ------------------------------------------------------------------
    def stats(self) -> dict[str, Any]:
        categories: dict[str, int] = {}
        classifications: dict[str, int] = {}
        actions: dict[str, int] = {}
        destructive_actions: dict[str, int] = {}
        for rule in self.rules:
            cat = rule.get("category", "unknown")
            categories[cat] = categories.get(cat, 0) + 1
            cls = rule.get("classification", "indicator")
            classifications[cls] = classifications.get(cls, 0) + 1
            for action in self._normalize_actions(rule.get("actions", [])):
                actions[action] = actions.get(action, 0) + 1
                if action in _DESTRUCTIVE_RULE_ACTIONS:
                    destructive_actions[action] = destructive_actions.get(action, 0) + 1
        return {
            "total_rules": len(self.rules),
            "managed_packages": {r["_id"]: r["_ai_package_digest"] for r in self.rules if r.get("_ai_package_digest")},
            "categories": categories,
            "classifications": classifications,
            "actions": dict(sorted(actions.items())),
            "destructive_actions": dict(sorted(destructive_actions.items())),
            "invalid_files": len(self.load_errors),
            "load_errors": list(self.load_errors),
            "rules_dir": str(self.rules_dir),
            "regex_budget_exceeded": self.regex_budget_exceeded,
        }

    @staticmethod
    def classification_at_least(value: str, minimum: str) -> bool:
        return _CLASSIFICATION_RANK.get(value, -1) >= _CLASSIFICATION_RANK.get(minimum, 999)
