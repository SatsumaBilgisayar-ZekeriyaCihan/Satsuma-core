"""Shared memory decision: which rule a memory indicator matches and whether the process is stopped.

Linux (satsuma.worker_memory) and Windows (satsuma_win.memory) name what they
find with the same indicator words (anonymous_rwx, writable_dir_code_mapping,
deleted_executable, process_traced, executable_code_mismatch, ...). This module
reads the memory rules from the same rule files the Linux rule engine loads
and asks satsuma.enforcement whether that rule stops the process, so the two
platforms cannot drift apart: a rule or policy change applies to both.

Owner's decision 2026-11-11 for code in a folder anyone can write
(writable_dir_code_mapping): when every such file carries a valid publisher
signature, or the process is a Satsuma setup approved with the administrator
password, it is recorded and not stopped; unsigned code there is stopped.
Linux supplies neither fact, so nothing changes there.

Owner's decision 2026-11-11 for writable and executable memory without a
file (anonymous_rwx) on Windows, where every .NET program has such memory
(proven on GitHub's Windows server: PowerShell 7, the Actions runner, .NET
services): the process is stopped when a thread was started from fileless
memory, or when its program file is not where it should be (outside the
Windows folder and Program Files); otherwise the finding is recorded. Linux
passes no such facts and keeps stopping on the indicator alone. Only
reading memory and stopping a process are platform specific. Needs only the
standard library, PyYAML and satsuma.enforcement.

Ortak bellek kararı: bir bellek göstergesinin hangi kurala uyduğu ve sürecin
durdurulup durdurulmayacağı. Linux ve Windows bulduklarını aynı gösterge
adlarıyla adlandırır. Bu modül bellek kurallarını Linux kural motorunun
yüklediği aynı kural dosyalarından okur ve kuralın süreci durdurup
durdurmadığını satsuma.enforcement'a sorar; böylece iki platform ayrışamaz,
bir kural ya da politika değişikliği ikisine birden uygulanır. Sahibinin
kararı 2026-11-11: herkesin yazabildiği klasördeki kodun her dosyası geçerli
yayıncı imzası taşıyorsa ya da süreç yönetici parolasıyla onaylanmış bir
Satsuma kurulumuysa kaydedilir, durdurulmaz; imzasız kod durdurulur. Linux bu
bilgileri vermez, orada hiçbir şey değişmez. Sahibinin kararı 2026-11-11,
Windows'ta dosyasız yazılabilir+çalıştırılabilir bellek için (her .NET
programında bulunur; GitHub'ın Windows sunucusunda kanıtlandı): bir iş
parçacığı dosyasız bellekten başlatılmışsa ya da program dosyası olması
gereken yerde değilse (Windows klasörü ve Program Files dışında) süreç
durdurulur; değilse bulgu kaydedilir. Linux bu bilgileri vermez, yalnızca
göstergeyle durdurmayı sürdürür. Platforma özgü
olan yalnızca belleği okumak ve süreci durdurmaktır.
"""
import os
import sys
from pathlib import Path

import yaml

from . import enforcement

RULE_FILES = ('ram_defense.yaml', 'memory_injection.yaml', 'memory_integrity.yaml')


def rules_dir():
    """The rules folder: next to the package, or inside the frozen Windows exe."""
    bundled = getattr(sys, '_MEIPASS', None)
    if bundled and Path(bundled, 'rules').is_dir():
        return Path(bundled, 'rules')
    return Path(os.environ.get('SATSUMA_RULES_DIR') or Path(__file__).resolve().parents[1] / 'rules')


def load_rules(directory=None):
    """{indicator: rule} for every memory rule matched by source=memory and an action."""
    directory = Path(directory) if directory else rules_dir()
    rules = {}
    for name in RULE_FILES:
        for rule in yaml.safe_load((directory / name).read_text(encoding='utf-8')) or []:
            match = rule.get('base_match') or {}
            if match.get('source') == 'memory' and match.get('action'):
                rules[match['action']] = rule
    if not rules:
        raise ValueError('no memory rules found in ' + str(directory))
    return rules


KEPT_WHEN = ('signed_publisher', 'approved_satsuma_setup', 'no_thread_from_fileless_memory')


def decide(indicator, rules, signed=False, approved_setup=False, executing=None, expected_location=None):
    """The rule and verdict for one indicator; None when no rule names it.

    ``signed``: every file behind a writable-folder indicator has a valid publisher
    signature. ``approved_setup``: the process is a Satsuma setup approved with the
    administrator password. Either keeps writable_dir_code_mapping a record.
    ``executing`` (Windows only; None on Linux): a thread was started from fileless
    memory. ``expected_location``: the program file is where it should be. With
    ``executing`` given, anonymous_rwx stops only when executing or misplaced.
    """
    rule = rules.get(indicator)
    if rule is None:
        return None
    finding = {'rule_id': rule['id'], 'classification': rule.get('classification', ''),
               'severity': rule.get('severity', '')}
    result = {**finding, 'indicator': indicator, 'name': rule.get('name', ''),
              'stop': enforcement.eligible(finding)}
    if indicator == 'writable_dir_code_mapping' and result['stop'] and (approved_setup or signed):
        result['stop'] = False
        result['kept'] = 'approved_satsuma_setup' if approved_setup else 'signed_publisher'
    if indicator == 'anonymous_rwx' and result['stop'] and executing is not None:
        if executing:
            result['stop_reason'] = 'thread_started_from_fileless_memory'
        elif expected_location is False:
            result['stop_reason'] = 'program_not_in_expected_location'
        else:
            result['stop'] = False
            result['kept'] = 'no_thread_from_fileless_memory'
    return result
