"""When an activated DeepSeek rule may stop a process (2.2.25).

Two confirmations replace the old "AI rules never act" gate. Audit records are
never used: they can be deleted on this machine (field report 2026-11-04).
1. Satsuma database: a fresh (<= 60 s) trusted record of the same process
   (pid + kernel start time + executable) from Satsuma's own sensors.
2. Live confirmation: the process is re-read from /proc right before the
   decision; it must be the same process and, for process rules, the
   activated rule must still match its live command line. Memory rules need a
   fresh memory-scanner record of the same process instead.
Only rules the operator approved, sealed and activated, whose proposal is
process_kill, qualify. Every existing exemption and identity recheck still runs.

Etkin bir DeepSeek kuralının süreci ne zaman durdurabileceği. Audit kullanılmaz.
1. Satsuma veritabanı: Satsuma sensörlerinden aynı sürecin taze kaydı.
2. Canlı teyit: süreç /proc'tan yeniden okunur; aynı süreç olmalı ve süreç
   kurallarında kural canlı komut satırında da eşleşmeli. Bellek kurallarında
   bellek tarayıcısının aynı süreç için taze kaydı gerekir.
Yalnız operatörün onaylayıp mühürlediği ve etkinleştirdiği, process_kill öneren
kurallar uygundur; mevcut istisnalar ve kimlik denetimleri aynen çalışır.
"""
import json

IGNORED_FAMILIES = ('audit',)


def _activated_detection(store, finding):
    try:
        row = store.db.execute("SELECT package_json,content_hash FROM rule_adapter_queue WHERE rule_id=? AND status='activated'",
                               (str(finding.get('rule_id') or ''),)).fetchone()
    except Exception:
        return None
    if not row or row[1] != finding.get('ai_package_digest'):
        return None
    try:
        return json.loads(row[0])['detection']
    except (TypeError, ValueError, KeyError):
        return None


def eligible(finding, store):
    """(detection, reason): the activated detection when this AI finding may lead to process_kill."""
    from .ai_rule_package import is_ai_finding
    finding = finding or {}
    if not is_ai_finding(finding):
        return None, 'not_ai_finding'
    proposal = finding.get('response_proposal')
    if not isinstance(proposal, dict) or proposal.get('requested_action') != 'process_kill' or proposal.get('target_type') != 'process':
        return None, 'ai_proposal_is_not_process_kill'
    detection = _activated_detection(store, finding)
    if detection is None:
        return None, 'ai_rule_not_operator_activated'
    return detection, None


def _live(event, detection):
    from .process_identity import (evidence_pid, evidence_starttime, evidence_exe,
                                   read_proc_starttime, read_proc_exe, read_proc_cmdline)
    pid, start, exe = evidence_pid(event), evidence_starttime(event), evidence_exe(event)
    if not pid or pid <= 1 or not start or not exe:
        return 'live_target_identity_missing'
    if read_proc_starttime(pid) != int(start[0]) or read_proc_exe(pid) != exe:
        return 'live_process_changed_or_gone'
    match = detection.get('base_match') or {}
    if match.get('source') == 'sys_proc':
        from .smart_rules import SmartRuleEngine
        import tempfile
        with tempfile.TemporaryDirectory(prefix='satsuma-live-') as folder:
            engine = SmartRuleEngine(folder)
            if not engine._matches(match, {'source': 'sys_proc', 'cmd': read_proc_cmdline(pid), 'exe': exe, 'pid': pid}):
                return 'live_command_line_no_longer_matches_rule'
    return None


def _stream_event_elsewhere(finding):
    event = finding.get('event') if isinstance(finding.get('event'), dict) else {}
    if not str(event.get('id') or '').startswith('flow-'):
        return False
    from . import flow as flow_module
    return flow_module.ACTIVE is None


def confirm(finding, store, context=None):
    """{'passed', 'missing', 'database', 'live'} for an AI process_kill; never sends a signal."""
    detection, reason = eligible(finding, store)
    if detection is None:
        return {'passed': False, 'missing': [reason]}
    from .rule_response import evidence_report
    proposal = finding['response_proposal']
    memory_rule = (detection.get('base_match') or {}).get('source') == 'memory'
    requirement = {'rule_id': finding.get('rule_id'), 'minimum_sources': 1,
                   'required_sources': ['memory'] if memory_rule else [],
                   'ignore_families': list(IGNORED_FAMILIES), 'freshness_seconds': 60,
                   'detection_sha256': proposal.get('detection_sha256')}
    database = evidence_report(store, finding, 'process_kill', requirement, context or {})
    if not database['passed'] and not memory_rule and _stream_event_elsewhere(finding):
        # 2.2.59 (field 2026-11-19, "sudo su"): a stream event lives only in the rule engine's
        # memory (flow.ACTIVE, satsuma-teams); privd, a separate process, could never find it,
        # so no AI process rule could ever stop anything. Here the kernel itself confirms:
        # the live process (pid, start time, executable) is re-read below and the activated
        # rule must match its live command line, which a forged event cannot change.
        # Akış olayını privd göremez; teyidi çekirdek verir: canlı süreç yeniden okunur.
        database = {**database, 'passed': True, 'missing': [], 'scope': 'live_process_identity'}
    if not database['passed']:
        return {'passed': False, 'missing': ['satsuma_database_confirmation_missing', *database['missing']], 'database': database}
    live = _live(finding.get('event') or {}, detection)
    if live:
        return {'passed': False, 'missing': [live], 'database': database}
    return {'passed': True, 'missing': [], 'database': database, 'live': 'confirmed'}
