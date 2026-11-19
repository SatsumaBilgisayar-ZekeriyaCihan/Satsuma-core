"""Policy-gated termination of the exact process in fresh detection evidence.

The stop decision travels to ResponseWorker.terminate_process as a context
(rule, finding, classification, whether a memory code difference is the
basis), so the signal step knows what it must recheck.

Taze tespit kanıtındaki işlemin kendisinin, politika kapısından geçerek
durdurulması. Durdurma kararı bir bağlam olarak (kural, bulgu, sınıflama,
dayanağın bellek kod farkı olup olmadığı) ResponseWorker.terminate_process'e
taşınır; sinyal adımı neyi yeniden denetleyeceğini bilir.
"""
from datetime import datetime
import math
import time

from .process_identity import evidence_pid
from .process_identity import evidence_exe, evidence_starttime, verify_process_identity
from .response_policy import authorize_destructive


def event_time_evidence(event, now):
    value=event.get('timestamp')
    try:
        if isinstance(value,bool):raise ValueError('boolean timestamp')
        if isinstance(value,(int,float)):
            observed=float(value)
        else:
            parsed=datetime.fromisoformat(str(value).replace('Z','+00:00'))
            if parsed.tzinfo is None:raise ValueError('timezone missing')
            observed=parsed.timestamp()
        if not math.isfinite(observed):raise ValueError('nonfinite timestamp')
        age=now-observed
        return {'event_timestamp':value,'event_epoch':observed,'evaluated_at':now,
                'event_age_seconds':round(age,3),
                'state':'FUTURE' if age < -60 else 'EXPIRED' if age > 300 else 'FRESH'}
    except (TypeError,ValueError,OverflowError):
        return {'event_timestamp':str(value)[:120],'evaluated_at':now,'state':'INVALID'}


def corroborate(findings):
    """Confirm independent high-severity detections of the same process.

    PID alone, duplicate rules, team labels and benign activity indicators do
    not count as corroboration. Identity must originate in both sensor events.
    """
    groups = {}
    for finding in findings:
        event = finding.get('event') or {}
        if not isinstance(event, dict):
            continue
        if finding.get('classification') not in ('suspicious', 'likely'):
            continue
        if finding.get('severity') not in ('high', 'critical'):
            continue
        source = event.get('source')
        if isinstance(source, dict):
            source = source.get('type') or source.get('collector_id')
        if source not in ('sys_proc', 'audit', 'memory'):
            continue
        pid, start, exe = evidence_pid(event), evidence_starttime(event), evidence_exe(event)
        try:
            stamp = event['timestamp']
            observed = (float(stamp) if isinstance(stamp, (int, float)) else
                        datetime.fromisoformat(str(stamp).replace('Z', '+00:00')).timestamp())
            if not math.isfinite(observed) or not 0 <= time.time() - observed <= 60:
                continue
        except (KeyError, TypeError, ValueError, OverflowError):
            continue
        if not pid or not start or start[1] != 'jiffies' or not exe:
            continue
        groups.setdefault((pid, str(start[0]), exe), []).append((source, finding))
    confirmed = []
    for identity, rows in groups.items():
        sources = sorted({source for source, _ in rows})
        rules = sorted({str(f.get('rule_id')) for _, f in rows if f.get('rule_id')})
        if len(sources) < 2 or len(rules) < 2:
            continue
        first = rows[0][1]
        confirmed.append({**first, 'classification': 'confirmed',
                          'finding_id': 'process-corroboration:' + '|'.join(map(str, identity)),
                          'independent_sources': sources, 'matched_rules': rules,
                          'matched_rule_hashes': {f['rule_id']: f.get('rule_content_hash') for _, f in rows},
                          'corroborating_findings': [{'rule_id': f.get('rule_id'), 'event': f['event']} for _, f in rows],
                          'confirmation_basis': 'independent_high_severity_process_detections'})
    return confirmed


def _persist_decision(store, finding, record):
    """Persist every response exit and its follow-up link.

    Her müdahale çıkışını ve bulgu takip bağını kaydeder.
    """
    from contextlib import nullcontext
    from .process_followup import decision
    record.setdefault('event_time',event_time_evidence(finding.get('event') or {},record['timestamp']))
    with store.atomic() if hasattr(store,'atomic') else nullcontext():
        store.add('actions',record)
        decision(store,finding,record,commit=False)
        latest=store.get('rule_intervention_latest',{}) or {}
        latest[str(finding.get('rule_id') or '')]={k:record.get(k) for k in
            ('timestamp','finding_id','rule_id','pid','status','signal_sent','exit_verified','reasons','event_time','exemption')}
        store.set('rule_intervention_latest',latest)
    return record


STOP_MEMORY = 60.0      # seconds a stop sent for (pid, starttime, exe) is remembered, per store


def respond(store, config, finding, response, *, approved_request=None):
    # Use one event's identity, never assemble PID/exe/starttime from unrelated
    # correlated events or capture a replacement identity after detection.
    event = finding.get('event')
    event = event if isinstance(event, dict) else {}
    extensions = event.get('extensions') or {}
    pid = evidence_pid(event)
    if pid is None and isinstance(extensions, dict):
        try:
            pid = int(extensions.get('host.pid'))
        except (TypeError, ValueError):
            pass
    record = {'timestamp': time.time(), 'action': 'process.terminate',
              'finding_id': finding.get('finding_id'), 'rule_id': finding.get('rule_id'),
              'pid': pid, 'status': 'policy_denied', 'signal_sent': False}
    record['target'] = 'PID ' + str(pid) if pid is not None else None
    context = {'automated': True, 'pid': pid}
    metadata = event.get('metadata')
    metadata = metadata if isinstance(metadata, dict) else {}
    memory_extensions = metadata.get('extensions')
    memory_extensions = memory_extensions if isinstance(memory_extensions, dict) else {}
    ram_evidence = memory_extensions.get('host.ram_v2')
    # 2.2.38: RAM-107 (heuristic/PUA or unconfirmed signature) stops too, after the
    # same chunk is read and scanned again. RAM-107 de aynı parça yeniden taranınca durdurur.
    ram_actions = ('ram_signature_match_v2', 'ram_review_v2')
    ram_claim = (finding.get('rule_id') in ('SATSUMA-RAM-106', 'SATSUMA-RAM-107')
                 or event.get('action') in ram_actions)
    if ram_claim:
        record.update(status='policy_denied', reasons=['ram_clamav_retired'])
        return _persist_decision(store, finding, record)
    validation = memory_extensions.get('host.memory_validation')
    validation = validation if isinstance(validation, dict) else {}
    # A verified byte difference is an enforceable code-integrity violation.
    # Reproduce it now; never trust a historical detector boolean as authority.
    if (finding.get('rule_id') == 'SATSUMA-RAM-005' and event.get('source') == 'memory'
            and validation.get('status') == 'CODE_MISMATCH'
            and verify_process_identity(pid, evidence=event).get('ok')):
        from .memory_validation import validate_executable
        current = validate_executable('/proc/' + str(pid))
        record['memory_revalidation'] = current
        if current['status'] == 'CODE_MISMATCH':
            finding = {**finding, 'classification': 'confirmed',
                       'confirmation_basis': 'live_executable_code_integrity_violation'}
            context['memory_integrity_verified'] = True
    if config.get('user_enforcement') is True and pid is not None and evidence_starttime(event) is None:
        # Audit command events carry pid and exe but no start time. Within a
        # few seconds of the event, the live start time of the process that
        # still runs the same executable stands in for it.
        try:
            stamp = event['timestamp']
            age = time.time() - (float(stamp) if isinstance(stamp, (int, float)) else
                                 datetime.fromisoformat(str(stamp).replace('Z', '+00:00')).timestamp())
        except (KeyError, TypeError, ValueError, OverflowError):
            age = None
        from .process_identity import read_proc_starttime, read_proc_exe, canonical_exe_path
        claimed = evidence_exe(event)
        if age is not None and 0 <= age <= 10 and claimed:
            live_exe = read_proc_exe(pid)
            start = read_proc_starttime(pid)
            if start is not None and live_exe and canonical_exe_path(live_exe) == claimed:
                event = {**event, 'starttime': start}
                finding = {**finding, 'event': event}
    if config.get('user_enforcement') is True:
        from . import enforcement
        exemption = enforcement.exempt(pid, evidence_exe(event), finding) if pid is not None else None
        if exemption:
            record.update(status='exempt', exemption=exemption)
            if exemption == 'init_cannot_be_stopped':
                # PID 1 matched a rule: nothing can kill it, so it is shown as a
                # critical alarm, never only recorded (2.2.38).
                # PID 1 kurala takıldı: öldürülemez; yalnızca kaydedilmez, kritik alarm olur.
                store.add('findings', {'source': 'satsuma_enforcement', 'classification': 'confirmed',
                    'severity': 'critical', 'rule_id': finding.get('rule_id'), 'pid': pid,
                    'executable': evidence_exe(event), 'automatic_action': 'init_cannot_be_stopped',
                    'signal_sent': False,
                    'title': 'PID 1 (systemd) bir saldırı kuralına takıldı; çekirdek durdurulmasına izin vermez. '
                             'Bilgisayarı ağdan ayırın ve inceleyin.'})
            return _persist_decision(store,finding,record)
        # 2.2.38: RAM-001 on a program installed in a root-only place (JIT) is
        # recorded, not stopped. RAM-001 kurulu güvenilir programda (JIT) kaydedilir.
        exe_for_rwx = evidence_exe(event) or memory_extensions.get('host.exe')
        kept = enforcement.rwx_kept(finding, exe_for_rwx,
                                    pid=event.get('pid') or memory_extensions.get('host.pid'))
        if kept:
            record.update(status='report_only', evaluation_only=True, kept=kept,
                          reasons=['trusted_program_jit_memory'],
                          decision_explanation='Güvenilir yoldaki program JIT için yazılabilir+çalıştırılabilir bellek kurar; kaydedildi, durdurulmadı.')
            return _persist_decision(store, finding, record)
        # A memory difference must reproduce now; a stale or forged one never
        # stops a process, with or without the blocking policy.
        memory_claim = finding.get('rule_id') == 'SATSUMA-RAM-005'
        if enforcement.eligible(finding, config.get('sudo_autoblock_enabled') is True) and (not memory_claim or context.get('memory_integrity_verified')):
            context['user_enforcement'] = True
    auth = authorize_destructive('process_kill', finding, config, context=context, evidence_store=store)
    reasons = list(auth.reasons)
    if config.get('auto_action_process_enabled') is not True:
        reasons.append('automatic_process_response_disabled')
    if pid is None:
        reasons.append('missing_event_process_identity')
    timing=event_time_evidence(event, record['timestamp'])
    record['event_time']=timing
    if timing['state'] in ('FUTURE','EXPIRED'):
        reasons.append('historical_or_future_event')
    elif timing['state']=='INVALID':
        reasons.append('missing_or_invalid_event_time')
    if reasons:
        record['reasons'] = reasons
        if 'activity_indicator_reports_only' in reasons:
            # Ordinary activity (sudo, systemctl, git…) is reported, not refused.
            record['status'] = 'report_only'
            record['evaluation_only'] = True
            record['decision_explanation'] = 'Sıradan etkinlik göstergesi; süreç sonlandırma uygulanmadı. Olay zamanı ayrıca kaydedildi.'
    else:
        # Interactive lab mode is opt-in and fail-closed. Never enqueue an
        # already denied action or bypass authorization for an approved one.
        if store.get('interactive_process_test_mode', False) is True and approved_request is None:
            from .process_approval import enqueue
            request = enqueue(store, finding)
            record.update(status=request['status'], signal_sent=False,
                          request_id=request.get('request_id'),
                          reasons=[request.get('reason')] if request.get('reason') else [])
            return _persist_decision(store, finding, record)
        # 2.2.57: one process, one stop. Several findings from the same process (three
        # writes, three findings) asked privd three times and wrote each answer.
        # Aynı süreç için tek durdurma kararı.
        key = (pid, evidence_starttime(event), evidence_exe(event))
        now = time.monotonic()
        stopped = getattr(store, '_satsuma_stopped', None)
        if stopped is None:
            stopped = {}
            try:
                setattr(store, '_satsuma_stopped', stopped)
            except (AttributeError, TypeError):
                pass
        for old_key in [k for k, at in stopped.items() if now - at > STOP_MEMORY]:
            stopped.pop(old_key, None)
        if key in stopped:
            record.update(status='already_decided', signal_sent=False,
                          decision_explanation='Bu süreç için durdurma kararı az önce verildi; yinelenmedi.')
            return record
        stopped[key] = now
        # Persist the authorization before sending any signal. ResponseWorker
        # retains integrity/pause/replay and critical-process/identity guards.
        store.add('actions', {**record, 'status': 'process_termination_authorized'})
        from copy import deepcopy
        revalidation = record.get('memory_revalidation', validation)
        termination_context = {
            'rule_id': finding.get('rule_id'), 'finding_id': finding.get('finding_id'),
            'finding': deepcopy(finding),
            'classification': finding.get('classification'),
            'ram_v2_required': bool(context.get('ram_v2_verified')),
            'ram_v2_evidence': ram_evidence if context.get('ram_v2_verified') else None,
            'memory_validation_required': bool(context.get('memory_integrity_verified')),
            'memory_validation': {k: v for k, v in (revalidation or {}).items() if k != 'regions'}
                                 if isinstance(revalidation, dict) else None}
        result = response.terminate_process(pid, 'verified attack: ' + str(
            finding.get('rule_id') or finding.get('type') or 'finding'), evidence=deepcopy(event),
            context=termination_context)
        record.update(status=result.get('status', 'failed'), result=result,
                      signal_sent=result.get('signal_sent', False),
                      exit_verified=result.get('exit_verified', False))
        if record['signal_sent'] is True:
            # Visible in the findings list, not only in the action log.
            stopped = record['status'] == 'terminated' and record['exit_verified'] is True
            store.add('findings', {'source': 'satsuma_enforcement', 'classification': 'indicator',
                'severity': 'high', 'rule_id': finding.get('rule_id'), 'pid': pid,
                'executable': evidence_exe(event),
                'automatic_action': 'process_terminated' if stopped else 'process_termination_unverified',
                'signal_sent': True, 'exit_verified': record['exit_verified'],
                'title': ('Satsuma bir programı durdurdu: ' if stopped else
                          'Sonlandırma sinyali gönderildi; süreç çıkışı doğrulanmadı: ')
                         +str(evidence_exe(event) or ('PID '+str(pid)))
                         +' (kural '+str(finding.get('rule_id') or finding.get('type'))+')',
                'timestamp': time.time()})
    return _persist_decision(store,finding,record)
