#!/usr/bin/env python3
"""Satsuma Core - insan onayli yetki-yukseltme response worker.

Guvenlik sinirlari:
- "Bana ait degil" cevabi tum sudo/su oturumlarini taramaz veya oldurmez.
- Yalnizca ticket evidence icindeki PID hedeflenir.
- PID reuse riskine karsi mevcut cmdline evidence ile yeniden dogrulanir.
- Gercek kill, ResponseWorker policy/fail-safe kontrollerinden gecer.
"""
from __future__ import annotations

import json
import re
import subprocess
import sys
import time
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parents[1]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from satsuma.config import load
from satsuma.process_identity import (
    capture_process_identity,
    evidence_exe,
    evidence_pid,
    evidence_starttime,
    verify_process_identity,
)
from satsuma.response import ResponseWorker
from satsuma.response_policy import authorize_destructive, denied_action_record
from satsuma.store import Store


def get_process_info(pid):
    info = {'pid': pid}
    captured = capture_process_identity(pid)
    if captured is not None:
        info.update({
            'pid': captured['pid'],
            'cmd': captured.get('cmdline', ''),
            'comm': captured.get('comm', ''),
            'starttime': captured.get('starttime'),
            'exe': captured.get('exe'),
        })
    try:
        pid = int(pid)
        status = Path(f'/proc/{pid}/status').read_text(errors='replace')
        for line in status.splitlines():
            if line.startswith('Uid:'):
                info['uid'] = line.split()[1]
            elif line.startswith('PPid:'):
                info['ppid'] = line.split()[1]
        if 'cmd' not in info:
            cmdline = Path(f'/proc/{pid}/cmdline').read_bytes().replace(b'\0', b' ').decode('utf-8', 'replace')
            info['cmd'] = cmdline.strip()
        try:
            info['session'] = str(Path(f'/proc/{pid}/fd/0').readlink())
        except (FileNotFoundError, PermissionError, OSError):
            info['session'] = '?'
    except (FileNotFoundError, PermissionError, OSError, ValueError):
        if captured is None:
            info['missing'] = True
    return info


def extract_from_evidence(evidence_data):
    info = {}
    if not isinstance(evidence_data, dict):
        return info
    # Prefer the canonical nested identity fields carried by the producer ->
    # finding -> ticket/evidence path.  Missing fields remain missing so the
    # response layer can fail closed.
    pid = evidence_pid(evidence_data)
    if pid is not None:
        info['pid'] = pid
    start = evidence_starttime(evidence_data)
    if start is not None:
        if start[1] == 'seconds':
            info['start_seconds'] = start[0]
        else:
            info['starttime'] = start[0]
    exe = evidence_exe(evidence_data)
    if exe is not None:
        info['exe'] = exe
    for ev in evidence_data.get('events', []) or []:
        if not isinstance(ev, dict):
            continue
        for key in ('pid', 'cmd', 'uid', 'tty', 'session', 'starttime', 'start_seconds', 'starttime_jiffies', 'exe', 'executable'):
            if ev.get(key) is not None and key not in info:
                info[key] = ev[key]
    event = evidence_data.get('event')
    if isinstance(event, dict):
        for key in ('pid', 'cmd', 'uid', 'starttime', 'start_seconds', 'starttime_jiffies', 'exe', 'executable'):
            if event.get(key) is not None and key not in info:
                info[key] = event[key]
        extensions = event.get('metadata', {}).get('extensions') if isinstance(event.get('metadata'), dict) else {}
        if isinstance(extensions, dict):
            for key in ('host.pid', 'host.exe', 'host.starttime', 'host.start_seconds', 'host.cmd'):
                if extensions.get(key) is not None:
                    mapped = {'host.pid': 'pid', 'host.exe': 'exe', 'host.starttime': 'starttime',
                              'host.start_seconds': 'start_seconds', 'host.cmd': 'cmd'}[key]
                    info.setdefault(mapped, extensions[key])
    summary = str(evidence_data.get('summary', ''))
    m = re.search(r'UID\s+(\d+)', summary)
    if m and 'uid' not in info:
        info['uid'] = m.group(1)
    m = re.search(r'(?:->|→)\s*([^\s]+)', summary)
    if m and 'cmd' not in info:
        info['cmd'] = m.group(1)
    return info


def pid_still_matches(evidence_info, current_info):
    """PID reuse / exe mismatch halinde ilgisiz sureci oldurmemek icin gate."""
    if not isinstance(evidence_info, dict):
        return False
    pid = evidence_info.get('pid')
    if not pid:
        return False
    result = verify_process_identity(pid, evidence_info)
    return bool(result.get('ok'))


# Gelecek state ayrimi (bu hotfix'te DB migration yok):
#   operator_status:       open | in_progress | resolved
#   security_disposition:  undecided | legitimate | malicious
#   response_state:        pending | eligible | executed | suppressed
#
# in_progress operator workflow state'idir; security response eligibility'yi
# tek basina kaldirmaz. Yalniz resolved/closed/false_positive eligible degildir.
def eligible_privilege_tickets(store):
    """Response approval hattina uygun privilege escalation ticket'lari."""
    return store.db.execute(
        "SELECT ticket_id,title,description,first_seen,occurrence_count,evidence "
        "FROM tickets WHERE type='privilege_escalation_attempt' "
        "AND status IN ('open', 'in_progress') AND false_positive=0 "
        "ORDER BY first_seen DESC LIMIT 5"
    ).fetchall()


def ask_user(ticket, process_info):
    text = f"""YETKI YUKSELTME BULGUSU\n\nTicket: {ticket['ticket_id']}\nKomut: {process_info.get('cmd', '?')}\nUID: {process_info.get('uid', '?')}\nOturum: {process_info.get('session', '?')}\nPID: {process_info.get('pid', '?')}\nIlk tespit: {time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(ticket['first_seen']))}\nTekrar: {ticket['occurrence_count']}\n\nBu islem sizin tarafinizdan mi baslatildi?\n\nHayir derseniz yalnizca yukaridaki PID ve onun dogrulanmis cocuk surecleri, response policy izin veriyorsa sonlandirilir."""
    try:
        result = subprocess.run([
            'zenity', '--question', '--title=Satsuma Guvenlik Uyarisi', '--text=' + text,
            '--ok-label=Evet, bana ait', '--cancel-label=Hayir, bana ait degil',
            '--width=700', '--height=430'
        ], timeout=120)
        return result.returncode == 0
    except (FileNotFoundError, subprocess.TimeoutExpired):
        return None


def main():
    store = Store()
    try:
        config = load()
        responder = ResponseWorker(store, config)
        rows = eligible_privilege_tickets(store)
        if not rows:
            print('Onay bekleyen ticket yok.')
            return 0

        print(f'{len(rows)} ticket onay bekliyor...')
        for ticket_id, title, description, first_seen, occurrence_count, evidence in rows:
            try:
                evidence_data = json.loads(evidence) if evidence else {}
            except json.JSONDecodeError:
                evidence_data = {}
            evidence_info = extract_from_evidence(evidence_data)
            current_info = get_process_info(evidence_info.get('pid')) if evidence_info.get('pid') else {'missing': True}
            display_info = dict(evidence_info)
            for key, value in current_info.items():
                display_info.setdefault(key, value)

            answer = ask_user({
                'ticket_id': ticket_id,
                'title': title,
                'first_seen': first_seen,
                'occurrence_count': occurrence_count,
            }, display_info)
            if answer is None:
                print(f'  {ticket_id}: onay penceresi iptal/zaman asimi')
                continue

            if answer:
                store.db.execute(
                    "UPDATE tickets SET status='closed', false_positive=1, "
                    "resolution='Kullanici onayi: mesru islem', closed_at=?, updated_at=? WHERE ticket_id=?",
                    (time.time(), time.time(), ticket_id),
                )
                print(f'  {ticket_id}: KAPATILDI (mesru)')
            else:
                now = time.time()
                store.db.execute(
                    "UPDATE tickets SET severity='critical', ticket_level=1, priority='critical', "
                    "resolution='Kullanici dogrulamasi: bana ait degil', updated_at=? WHERE ticket_id=?",
                    (now, ticket_id),
                )
                result = {'status': 'review_required'}
                pid = evidence_info.get('pid')
                if pid and pid_still_matches(evidence_info, current_info):
                    operator_finding = {
                        'classification': 'confirmed',
                        'policy_allowed': True,
                        'multi_source_verified': True,
                        'source': ['operator_confirmation', 'ticket_evidence'],
                        'type': 'operator_confirmed_process_kill',
                        'rule_id': evidence_data.get('rule_id') or (evidence_data.get('finding') or {}).get('rule_id') or ('onay_worker:' + str(ticket_id)),
                        'event': evidence_info,
                    }
                    auth = authorize_destructive(
                        'process_kill', operator_finding, config,
                        context={'pid': pid, 'manual': True}, evidence_store=store,
                    )
                    if auth.allowed:
                        result = responder.kill_process_tree(
                            pid,
                            f'user-confirmed ticket {ticket_id}',
                            evidence=evidence_info, context={'rule_id':operator_finding['rule_id'],'finding':operator_finding},
                        )
                    else:
                        result = {'status': 'destructive_hard_brake'}
                        store.add('actions', {
                            **denied_action_record(auth, operator_finding),
                            'ticket_id': ticket_id,
                            'pid': pid,
                        })
                else:
                    store.add('actions', {
                        'timestamp': now,
                        'status': 'pid_revalidation_failed',
                        'ticket_id': ticket_id,
                        'pid': pid,
                        'reason': 'PID/cmdline evidence no longer matches; no process killed',
                    })
                print(f"  {ticket_id}: DOGRULANDI, response={result.get('status')}")
            store.db.commit()
        return 0
    finally:
        store.close()


if __name__ == '__main__':
    raise SystemExit(main())
