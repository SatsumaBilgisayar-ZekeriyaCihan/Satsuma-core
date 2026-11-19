"""What a rule does when it matches, and what the automatic stops really did (2.2.49).

Field question 2026-11-19: "why don't the rules stop?" The rules page said
"0 can stop the program directly · 251 only report" because it counted only
kill actions written in rule files. No rule file has one: stopping is decided
by the central policy (satsuma.enforcement) by classification and severity,
and for an activated DeepSeek rule by its approved proposal. Plain activity
indicators (screenshot, clipboard, ps, BPF tools…) only report on purpose.
A stop also needs the program to be running: a command that ends in a few
milliseconds is finished before the signal, which the actions record says.

Saha sorusu: "kurallar neden durdurmuyor?" Sayfa yalnızca kural dosyasındaki
kill eylemlerini sayıyordu; durdurmaya merkezi ilke karar verir. Sıradan
etkinlik göstergeleri bilerek yalnızca bildirir. Durdurmak için programın hâlâ
çalışıyor olması gerekir; milisaniyede biten komut sinyalden önce biter.
"""
from .presentation import SEVERITY_LABELS

CLASSIFICATION_LABELS = {'confirmed': 'Kesin', 'likely': 'Muhtemel', 'suspicious': 'Şüpheli', 'indicator': 'Gösterge'}

STOPPED = ('terminated', 'process_killed', 'process_tree_killed', 'killed')
ALREADY_GONE = ('live_process_not_found', 'starttime_mismatch', 'exe_mismatch', 'evidence_pid_mismatch')


def effect(rule, policy_enabled):
    """(stops, text) for one loaded rule."""
    from .enforcement import eligible
    rule_id = rule.get('_id') or rule.get('id')
    if rule.get('_ai_package_digest'):
        proposal = rule.get('_response_proposal') or {}
        if proposal.get('requested_action') == 'process_kill':
            return True, 'Programı durdurur (DeepSeek kuralı; veritabanı ve canlı teyitten sonra)'
        return False, 'Yalnızca bildirir (DeepSeek önerisi gözlem; durdurma önermedi)'
    if eligible({**rule, 'rule_id': rule_id}):
        if policy_enabled:
            return True, 'Programı durdurur'
        return False, 'Durdurabilir, ama otomatik durdurma kapalı: şu an yalnızca bildirir'
    return False, 'Yalnızca bildirir (sıradan programların da yaptığı bir iş; bilerek durdurulmaz)'


def outcome_kind(record):
    """stopped, gone, denied, failed or None for one actions record of the automatic stop path."""
    if not isinstance(record, dict):
        return None
    status = str(record.get('status') or '')
    if record.get('source') == 'unhide':
        return None
    if status in STOPPED and (record.get('exit_verified') is not False or status != 'terminated'):
        return 'stopped'
    if status in ('identity_verification_failed', 'identity_recheck_failed'):
        reason = str(record.get('reason') or (record.get('identity') or {}).get('reason') or '')
        return 'gone' if reason in ALREADY_GONE or status == 'identity_recheck_failed' else 'failed'
    if status == 'policy_denied':
        return 'denied'
    if status in ('termination_failed', 'termination_pending', 'failed'):
        return 'failed'
    return None


def stop_summary(records):
    counts = {'stopped': 0, 'gone': 0, 'denied': 0, 'failed': 0}
    for record in records:
        kind = outcome_kind(record)
        if kind:
            counts[kind] += 1
    return counts


def summary_text(total, stops, reports, policy_enabled, counts, ai_total=0):
    parts = [f'{total} etkin kural', f'{stops} tanesi eşleşince programı durdurur', f'{reports} tanesi yalnızca bildirir']
    text = ' · '.join(parts) + '. Otomatik durdurma: ' + ('açık.' if policy_enabled else 'KAPALI (Koruma → Ayarlar).')
    if ai_total:
        text += f' DeepSeek kuralı: {ai_total}.'
    if counts is not None:
        made = [f"{counts['stopped']} program durduruldu"]
        if counts['gone']:
            made.append(f"{counts['gone']} eşleşmede program sinyal gitmeden zaten kapanmıştı")
        if counts['denied']:
            made.append(f"{counts['denied']} durdurmaya güvenlik denetimi izin vermedi")
        if counts['failed']:
            made.append(f"{counts['failed']} durdurma başarısız")
        text += ' Son 24 saat: ' + ', '.join(made) + '.'
    return text


INTERVENTION_TEXT = {'terminated': 'Durduruldu', 'process_killed': 'Durduruldu', 'policy_denied': 'İzin verilmedi',
                     'identity_verification_failed': 'Program zaten kapanmıştı', 'UNKNOWN': '—'}


def row(rule, policy_enabled):
    stops, text = effect(rule, policy_enabled)
    return {'stops': stops, 'what_happens': text,
            'severity_label': SEVERITY_LABELS.get(str(rule.get('severity')), str(rule.get('severity') or '—')),
            'classification_label': CLASSIFICATION_LABELS.get(str(rule.get('classification')), str(rule.get('classification') or '—'))}
