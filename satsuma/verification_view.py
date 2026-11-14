"""Plain text verification presentation; a completed job is not a trust verdict."""
def job_text(job):
    job = job if isinstance(job, dict) else {}
    state = job.get('status', 'IDLE')
    labels = {'RUNNING': 'Kontrol çalışıyor; sonuç bekleniyor',
              'COMPLETED': 'Kontrol işi tamamlandı; güven kararı aşağıda',
              'FAILED': 'Kontrol işi başarısız', 'IDLE': 'Bekleyen kontrol yok'}
    text = labels.get(state, str(state)) + ' · ' + str(job.get('operation') or '')[:80]
    if job.get('command_id'): text += ' · ' + str(job['command_id'])[:12]
    if job.get('returncode') is not None: text += ' · çıkış: ' + str(job['returncode'])
    if job.get('output'): text += '\n' + str(job['output'])[-10000:]
    return text


def decision_text(decision):
    decision = decision if isinstance(decision, dict) else {}
    if decision.get('allowed') is True and decision.get('status') == 'READY':
        return 'Müdahale: güven koşulları sağlandı'
    reasons = {'application_integrity_unverified': 'uygulama bütünlüğü doğrulanmadı',
               'boot_verdict_unverified_or_stale': 'açılış/çalışma koşulları doğrulanmadı veya sonuç eski'}
    return 'Müdahale kilitli: ' + ', '.join(reasons.get(str(r), str(r)[:120]) for r in (decision.get('reasons') or ['güncel doğrulama verisi yok']))
