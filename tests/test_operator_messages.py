"""Operator answers as one plain sentence (2.2.45). Yönetim yanıtları tek sade cümle."""
from satsuma.operator_messages import describe, session_lost


def test_switches_say_what_changed():
    assert describe('enforcement', {'enabled': False}, {'ok': True}) == (
        'ok', 'Otomatik durdurma kapatıldı; zararlı programlar yalnızca bildirilecek.')
    assert describe('interactive_process_test_mode', {'enabled': True}, {'ok': True})[1].startswith('Bundan sonra')


def test_jobs_report_that_they_started():
    assert describe('repair', {}, {'ok': True, 'accepted': True, 'status': 'RUNNING'})[1].startswith('Bakım kiti çalışıyor')


def test_errors_are_plain_and_session_loss_is_recognised():
    assert describe('login', {}, {'ok': False, 'error': 'invalid_credentials'}) == ('error', 'Parola yanlış.')
    lost = 'Yönetici oturumu gerekli / süresi doldu'
    assert session_lost(lost) and describe('allow_ip', {}, {'ok': False, 'error': lost})[1].startswith('Oturumun süresi doldu')
    assert 'parola yeniden gerekli' in describe('unblock', {}, {'error': 'Korumayı azaltan işlem için yönetici parolasını yeniden girin (denetim K7)'})[1]


def test_application_decisions():
    assert describe('application_control', {'action': 'decision', 'decision': 'deny'}, {'ok': True})[1] == 'Uygulama engellendi.'
