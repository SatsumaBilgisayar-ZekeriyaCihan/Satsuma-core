"""System health cards say "no problem" once, or what broke and what to do.

Sistem sağlığı kartları ya bir kez "sorun yok" der ya da neyin bozulduğunu
ve ne yapılacağını söyler.
"""
from satsuma.dashboard_qt.panels.system_health import card_text

OK = {'ok': True}


def test_healthy_card_is_one_clear_line_without_advice():
    text, tone = card_text('traffic', {'status': 'PASSED'},
                           {'packet_drop': OK, 'production_incoming_rules': OK, 'nfqueue_consumers': OK, 'app_control': OK, 'competing_ips': OK})
    assert tone == 'ok' and text.startswith('✓ Trafik engelleme — sorun yok')
    assert 'paket engelleme testi' in text and 'Ne yapmalı' not in text and 'rapor kapsamı' not in text
    assert text.count('sorun yok') == 1


def test_problem_card_names_the_broken_part_and_the_next_step():
    text, tone = card_text('traffic', {'status': 'DEGRADED'},
                           {'packet_drop': OK, 'competing_ips': {'ok': False, 'error': 'İkinci bir Suricata servisi çalışıyor'}})
    assert tone == 'problem' and text.startswith('⚠ Trafik engelleme — sorun var')
    assert '• ikinci Suricata servisi: İkinci bir Suricata servisi çalışıyor' in text
    assert 'Ne anlama gelir:' in text and 'Ne yapmalı:' in text


def test_stopped_services_are_named():
    checks = {'services': {'ok': False, 'states': {'satsuma-teams.service': {'ActiveState': 'failed'},
                                                   'satsuma-core.service': {'ActiveState': 'active'}}}}
    text, tone = card_text('services', {'status': 'DEGRADED'}, checks)
    assert tone == 'problem' and 'satsuma-teams.service çalışmıyor' in text and 'satsuma-core.service' not in text


def test_no_report_says_why_instead_of_a_success():
    assert card_text('dns', {'status': 'NOT_RUN'}, {}) == ('DNS — bilgi yok\nİlk sağlık kontrolü henüz yapılmadı.', 'unknown')
    assert card_text('events', {'status': 'PASSED'}, {})[1] == 'unknown'


def test_disabled_dns_filter_is_not_a_failure_or_a_success():
    text, tone = card_text('dns', {'status': 'PASSED'}, {'dns_filter': {'ok': True, 'status': 'DISABLED'}, 'dns_policy': OK})
    assert tone == 'info' and 'filtre kapalı' in text


def test_header_warns_when_a_card_is_red(monkeypatch):
    from types import SimpleNamespace as NS
    from PyQt6.QtWidgets import QApplication
    from satsuma.dashboard_qt.panels.system_health import SystemHealthPanel
    app = QApplication.instance() or QApplication([])
    data = {'summary': {'overall': 'Sağlıklı'}, 'self_health': {'status': 'DEGRADED', 'checks': {
        'packet_drop': OK, 'competing_ips': {'ok': False, 'error': 'çakışma'}}}, 'otx': {}}
    panel = SystemHealthPanel(NS(call=lambda *a, **k: data))
    try:
        panel.refresh()
        assert panel.headline.text() == '⚠ Dikkat: Trafik engelleme alanında sorun var'
        assert panel.cards['traffic'].pill.text() == 'Sorun var' and not panel.cards['traffic'].step.isHidden()
        assert panel.cards['dns'].step.isHidden()
    finally:
        panel.close()
