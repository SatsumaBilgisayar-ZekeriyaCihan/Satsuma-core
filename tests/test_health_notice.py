from satsuma.self_health import notice_text


def test_failure_notice_names_actual_failed_controls_and_service():
    text=notice_text({'status':'DEGRADED','checks':{
        'services':{'ok':False,'states':{'satsuma-core.service':{'ActiveState':'failed'}}},
        'modem_reference':{'ok':False},'packet_drop':{'ok':True}}})
    assert 'satsuma-core.service' in text
    assert 'Modem/ağ geçidi onayı' in text
    assert 'Paket engelleme testi' not in text


def test_missing_or_unknown_report_never_hides_notice():
    assert notice_text({})
    assert notice_text({'status':'UNRECOGNIZED'})
    assert 'ayrıntısı raporda yok' in notice_text({'status':'DEGRADED'})
    assert notice_text({'status':'PASSED'})==''
