import time

from satsuma.dashboard_qt.panels.defense_sections import memory_status


def health(**extra):
    return {'updated_at': time.time(), 'inspected': 57, 'unreadable': 0, 'vanished': 71, **extra}


def test_old_metadata_scan_cannot_be_presented_as_ram_validation():
    text = memory_status(health(events_count=0))
    assert 'yalnızca üstveri' in text
    assert 'kod doğrulaması yok' in text
    assert 'temiz' not in text and 'bulgu yok' not in text


def test_inaccessible_memory_is_visible_despite_zero_metadata_denials():
    text = memory_status(health(validation_counts={'CODE_MATCH': 40, 'ACCESS_DENIED': 17},
                                incomplete_validations=17))
    assert 'kısmen' in text
    assert 'Bellek erişimi reddedilen: 17' in text


def test_mismatch_is_not_presented_as_successful_termination():
    text = memory_status(health(validation_counts={'CODE_MISMATCH': 1}))
    assert 'RAM kod farkı doğrulandı' in text
    assert 'müdahale sonucu aksiyon kayıtlarında' in text
    assert 'sonlandırıldı' not in text


def test_matched_sample_is_not_total_ram_cleanliness_claim():
    text = memory_status(health(validation_counts={'CODE_MATCH': 57}, incomplete_validations=0))
    assert 'executable kodunda fark bulunmadı' in text
    assert 'tüm RAM taraması değildir' in text


def test_stale_result_is_not_current_validation():
    text = memory_status(health(updated_at=time.time() - 300, validation_counts={'CODE_MATCH': 57}))
    assert 'Durum bildirimi gecikti' in text
