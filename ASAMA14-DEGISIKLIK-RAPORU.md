# Satsuma-core — Aşama 14: Sistem ClamAV soket yapılandırması

Tarih: 2026-11-14
Temel: satsuma-core-2.2.37-asama13-kaynak.tar.gz

## Kodda uygulandı

- `satsuma/temporary_scan.py`: dosya tarama istemcisi artık sistem clamd yapılandırmasında **tam olarak bir** `LocalSocket` gerektirir. `TCPSocket` ve `TCPAddr` reddedilmeye devam eder. Göreli veya `..` içeren soket yolları ve emekli RAM-ClamAV soket kökü reddedilir. Geçerli yerel Unix soketi üzerinden dosya tanımlayıcısı aktarımı korunur.
- `tests/test_system_clamd_config.py`: yapılandırma sınırları için 9 yeni regresyon testi eklendi.

## Test ortamında doğrulandı

`python -m pytest -q tests/test_system_clamd_config.py tests/test_temporary_scan_unittest.py tests/test_onaccess_listener.py tests/test_onaccess_events.py tests/test_retired_ram_catalog.py tests/test_retired_ram_clamav_policy.py tests/test_process_followup.py`

Sonuç: **45 geçti, 8 atlandı, 0 başarısız.** Tam regresyon çalıştırılmadı.

## Hâlâ açık olanlar

- Gerçek `clamonacc` journald mesaj biçimi doğrulanmadı; dinleyici otomatik başlatılmadı.
- Eski RAM motorunu doğrudan içe aktaran testler hâlâ kaynakta ve tam test toplamasını engelleyebilir. Bu testler gizlenmedi veya silinmedi.
- Linux ve Windows'taki diğer RAM-ClamAV tarihsel referansları ve bütün servis bağımlılıkları tam olarak temizlenmiş sayılmıyor.
- Fedora üzerinde fanotify/SELinux/on-access engelleme doğrulaması yapılmadı.
- Yeni RPM üretilmedi. DNS, nftables, Suricata, OTX, ptrace_scope, SELinux ve systemd başlangıç ayarları değiştirilmedi.

## Etki ve geri alma

Değişiklikler kaynak kodda yer alır; canlı sistemde bir işlem yapılmadı. Artık belirsiz/mükerrer ClamAV soketi yapılandırmaları tarama hatası olarak reddedilir; dosya taramasının başlamaması söz konusu olabilir. Bu davranış korumayı sessizce atlamak yerine hatayı açıkça bildirir.

Geri alma: 13. aşama arşivinden `satsuma/temporary_scan.py` dosyasını geri yüklemek ve yeni `tests/test_system_clamd_config.py` test dosyasını kaldırmak yeterlidir. 13. aşama arşivi bağımsız tutulmuştur.

**Durum:** Kodda uygulandı; seçili testlerde doğrulandı; Fedora hedef cihazında doğrulanmadı.
