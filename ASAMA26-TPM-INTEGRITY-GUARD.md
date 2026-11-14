# Satsuma-core 26. aşama — TPM Integrity Guard

## Kapsam

TPM kalıcı nesne (`handles-persistent`) ve NV indeks (`handles-nv-index`) envanteri `tpm2_getcap` aracının **yalnızca iki salt okunur GetCapability sorgusuyla** toplandı. Çıktı biçimi ve handle aralıkları sınırlandırıldı. Satsuma `host_provenance` API'sine ve mevcut Qt panelindeki özet ve kanıt tablosuna bağlandı.

## Karşılaştırma

Komut satırı: `python -m satsuma.tpm_integrity_guard [--baseline BASELINE.json --expected-baseline-sha256 HARICI_SHA256]`.

Baseline JSON şeması: `{"schema":1,"handles-persistent":["0x81000001"],"handles-nv-index":["0x01000001"]}`. İçeriği gerçek, güvenilir cihaz envanterine göre dışarıda oluşturulmalıdır. SHA-256 pin **bağımsız ve güvenilir bir kanaldan** temin edilmelidir. SHA-256 eşleşmesi dosyanın üreticisini veya TPM güven zincirini kanıtlamaz. Baseline dosyası değiştirilmez; karşılaştırma otomatik engelleme, silme, TPM yazma, firmware güncellemesi yapmaz. Her fark sadece inceleme bulgusudur.

## Güvenlik etkisi

* TPM: Sadece `tpm2_getcap handles-persistent` ve `handles-nv-index`; anahtar üretimi, NV yazımı, `clear`, `evictcontrol` yok. TPM araçlarının hatalı/ele geçirilmiş olması ayrıca risktir.
* Yetkiler: systemd birimi, SELinux politikası, root yetkisi ve cihaz ACL'leri değiştirilmedi. TPM'ye mevcut erişim izni yoksa işlem `UNAVAILABLE`/`PARTIAL_INVENTORY` olarak sonuçlanır.
* RAM, ağ, DNS, nftables, Suricata, OTX, ClamAV: Sadece yerel TPM sorgusu; yeni ağ veya tarama ayarı yok. Panel çağrısı, TPM'ye erişebilen mevcut servisten yapılır; servis başlatma yapılandırması değişmedi.
* Geri alma: `satsuma/tpm_integrity_guard.py` ile `dashboard_api.py` ve `dashboard_qt/panels/host_provenance.py` değişikliklerini geri almak yeterli; kalıcı cihaz değişikliği yok. Üretilen raporlar hassas TPM verilerinin tamamını değil sadece indeks/handle numaralarını içerir. Bu bile envanter bilgisi olabileceği için raporu gizli tutun.

## Test

`python -m pytest -q tests/test_tpm_integrity_guard.py tests/test_boot_chain_audit.py tests/test_tpm_quote_verifier.py tests/test_host_provenance.py tests/test_deployment_attestation.py tests/test_cve_trust_verification.py tests/test_host_risk_integration.py`

49 passed, 0 failed (kontrollü test ortamı). PyQt görsel testi yapılmadı. TPM donanımı ve Fedora üzerinde test yapılmadı. Tüm regresyon paketi ve yeni RPM test edilmedi.

## Sınırlamalar

Bu çalışma TPM kalıcı nesne **envanteridir**, nesne içeriğinin, EK/AK zincirinin, firmware bütünlüğünün, cihazın kimliğinin veya kötü amaçlı yerleştirmenin kanıtı değildir. Manipüle edilmiş işletim sistemi TPM çıktısını sahteleyebilir; bağımsız TPM quote ve güvenilir ölçüm analizi ayrıca gerekir. Aynı handle altındaki nesne değiştirilirse yalnız handle seti bunu yakalayamaz. Bir baseline pin'i kimlik doğrulamalı imzanın yerine geçmez.
