# SatsumaSecurity 2.2.16

Tek ana dal: `main`, 2026-11-03 kaynak arşivini temel alır. Önceki bütün dallar `eski/` altında aynen durur.

## Değişenler

- **Duraklatma kaldırıldı.** Panel düğmesi, operatör servisindeki `pause` işlemi, komut satırı `pause/resume` ve çekirdek bekçisinin `PAUSE` dosyası yok. Eski sürümden kalan değer okunmaz ve temizlenir. Acil çıkış yolu `release/kaldir.sh` kaldırma betiğidir.
- **Kuyruk dışında kabul edilen portlar (DIRECT).** TCP 5938 (TeamViewer), 6568 (AnyDesk), UDP 67 (DHCP), 123 (NTP), 5938. Yalnızca dışarıya; içeriye yalnızca yanıt. Suricata kuyruğu dursa da uzaktan destek, saat ve IP adresi korunur. DNS ve HTTPS denetlenmeye devam eder.
- **Geçici dizin taraması.** `/tmp` benzeri dizinler on dakikada bir RAM clamd üzerinden taranır (`satsuma-temporary-scan.timer`).
- **Tarayıcı alt süreç koruması.** Firefox/Chromium altından "indir ve kabuğa aktar" zinciri `SATSUMA-BROWSER-001` kuralıyla bildirilir (231 kural).
- **Kaldırma betiği geri geldi.** `release/kaldir.sh` kaynak ağacında.
- **Test paketi yeşil.** Eski testler güncel kodla hizalandı; ürün davranışı testlerle korunuyor.

## Bilinçli olarak taşınmayanlar

- `remote_policy` (TeamViewer'ı öldürüyordu), `memory_av` (RAM v2 karşılıyor), `admin_totp` (önce panelde kayıt akışı gerekir).

## Doğrulanmadı

- Hedef Fedora 44 makinesinde kurulum, açılış ve kaldırma.
- Paket imzası.
