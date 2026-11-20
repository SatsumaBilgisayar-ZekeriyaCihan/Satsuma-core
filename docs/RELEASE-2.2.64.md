# Satsuma Core 2.2.64

Saha 2026-11-20: 2.2.63'te panel hiçbir şey okuyamıyordu ve Satsuma kaldırılamıyordu; sahip ancak açılış
menüsündeki önceki dağıtımla çıkabildi. Bu sürüm bunu bir daha olmayacak şekilde kapatır.

## Sahibin çıkış yolu asla kapanmaz
- En sıkı mod GAP-036 ve GAP-075'i artık durdurmaz: Satsuma'yı kaldırma/güncelleme, `rpm-ostree rollback`,
  `reset`, `override reset` yalnız kritik alarm verir. Kapı rpm-ostree'nin sorduğu polkit parolasıdır (2.2.58).
- **Acil kapatma anahtarı:** açılış menüsünde çekirdek satırının sonuna `satsuma.off` yazılırsa o açılışta hiçbir
  Satsuma birimi başlamaz (64 birimin hepsinde `ConditionKernelCommandLine=!satsuma.off`). Bir sonraki normal
  açılışta SATSUMA-OFF-001 bulgusu açılır.
- Satsuma kendi başına rpm-ostree işlemi başlatmaz. İlk açılış görüntüsüne taşıma yalnız sahip isterse:
  `sudo satsuma-admin initramfs esitle` (durum: `... initramfs durum`).
- Panel okuyucusu yine root (2.2.61 gibi); kendi kullanıcısıyla panel hiçbir şey okuyamıyordu.
- `/run/satsuma` açılışta tmpfiles ile oluşur ve operatör yeniden başlayınca silinmez.

## Sahibin kalıcı yasakları
- Posta gönderme programları (s-nail, mail, mailx, sendmail, mutt, msmtp) durdurulur: SATSUMA-GAP-076.
  rkhunter paketinin raporu s-nail ile gönderen günlük cron işi kapatıldı (Satsuma rkhunter'ı kendisi çalıştırır).
- İmajdan çıkarılan paketler (Firefox rpm, systemd-resolved, avahi, gssproxy, brltty, ipp-usb, python3-cups,
  ibus panel/python parçaları, python3-langtable, s-nail): programları çalışırsa durdurulur (SATSUMA-GAP-077,
  snap Firefox etkilenmez), servisleri maskelidir, paket geri gelirse saat başı kritik SATSUMA-BANNED-PKG-001.
- Firefox dil eklentileri (langpack) Firefox politikasıyla engelli.

## ClamAV
- clamdscan "Communication error" verince clamscan'a geçmeden önce clamd başlatılır, `--ping` ile beklenir ve
  tarama yeniden denenir; olmazsa `--stream` ile. clamscan (900 sn'de bitemiyordu) yalnız en son çare.

## Güncelleme
En sıkı mod bu sürümden itibaren Satsuma güncellemesini durdurmaz:
`sudo rpm-ostree uninstall satsuma-core --install ./satsuma-core-2.2.64-1.fc44.x86_64.rpm` ve yeniden başlatma.
