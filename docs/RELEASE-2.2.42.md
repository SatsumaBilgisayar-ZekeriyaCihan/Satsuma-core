# Satsuma Core 2.2.42 (2026-11-18)

Durum: kaynak adayı; RPM GitHub Actions'ta Fedora 44 içinde derlenir. İmzasız.

## Fedora Atomic saha raporu (2.2.41)

2.2.41 Atomic'te: bütünlük, servisler, derin motor, panel okuyucusu ve olay
akışı sağlıklı; panel açılıyor; nftables'ta Suricata'yı atlayan kanal yok.

- satsuma-clamonacc her yeniden başlatmada düşüyordu, satsuma-onaccess-listener
  çalışmıyordu. Erişim anında tarama /home'u izliyordu; Atomic'te /home,
  var/home'a bağdır. Yapılandırma artık gerçek klasörü yazar; eski /home satırı
  kurulum adımında Satsuma'nın kendi bloğu içinde düzeltilir. Normal Fedora'da
  değişiklik yok. (Varsayım: cihaz günlüğüyle doğrulanmalı.)
- Panel "Arka plan bileşenleri": ram_v2 (kaldırılan RAM ClamAV motoru) "Veri
  alınamadı" görünüyordu; kaldırılan bileşen artık listelenmez.
- OPNsense toplayıcısı kayıt dosyası yokken "Sorunlu çalışıyor" görünüyordu;
  ağda OPNsense yoksa durum "Yapılandırılmamış"tır. Bağlı (symlink) kayıt
  dosyası yine hatadır.
