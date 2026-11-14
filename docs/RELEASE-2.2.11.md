# SatsumaSecurity 2.2.11 — virüs taraması, otomatik karantina, nftables

2.2.10'un yerini alır ve onun her şeyini içerir. Kurulu sürümün üstüne
`yama.sh` ile kurulur.

## Virüs taraması çalışıyor ve bulguları karantinaya alıyor

- ClamAV servisi (clamd) cevap vermiyorsa tarama artık hatayla bitmiyor;
  `clamscan` ile yapılıyor ve bu durum Tarayıcılar sayfasında yazıyor.
- ClamAV'ın kendi hata mesajı (ör. "virüs veritabanı yok") sayfada
  görünüyor.
- Taranan yerlere `/root`, `/tmp`, `/var/tmp`, `/dev/shm`, `/usr/bin` ve
  `/usr/sbin` eklendi.
- **Otomatik karantina:** ClamAV'ın bulduğu her dosya taramadan hemen sonra
  karantinaya alınır (`/var/lib/satsuma-core/scan-quarantine`; silinmez).
  `/home`, `/opt`, `/root`, `/tmp`, `/var/tmp`, `/dev/shm`, `/usr/local`,
  `/srv` için geçerlidir. `/usr/bin`, `/etc` gibi sistem klasörlerindeki
  bulgular bildirilir, taşınmaz.

## nftables.service Satsuma güvenlik duvarını yüklüyor

- Açılışta `nftables.service` de `/etc/satsuma-core/nftables.nft`'yi
  yükler (satsuma_core tablosu yoksa).
- `nftables.service` durdurulsa ya da yeniden yüklense de Satsuma
  tabloları silinmez.

## Diğer

- "Cross-team" kritik bulguları artık programın adını ve komut satırını,
  her ekibin ne gördüğünü yazıyor.
- Arka plan bileşenlerinde `dns_monitor`, `evidence`, `response` artık
  "Veri alınamadı" değil "Etkin" görünüyor.
- `satsuma-admin tam-kontrol` modem rota farkını `[SORUN]` olarak
  bildiriyor.
