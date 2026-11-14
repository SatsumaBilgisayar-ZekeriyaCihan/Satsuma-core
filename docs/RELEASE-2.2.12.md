# SatsumaSecurity 2.2.12 — düzeltme yaması

2.2.11'in yerini alır ve onun her şeyini içerir. Kurulu sürümün üstüne
`yama.sh` ile kurulur.

## Düzeltilen

- **Virüs taraması "Başarısız" görünmüyor:** zamanlayıcı servisi her dakika
  başlatıyor, servis ise 5 dakikada yalnızca 3 başlatmaya izin veriyordu;
  her 4. ve 5. başlatma reddedilip "başarısız" görünüyordu. Sınır kalktı.
- **Güvenlik aksiyonlarında "Neden" boş kalmıyor:** bir otomatik eylem
  uygulanmadıysa sebebi Türkçe yazıyor. Sıradan etkinlik göstergeleri
  (sudo, systemctl, git…) "Uygulanmadı" değil "Yalnızca bildirildi" diye
  görünüyor.
- **Otomatik ağ engelinde kalan dakikada 20 kotası kaldırıldı.**
- **Elle değiştirilmiş `/etc/satsuma-core/nftables.nft` ağı kesmiyor:**
  değiştirilmiş dosya `nftables.nft.elle-degistirilmis-<tarih>` olarak
  saklanıyor ve doğru dosya yeniden yazılıyor. Önceden bu durumda açılışta
  bütün trafik kesiliyordu.
