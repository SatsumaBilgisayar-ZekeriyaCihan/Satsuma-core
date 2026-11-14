# SatsumaSecurity 2.2.10 — modem ve tam kontrol yaması

2.2.9'un yerini alır ve onun her şeyini (tam koruma, IPv6 kapalı) içerir.
Kurulu 2.2.9'un üstüne `yama.sh` ile kurulur.

## Düzeltilen: modem seçilemiyordu

- Modem listesi boş kalıyor ve sebep gösterilmiyordu. Artık modem olarak
  sunulmayan her bağlantı sebebiyle yazılıyor (ağ geçidi yok, VPN/tünel
  arayüzü, modemin MAC adresi görünmüyor…).
- Modemin MAC adresi komşu tablosunda yoksa ARP tablosundan da okunuyor.
- IPv6 okuması başarısız olsa da IPv4 modemi listeleniyor.
- Modemi onaylamak artık açılış bütünlük kilidini beklemiyor.

## Yeni

- **Modem otomatik tanınıyor:** bilgisayar tek bir modem görüyorsa Satsuma
  onu kendiliğinden kaydeder ve izlemeye başlar. Modemden başka bir MAC
  adresi cevap verirse kritik uyarı verir.
- **MAC adresini elle yazma:** Ağ koruması sayfasında ya da terminalde
  `sudo satsuma-admin modem --mac <modem-etiketindeki-MAC>`.
- **Tam kontrol:** `sudo satsuma-admin tam-kontrol` paneldeki kapalı
  anahtarları yeniden açar, duraklatmayı kaldırır, modemi kaydeder ve her
  maddeyi (ayarlar, servisler, güvenlik duvarı, IPv6, modem, anahtarlar)
  TAMAM / SORUN olarak sebebiyle yazar.
