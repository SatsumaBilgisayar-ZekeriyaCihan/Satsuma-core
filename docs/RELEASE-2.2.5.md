# SatsumaSecurity 2.2.5 — internet trafiği profilleri

2.2.4'ün üzerine kurulur; 2.2.4'teki her şeyi içerir.

## Yeni

- **"İnternet trafiği" sayfası** (Yönetim → İnternet trafiği): "İnternet
  trafiğini nasıl ayarlayalım?" sorusuyla, bu bilgisayardan dışarıya hangi
  bağlantıların açılacağını seçersiniz. DNS (53) ve HTTPS (443) her zaman
  açıktır. Eklenebilenler:
  - Uzak destek: TeamViewer TCP/UDP 5938, AnyDesk TCP 6568 (yalnızca dışarıya)
  - SSH ile başka bilgisayara bağlanma: TCP 22
  - E-posta programı: TCP 465, 587, 993, 995 (şifreli)
  - Özel: kendi TCP/UDP portlarınız (en fazla 32)

  Dışarıdan gelen bağlantılar her seçenekte kapalıdır. DNS sunucunuz
  değişmez. Port açmak yönetici parolasını yeniden ister ve kritik olarak
  kaydedilir. Değişiklik güvenlik duvarına tek işlemde uygulanır ve geri
  okunarak doğrulanır; doğrulanamazsa eski hâline döner. TCP 80 (şifresiz
  HTTP) bilerek eklenmedi.

## Düzeltilen (saha testi)

- **App Control tek bir paket yüzünden çöküyordu** ("NFQUEUE handle-packet
  failure ... errno=0"). Karar verilemeyen pakete izin verilmiyor, sayılıyor
  ve süreç çalışmaya devam ediyor.
- **İkinci Suricata servisi:** sistemin kendi `suricata.service`'i açıksa
  Satsuma IPS ile kuyruk 100 için çakışır ve ikisi birbirini durdurur. Sistem
  sağlığı sayfası bunu artık "Trafik engelleme" altında, kapatma komutuyla
  birlikte gösteriyor. Otomatik kapatılmaz.
- **`kaldir.sh` 3. adımda takılıyordu:** nftables paketinin yeniden kurulumu
  artık Satsuma'nın güvenlik duvarı kaldırıldıktan sonra yapılıyor. nftables
  hâlâ Satsuma'yı gösteriyorsa betik yeniden başlatma önermiyor.

Önceki sürümler için: `docs/RELEASE-2.2.4.md`, `docs/RELEASE-2.2.3.md`.
