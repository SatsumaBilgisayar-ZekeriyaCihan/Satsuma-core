# Satsuma Core 2.2.52 (2026-11-19)

Durum: kaynak adayı; RPM GitHub Actions'ta Fedora 44 içinde derlenir. İmzasız.
2.2.51'in DNS düzeltmesini de içerir.

## Uyarı ve hata listesindeki yanlış alarmlar ve ham kodlar

Saha ekranı (Kayıtlar → Tüm kayıtlar → Yalnızca uyarı ve hatalar):

- **AUDIT_SOURCE_CHANGED her ~10 dakikada:** auditd günlüğü dolup yeni dosyaya
  geçtiğinde Satsuma eski dosyayı sonuna kadar okuyup yenisine doğru geçiyordu,
  ama kayıtlı konum eski dosyada kaldığı için her geçişi hata sayıyordu. Artık
  izlenen bir geçiş hata değildir. Gerçek durum (Satsuma kapalıyken günlüğün
  değişmesi) yine bildirilir, artık "Uyarı" olarak ve Türkçe cümleyle.
- **"Tarayıcı bellek taraması hataları · Hata (×2)":** bu tür aslında geçici
  dosya taramasının hatalarıdır; adı düzeltildi. Kayıt artık hata türünün
  yanında nedenini ve errno'yu tutar; satır "Geçici dosya taranamadı · /tmp/… ·
  izin yok" gibi okunur.
- **"otx_domain":** OTX alan adı sorgusu hataları hangi alan adı olduğunu
  yazar: "OTX alan adı sorgusu başarısız: ornek.com".
- Kaydın ayrıntı kartı her seçimde ilk satırından başlar.

## Kural motoruna giden olaylar kaybolmuyor

Saha ekranı: "Akış bekçisi · Olay gönderilemedi" ve "Toplayıcı olay düşürdü"
aynı saniyede. Toplayıcı (satsuma-core) olayları kural motoruna (satsuma-teams)
Unix datagram soketiyle beklemeden gönderiyordu. Alıcının kuyruğu doluysa
(çekirdek bu soketlerde yalnızca birkaç yüz paket bekletir; systemd'siz
sistemlerde 10) ya da motor yeniden başlıyorsa olay o anda kayboluyordu ve aynı
kayıp iki ayrı sayaçta iki uyarı olarak görünüyordu. Kaybolan olay hiçbir
kurala ulaşmadığı için tespit edilemezdi.

Şimdi olaylar sınırlı (20 000 olay), sırayı koruyan bir bekleme kuyruğunda
bekler ve bir sonraki gönderimde ya da sağlık güncellemesinde gönderilir. Yalnızca
bu kuyruk taşarsa gerçek kayıp sayılır, tek uyarıyla.
