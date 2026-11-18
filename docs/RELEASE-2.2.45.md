# Satsuma Core 2.2.45 (2026-11-18)

Durum: kaynak adayı; RPM GitHub Actions'ta Fedora 44 içinde derlenir. İmzasız.

## Panel baştan tasarlandı (sahibinin kararı: "eksiksiz, kullanışlı, kullanıcı tabanlı")

Siyah-turuncu tema korundu; bilgi mimarisi, menü ve sayfalar yeniden yazıldı.

- **Durum** (açılış sayfası): tek cümlelik sonuç ("Korunuyorsunuz", "2 konu sizi
  bekliyor", "Müdahale gerekiyor"); **sizi bekleyenler** — her birinin yanında onu
  çözen düğme (sağlık kontrolü başarısız → *Onar*; uygulama internete çıkmak
  istiyor → *İzin ver / Engelle*; onay bekleyen program → *İncele*; modem → *Modemi
  onayla*); altı koruma katmanı (programlar ve bellek, ağ, DNS filtresi,
  uygulama izinleri, dosyalar, tehdit istihbaratı) ve son 24 saatin sayıları.
- **Olanlar**: bulgu, durdurma, engelleme ve karantina tek akışta. Aynı olay tekrar
  ettiğinde tek satırda sayılır ("11 kez · son 18:31"). Her kayıtta *Ne oldu*,
  *Satsuma ne yaptı*, *Öneri* ve *Ne yapabilirsiniz* (engeli kaldır, adrese/alan
  adına izin ver, teknik ayrıntı). Filtre, arama ve 24 saat / 7 gün / 30 gün.
- **Koruma**: her anahtar gerçek durumunu kilitliyken de gösterir ve neyi
  değiştirdiğini tek cümleyle söyler. Test modu artık "Durdurmadan önce bana sor".
  Ağ (otomatik engel, yerel ağ, alt ağ, internet trafiği profili, engellenen ve
  izinli adresler), DNS (filtre, izinli alan adları, kendi listeleriniz), OTX,
  uygulama izinleri, dosya taraması, cihazlar.
- **Sağlık**: başarısız kontroller sade adlarıyla, bileşenler, son bakım raporu;
  **Sorunları onar** düğmesi bakım kitini çalıştırır (yeni yönetim işi `repair`:
  `systemctl start --wait satsuma-maintenance.service`).
- **Ayarlar**: yönetici kilidi, modem onayı, WireGuard VPN, anahtarlar, görünüm.
- **Tek yönetici kilidi**: ayrı "Yönetim" girişi yok. Bir ayarı değiştirmek
  istediğinizde kilit kapalıysa parola o anda sorulur (30 dakika açık kalır);
  korumayı azaltan işlemler parolayı yine yeniden ister (denetim K7). Üst
  çubukta kilit durumu, bekleyen konu sayısı ve arama (Ctrl+F) var.
- **Uzman görünümü**: önceki sürümlerin bütün teknik tabloları (bulgular,
  Suricata, DNS sorguları, denetim, kurallar, DeepSeek, eski yönetim sayfası…)
  kenar çubuğunda isteğe bağlı bir bölümde. Hiçbir bilgi kaldırılmadı.
- Kısayollar: Ctrl+1…5 bölümler, Ctrl+F arama, Ctrl+L kilit, F5 yenile, Ctrl+Q çıkış.

## Okuyucu (salt okunur) yeni yöntemler

- `home`: sonuç, bekleyenler, katmanlar, son olaylar (`satsuma.home_view`).
- `activity`: tekrarları katlanmış olay akışı; süre, sonuç ve metin filtresi.
- `protection`: anahtarların ve listelerin şu anki durumu.
- `maintenance_report`: son bakım kiti raporu.

## Doğrulama

GitHub Actions'taki `dashboard` iş akışı paneli Fedora 44 içinde PyQt6 ile
ekransız açar, her sayfanın görüntüsünü alır ve tüm testleri PyQt6 varken
çalıştırır.
