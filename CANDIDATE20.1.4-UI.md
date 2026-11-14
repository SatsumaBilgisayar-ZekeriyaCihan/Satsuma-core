# 20.1.4 — Yerel Qt Internet Security arayüzü

22 Ekim 2026 · Europe/Istanbul

20.1.3 üzerine hazırlanan bu sürüm, mevcut **PyQt6 / PyQt5 masaüstü yapısını**
geliştirir. Web sayfası veya gömülü tarayıcı kullanılmaz. Paket tam ve imzasızdır;
GPG anahtarı oluşturulmaz. Ana dal ve önceki paketler değiştirilmez.

## Yeni görünüm

- Açılışta Güvenlik merkezi: büyük durum özeti, yerel Qt ile çizilen kalkan,
  belirgin inceleme düğmesi ve uygulama izinlerine doğrudan erişim.
- Grafit koyu tema, sıcak turuncu ana işlem rengi, açık metin, ortak kart,
  giriş, tablo, liste, seçim, klavye odağı ve kaydırma stilleri.
- Kalıcı sol menü: Genel bakış, Koruma, Ağ güvenliği, Sistem sağlığı ve Ayarlar.
  Alt sayfalar açılır kutu yerine klavyeyle de kullanılabilen yerel listede.
- Dosya bütünlüğü, ağ koruması ve tehdit istihbaratı kartları. Altta gerçek
  kayıtlardan gelen bulgu sayısı, kural sayısı ve son etkinlikler.
- Ayarlarda üstten hizalı sayfalar, yönetici girişine görünür kısayol,
  daha tutarlı boşluklar. Düzen gereksiz biçimde dikey alana yayılmaz.
- Bağımsız App Control penceresinde aynı koyu tema, büyük uygulama başlığı,
  ayırt edilen İzin ver / Engelle düğmeleri ve katlanabilir bağlantı ayrıntıları.
- İkonlar QPainter ile çizilir. Harici ikon yazı tipi veya internetten indirilen
  görsel gerekmez; yüksek DPI için ölçekli QPixmap kullanılır.

## Durumların doğruluğu

Görsel kalkan bir güvenlik skoru değildir. Dosyalar, yapılandırma ve koruma
kontrolleri birlikte başarılı bildirilmeden başarılı kalkan gösterilmez.
Tutarsız veya kritik kayıtlar başarılı görünümün önüne geçer. Veri yokken gri
bekleme durumu ve “—” sayıları kullanılır; sıfır veya temiz sonucu üretilmez.

Yeşil dosya kartı yalnız uygulama dosya kontrolünün sonucudur; sistemde tehdit
bulunmadığını göstermez. OTX kaynağının etkinliği paket düşürme kanıtı sayılmaz.
Yönetici yetkisi, karar kimliği sabitlemesi, REQUESTED/APPLIED ayrımı, yön kontrolü
ve firewall güvenlik kapıları korunur. Ana penceredeki inceleme bağlantıları
korumayı kendiliğinden etkinleştirmez.

## Doğrulama

Debian / Python 3.12 / Qt6 offscreen: **558 test ve 5 alt test geçti**; başarısızlık,
hata veya atlama yok. Altı yeni Qt testi şunları kontrol eder:

- Eksik veya çelişkili sağlık verisinin başarılı kalkana dönüşmemesi.
- Tüm mevcut sayfalara sol menüden erişim ve liste seçiminin korunması.
- Veri yokken sahte sıfır/başarı gösterilmemesi.
- İzin kısayolunun gerçek yönetim sayfasına gitmesi ve yetkilendirme gerektirmesi.
- 1000×680 boyutta sabit yan menü ve yatay taşma olmadan kaydırılabilir içerik.
- Yalnız sağlık bilgisi yenilendiğinde etkinlik seçiminin korunması.

Ekran görüntüleri çalışan yerel Qt penceresinden alınmıştır. Görüntülerdeki örnek
bulgular/sayaçlar **sentetik tasarım verisidir**, gerçek tehdit veya engelleme
kanıtı değildir. Verisiz görünüm de ayrıca gösterilir. Üretim uygulamasına demo
kayıtları veya sahte sayılar eklenmez. Önizleme aracı `tools/preview-security-ui.py`
yalnız kendi sahte backend'ini kullanır; servis başlatmaz veya politika yazmaz.

## Kalan kabul kapıları

Bu sürüm görünüm ve gezinme yenilemesidir. 20.1.3 raporundaki açık işlevsel
maddeler kapanmış sayılmaz. Gerçek Fedora44/Wayland, SELinux, ilk kurulum,
yükseltme, yeniden başlatma/kaldırma, gerçek Brave, canlı trafik engelleme,
uzun süreli kaynak tüketimi ve tüm donanım ölçekleme senaryoları doğrulanmadı.
App Control bildirim penceresi uygulama tamamen kapalıyken çalışmaz. Wayland
pencere konumlandırması compositor'e bağlıdır. İmzasız test adayıdır; kararlı
veya üretime hazır olduğu iddia edilmez.
