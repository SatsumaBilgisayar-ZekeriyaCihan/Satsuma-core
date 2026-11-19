# Satsuma Core 2.2.50 (2026-11-19)

Durum: kaynak adayı; RPM GitHub Actions'ta Fedora 44 içinde derlenir. İmzasız.

## Aralığa her zaman izin ver (ör. bir VPN sağlayıcısı)

Saha bildirimi: "Opera VPN'i açınca hemen engelliyor." VPN sunucularının PTR
kaydı yoktur ve çok bağlantı açar; bekçinin sabit kuralı (PTR'siz bir uca tek
ziyarette 6. bağlantı) onları hemen engelliyordu.

Güvenlik duvarı → Engeller → "Hep izin verilen adresler ve aralıklar" alanına
artık CIDR aralığı yazılabilir (IPv4 en geniş /8, IPv6 en geniş /16), isteğe
bağlı bir notla. İzin verilen aralık hiçbir otomatik yolla engellenmez: bekçinin
bağlantı seli kuralı, OTX bağlantı kesme, Suricata uyarısı, alt ağ sınırı,
otomatik ağ yanıtı. Aralığın içinde önceden engellenmiş adreslerin engeli
eklenir eklenmez kalkar (bekçinin kendi tablosundakiler bir sonraki turda).
İzin korumayı azalttığı için parola yeniden sorulur. İzinli aralıkla çakışan
elle engel reddedilir; önce izin kaldırılmalıdır.

## Güvenlik duvarı tablo bekçisi

Saha bildirimi: Satsuma'nın bütün nftables tabloları elle silindiğinde hiçbiri
geri gelmedi. Tabloları kuran servisler bir kez çalışıp "etkin (tamamlandı)"
kalıyordu, sağlık bekçisi onları sağlıklı sanıyordu; DNS filtresi çözümleyiciye
ulaşamıyor, güvenlik duvarı hiçbir şeyi süzmüyordu.

`satsuma-firewall-watch.timer` her dakika her tabloyu sahibi olan servisle
karşılaştırır: ana filtre ve aralık engelleri (satsuma-network), DNS ad alanı
(satsuma-dns-netns, satsuma-core-dns), bekçi tablosu (satsuma-suricata-otx-guard).
Servis etkinken tablo yoksa servis yeniden başlatılır ve tablo açılıştaki
kurallarla geri kurulur. Bilerek durdurulmuş servisin tablosu beklenmez. Bir
grup 30 dakikada en çok üç kez onarılır, sonra yalnızca bildirilir. Her onarım
"Satsuma'nın işlemleri"ne ve Kayıtlar'a yazılır.

## 2.2.49'dan

Kurallar sayfası her kuralın ne yaptığını (durdurur / yalnızca bildirir),
otomatik durdurmanın açık olup olmadığını ve son 24 saatin sonuçlarını gösterir.
