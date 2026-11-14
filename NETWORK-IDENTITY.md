# Kullanıcı seçimiyle tek modem referansı

Ağ kimliği modülü yalnız okur. Tüm IPv4/IPv6 yönlendirme tabloları, policy-routing
kuralları ve mevcut Ethernet modem/ağ geçidi adayları yönetim panelinde listelenir.
Komşu tablosu güvenilir kimlik kaynağı sayılmaz; yalnız aday MAC gözlemidir.

Kullanıcı Yönetim bölümünde tabloları listeler, kendi modemini seçer ve açık onay
kutusuyla onaylar. Kayıt, UID'ye bağlı yönetici oturumu gerektirir; backend seçim
anında envanteri yeniden okur. Tek referans `network-identity/approved-modem.json`
içinde atomik ve HMAC ile saklanır. Önceki otomatik ilk gözlem kaydı onay sayılmaz.

Seçim yapılamazsa envanter otomatik hazırlanır; güvenilir modem uydurulmaz.
MODEM_APPROVAL_REQUIRED, MODEM_REFERENCE_CHANGED veya gözlem hatası sağlıklı
sayılmaz. Modem/arayüz/MAC yanında tüm route/rule snapshot fingerprint'i karşılaştırılır;
farklı bir tabloda yeni yönlendirme varsa eski modem kaydı eşleşse bile uyarılır.
Dinamik yaş/expiry alanları karşılaştırmadan çıkarılır; route/rule değişiklikleri
kendiliğinden yeni baseline yapılmaz. Ek ağ geçitleri de açıkça gösterilir.

Servis CAP_NET_ADMIN/CAP_NET_RAW taşımaz. Yalnız AF_UNIX/AF_NETLINK açabilir.
`ip` çağrıları kesin okuma allowlist'iyle sınırlıdır. Modül rota, komşu, DNS veya
nft tablosunu değiştirmez; ARP/ND sondası göndermez. Sağlık kontrolü modem
onayı/güncel karşılaştırma olmadan PASSED demez. Kullanıcı onayı donanımsal veya
kriptografik modem kimliği kanıtı değildir; MAC kopyalama tek başına bu yöntemle
çözülemez. Ekran da bağımsız cihaz doğrulaması yapıldığını iddia etmez.

Önceki sürümlerin kalıcı komşu ve identity nft kayıtları otomatik silinmez;
yönetici bunları ayrı incelemelidir. `--learn` otomatik güven kazandırmaz;
seçim/onay için yönetim panelini kullanın.
