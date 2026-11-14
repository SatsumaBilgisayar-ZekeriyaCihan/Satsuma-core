# Dışarıya TeamViewer ve AnyDesk

17 Ekim 2026 tarihinde resmî sürüm sayfalarında doğrulanan Linux sürümleri:
TeamViewer 15.82.6 (29 Eylül 2026) ve AnyDesk 8.1.0 (23 Eylül 2026). Bunlar
uyumluluk hedefidir; hedef bilgisayarda kurulu sürümün tespit edildiği veya gerçek
uzak oturumun bu sürümlerle test edildiği anlamına gelmez.

Ana firewall dışarı başlatılan TCP/53, TCP/443 ve UDP/53 bağlantılarını ve
yanıtlarını Suricata NFQUEUE100 ile geçirir. Dışarıdan başlatılan yeni bağlantılar
ve yönlendirilen trafik DROP olur. Ek uygulama filtresi varsayılan kapalıdır.
TeamViewer ve AnyDesk servisleri Satsuma tarafından durdurulmaz veya maskelenmez.

Bu iki araç aracı sunucular üzerinden çalışabilir: dışarı açılmış TCP bağlantısı
üzerinden bilgisayara uzaktan kontrol oturumu gelebilir. Bu yüzden firewall
kuralları tek başına bu araçlarda gelen kontrolü kapattığını kanıtlamaz.

TeamViewer'ın kendi ayarlarında **Advanced → Connections to this computer →
Access Control → Deny incoming remote control sessions** seçilmelidir.
“Connections to other computers” çıkış ayarı bundan ayrıdır. Kullanılan sürümdeki
ayar ve başka bir cihazdan gelen oturum denemesi ayrıca doğrulanmalıdır.

AnyDesk'in resmî özel istemci oluşturucusunda **Connection Type: Outgoing**
istemci gelen oturum kabul etmez. Standart istemcide yalnız “Never show incoming
session requests” seçmek yeterli değildir: unattended access ayrıca çalışabilir.
Satsuma, doğrulanmamış Linux config anahtarları yazarak bunu kapattığını söylemez.
Özel istemci oluşturma/dağıtma için gerekli kullanıcı hesabı ve lisans sağlanmadı.

Kaynaklar:
- https://www.teamviewer.com/en-us/global/support/knowledge-base/teamviewer-classic/security/best-practices/restrict-access-for-connections/
- https://www.teamviewer.com/en-us/global/support/knowledge-base/teamviewer-remote/troubleshooting/ports-used-by-teamviewer/
- https://support.anydesk.com/firewall
- https://support.anydesk.com/v1/docs/create-custom-client
- https://support.anydesk.com/docs/interactive-access
- https://www.teamviewer.com/de/download/portal/linux/
- https://anydesk.com/en/changelog/linux

## Yerel uzak sunucu ve paylaşım servisi koruması

RPM, dosya açmadan önce bilinen SSH/RDP/VNC, diğer listelenmiş uzak sunucu,
SMB/NFS ve yönetim web servislerini durdurur ve maskeler. Önceden bulunan yerel
unit dosyaları özel `/var/lib/satsuma-core/containment/backups` klasörüne taşınır.
`satsuma-containment.service` bu bilinen birimleri ve süreçleri izlemeyi sürdürür.
Bu bir kötü amaçlı yazılım temizleme veya tüm olası uzak araçları tanıma iddiası
değildir. Durumda `vendor_incoming_session_policy: requires_native_policy_verification`
ve `host_cleanliness_verified: false` açıkça bulunur.

Fedora konteyner testleri gerçek systemd servislerinin durdurulmasını ve örnek
TeamViewer/AnyDesk daemon birimlerinin korunmasını denetler. Gerçek TeamViewer /
AnyDesk oturumları, hedef sürümler ve hesaplar sağlanmadığından denenmedi.
