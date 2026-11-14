# /dev ve systemd: kaynaklar, kurallar ve gerçek sınırlar

Araştırma tarihi: 19 Ekim 2026. Aşağıdaki erişim örüntüleri tek başına
istismar gerçekleştiğini kanıtlamaz; meşru sistem araçları da bunları yapar.

| Kanıtlanmış kötüye kullanım yüzeyi | Satsuma gözlemi | Belgelenmiş koruma |
|---|---|---|
| /dev/input üzerinden tuş kaydı | SATSUMA-DEV-002, audit read/write ve aygıt yolu | Aygıt izinleri/ACL, yalnızca gerekli gruplara erişim; uygun systemd servislerinde DevicePolicy/DeviceAllow. Masaüstü girişini topluca chmod ile bozma. |
| /dev/mem, /dev/kmem, /dev/port üzerinden donanım/bellek erişimi | SATSUMA-DEV-001 | CONFIG_STRICT_DEVMEM, CONFIG_IO_STRICT_DEVMEM ve uygun çekirdek yapılandırması; ihtiyaç dışı CAP_SYS_RAWIO vermeme; servis aygıt sınırları. |
| Ham diske yazarak veri yok etme | SATSUMA-DEV-003, audit write ve gerçek aygıt yolu | /dev disk izinleri, disk grubunu sınırlama, servislerde DevicePolicy=closed ve dar DeviceAllow; ayrı, geri yüklenebilir yedek. |
| Hassas aygıtın herkese açık izni | SATSUMA-DEV-004, metadata envanteri | Udev/ACL politikası ve en az yetki. Otomatik geniş chmod uygulanmaz. |
| TIOCSTI ile terminal girdisi enjekte etme | Bu sürümde TIOCSTI syscall/ioctl kanıtı yok; tespit edildiği iddia edilmez | Linux 6.2+ dev.tty.legacy_tiocsti=0 ve ilgili çekirdek seçeneği; root yetkisi/CAP_SYS_ADMIN sınırları. Dağıtım etkisi ayrıca test edilmeli. |

İlk üç kural, audit kayıtlarında ilgili aygıt yolunun ve operation alanının
bulunmasına bağlıdır. Bu kuralları yüklemek bütün /dev erişimlerini otomatik
olarak audit'e kaydettirmez. Yeni aygıtın udev olayı, mevcut bir işlemin o aygıta
ait açık FD'si ve süreç kimliği ayrıca SATSUMA-UDEV-001/002 ile kaydedilir.
İki saniyelik örnekleme kısa süre açılıp kapanan FD'leri kaçırabilir; olay sonrası
ilişki nedensellik, keylogger veya rootkit kararı değildir.

`systemd-analyze security`, servislerin systemd koruma seçeneklerinden bir
hardening tahmini çıkarır. Çalışan sistemin temizliğini veya istismar
olmadığını doğrulamaz; IPC ve uygulama içi güvenlik kapsamı sınırlıdır.
Yönetim ekranındaki yeni başlatıcı sabit komut çalıştırır; shell komutu kabul
etmez. /dev envanteri lstat/readlink ile sınırlıdır, ham aygıt içeriği okunmaz.

Satsuma'nın yeni udev servisi host aygıt metadata'sını görebilmek için
PrivateDevices kullanmaz; DevicePolicy=closed aygıt açma yetkisini sınırlar.
Bu politika bütün makinenin diğer uygulamalarına yayılan genel bir aygıt
engelleme politikası değildir. Kernel worker için eklenen CAP_SYSLOG, kısıtlı
dmesg okumasını mümkün kılmak içindir; CAP_SYS_ADMIN verilmez.

## Birincil kaynaklar

- [MITRE ATT&CK T1056.001 — Keylogging](https://attack.mitre.org/techniques/T1056/001/)
- [MITRE ATT&CK T1561.001 — Disk Content Wipe](https://attack.mitre.org/techniques/T1561/001/)
- [Linux mem(4)](https://man7.org/linux/man-pages/man4/mem.4.html)
- [Linux TIOCSTI(2const)](https://man7.org/linux/man-pages/man2/TIOCSTI.2const.html)
- [Linux tty Kconfig](https://github.com/torvalds/linux/blob/master/drivers/tty/Kconfig)
- [Linux STRICT_DEVMEM / IO_STRICT_DEVMEM](https://github.com/torvalds/linux/blob/master/lib/Kconfig.debug)
- [systemd.exec](https://www.freedesktop.org/software/systemd/man/latest/systemd.exec.html)
- [systemd.resource-control — DevicePolicy/DeviceAllow](https://www.freedesktop.org/software/systemd/man/latest/systemd.resource-control.html)
- [systemd-analyze security ve değerlendirme sınırları](https://www.freedesktop.org/software/systemd/man/latest/systemd-analyze.html)

Bu kaynaklardan türetilen kurallar koşullu tespittir. Native Fedora VM'de aygıt
politikası, klavye, disk, ağ aygıtı ve yeniden başlatma davranışları doğrulanmadan
canlı önleme başarısı ilan edilmez.
