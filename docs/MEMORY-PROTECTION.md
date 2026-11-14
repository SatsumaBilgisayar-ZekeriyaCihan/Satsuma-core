# Bellek koruması ve kapsamı

## Kod bütünlüğü ve otomatik sonlandırma

WorkerMemory her 5 saniyede en fazla 128 süreç seçer. Ana executable dosyasının
private çalıştırılabilir eşlemelerinden süreç başına en
fazla 1 MiB RAM içeriği bağlı executable dosyasıyla karşılaştırılır. PID başlangıç
zamanı, executable ve eşleme listesi inceleme öncesi/sonrası kontrol edilir.
Bellek içerikleri kayda yazılmaz; yalnızca karşılaştırma sonucu ve SHA-256
özetleri tutulur. Bu özetler şifreleme değildir.

Kod farkı SATSUMA-RAM-005 bulgusu üretir. AutoActionEngine algılama kimliğini ve
kod farkını canlı süreçte tekrar doğrular. Etkin response/process_kill politikası
altında bu doğrulanmış kod bütünlüğü ihlali için ikinci sensör beklemeden pidfd
ile SIGTERM, gerekirse SIGKILL uygulanır ve çıkış doğrulanır. Değiştirilmemiş
kod, sahte/eski mismatch etiketi, PID değişimi ve okunamayan bellek bu yetkiyi
vermez. Debugger breakpoint ve yetkili hotpatch de kod farkıdır; etkin politika
bu uygulamaları da sonlandırabilir. Bu davranış yalnızca doğrulanan kod
bütünlüğü kapsamındadır, tüm bellek saldırılarının tespiti iddiası değildir.

Anonim/JIT sayfaları, paylaşımlı kütüphaneler ve veri sayfaları bu karşılaştırma
kapsamında değildir. CODE_MATCH, zararlı yazılım içermediği anlamına gelmez;
yalnızca kontrol edilen kodun bağlı dosyayla aynı olduğunu gösterir. Dosyanın
kendisi zararlıysa eşleşmesi onu güvenilir yapmaz. Eksik/engellenmiş inceleme
RUNNING gibi gösterilmez. Süreç sayısı 128'i aşıyorsa tam tur birden fazla
aralık sürer. Polling, işlem başlamadan engelleme garantisi vermez.

## Erken boot: devtmpfs ve shared memory

satsuma-memory-hardening.service, mevcut Satsuma image mount ve local-fs
sonrasında, early-guard/core/teams öncesinde çalışır. Bu initramfs veya kernel
başlangıcından itibaren koruma değildir. /dev devtmpfs üzerine nosuid,noexec;
/dev/shm tmpfs üzerine nosuid,nodev,noexec uygulanır ve mountinfo'dan okunarak
doğrulanır. /dev üzerine nodev eklenmez; cihaz işlevleri korunur. Mount türü
beklenmiyorsa işlem hata verir. Çalıştırılabilir /dev/shm kullanan uygulamalar
bu politikadan etkilenir. Bu ayarlar memfd veya anonim executable sayfaları
tümüyle engellemez. Erken guard mount politikasını kontrol eder; başarısızlık
response kilidini açık bırakmaz.

Core servisinde gereken SYS_PTRACE/KILL yetkileri zaten bulunuyordu; teams
servisine canlı kod kontrolü ve sonlandırma için bu yetkiler eklendi. Bu
yetkiler yalnızca sistem servislerine aittir. SELinux ve hedef kernel
kısıtlarının Fedora cihazında ayrıca doğrulanması gerekir.

## Erken boot bellek erişimi

Aynı hardening servisi kernel.yama.ptrace_scope=2, kernel.kptr_restrict=2,
kernel.dmesg_restrict=1 ve fs.suid_dumpable=0 uygular. kernel.core_pattern
`|/usr/bin/false` yapılarak sistem genelinde kernel core dump aktarımı
engellenir; önceki coredump handler bu politika altında kullanılmaz.
Kontroller yazıldıktan sonra tekrar okunur. ptrace_scope=3 gibi daha sıkı
mevcut politika gevşetilmez. Early guard bu ayarların sonucunu ayrı kontrol
eder. Sysctl değişikliği hedef kernelde mümkün değilse başarı gösterilmez.

Core/teams servisleri LimitCORE=0 ve PR_SET_DUMPABLE=0 ile başlar. Yama scope=2
normal kullanıcıların başka süreçlere debugger/proc-mem erişimini sınırlar;
debugging için yönetici yetkisi gerekir. CAP_SYS_PTRACE sahibi bir yönetici
veya ele geçirilmiş kernel bu sınırın dışındadır. Bu kontroller fiziksel RAM
şifrelemesi veya ele geçirilmiş root/kernel karşısında gizlilik garantisi
değildir. Satsuma servislerine verilen CAP_SYS_PTRACE belleği doğrulayabilmek
içindir; bu yetki son kullanıcı süreçlerine verilmez.

## Fiziksel RAM şifreleme

SHA-512 bir özet algoritmasıdır, şifreleme sağlamaz. Tüm fiziksel RAM için
AMD SME/Intel TME gibi CPU/firmware/kernel desteği gerekir. Anahtarlar donanım
tarafından yönetilir; çalışan RAM'i bir Python servisiyle rastgele anahtarla
şifrelemek uygulanabilir bir sistem tasarımı değildir. Donanım RAM şifreleme
yetkili bir sürecin başka süreç belleğini okumasını tek başına engellemez;
DMA/shared sayfalar da açık tutulabilir. Yüzde yüz açık bellek yok iddiası yoktur.

Hedef olarak bildirilen MSI A520 / Ryzen 5 5500 sisteminin lscpu çıktısında
sme/sev desteği görünmüyor. Bu mevcut yapılandırmada SME etkinleştirilemez.
AES/SHA işlemci bayrakları RAM şifrelemesi kanıtı değildir. Satsuma bu cihazda
hardware RAM encryption aktifmiş gibi bir durum üretmez.

Salt okunur durum kontrolü kaynak ağacında:
`PYTHONPATH=source python -m satsuma.hardware_memory`.
Kurulu üründe root olarak:
`python3 -I -B /opt/satsuma-core/installer/boot_setup.py --memory-encryption-status`.
Araç CPU bayrağı/boot parametresi ile gerçek kernel etkinleştirme kanıtını
ayırır. BIOS/kernel parametresi değiştirmez; donanım key'i oluşturduğunu iddia
etmez. Hedef Fedora cihazında boot/remount/SELinux ve gerçek donanım şifreleme
kabul testi bu bulut ortamında çalıştırılmamıştır.
