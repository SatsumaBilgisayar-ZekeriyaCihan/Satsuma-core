# Satsuma Core 2.2.57

Saha 2026-11-19: iki yanlış alarm ve tekrarlanan durdurma kayıtları.

## Satsuma kendi kısa servis çalışmalarını tanıyor

`satsuma-core-dns-refresh` (dakikalık, `python3 -m satsuma.dnsmasq_control`) DNS listesi her değiştiğinde
`/etc/satsuma-core/dns/` altına yazıyor ve SATSUMA-GAP-047 ("Satsuma yapılandırmasını Satsuma dışından
değiştirme") olarak durdurulmaya çalışılıyordu. Sebepler:

* süreç, olay değerlendirilmeden bitiyordu; hangi birime ait olduğu /proc'tan okunamıyordu;
* denetim kaydındaki komut satırı `systemd-executor --deserialize ...` idi (güvenilmez);
* yorumlayıcı (python) yalnız komut satırında /opt/satsuma-core/ varsa Satsuma'nın sayılıyordu.

Artık kanıt systemd'nin kendi kaydıdır: paketle gelen (salt okunur /usr/lib/systemd/system, /etc'den
değiştirilmemiş) bir Satsuma biriminin `ExecMainPID`'i olan ve olay zamanı o çalışmanın içinde kalan süreç
Satsuma'nındır. Böyle bir birimin python süreci Satsuma kodu sayılır. Kabuklar ve indirme araçları yine asla
kendi sayılmaz; /etc'deki birimler ve yeniden kullanılan PID'ler güvenilmez. Kural genişletilmedi:
`/etc/satsuma-core/dns/`'e başka bir sürecin yazması hâlâ kritik bulgudur.

## Bir süreç, bir durdurma

Aynı süreçten gelen birden çok bulgu (üç yazma, üç bulgu) privd'ye üç kez gidiyor ve her biri ayrı kayıt
üretiyordu. Artık aynı süreç (pid, başlangıç zamanı, program) için 60 saniye içinde tek karar verilir.

## Masaüstü kaydı (PRIV-003)

Panelin `pkexec /usr/bin/satsuma-enroll-desktop --user <hesap> --password-stdin` komutu "şüpheli pkexec" izi
bırakıyordu (18.11 18:22'de eski POLKIT-001 bunu durdurmuştu). Yalnız bu komutun tam hali muaftır; fazladan
argüman, kabuk ya da /tmp yolu yine yakalanır.
