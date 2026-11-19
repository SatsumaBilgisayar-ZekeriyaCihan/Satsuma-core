# Satsuma Core 2.2.56

## Otomatik geri alma (sahip kararı 2026-11-19, kapsam "her şey")

Tek seferlik bir saldırı komutu milisaniyede biter; süreci durdurmak geç kalır. Satsuma artık
komutun bıraktığı etkiyi geri alır (durdurma politikası açıkken):

| Bulgu | Geri alma |
|---|---|
| Güvenlik duvarı silindi (LNX-EVAS-002, EVAS-005, GAP-023) | satsuma-firewall-watch hemen çalışır, tablolar geri kurulur |
| Kalıcılık dosyası yazıldı: cron, systemd birimi, autostart, kabuk başlangıç dosyaları, ld.so.preload, udev, binfmt, sudoers.d, kök sertifika (PERS-*, GAP-010/011/013/015/053, SUDO-005) | Dosya karantinaya alınır (`sudo satsuma-admin karantina geri-al <kimlik>`); systemd birimi durdurulur ve systemd yeniden yüklenir, udev kuralı ardından udev yeniden yüklenir; `.wants` bağlantısı silinir ve geri koyma komutu kayda yazılır |
| authorized_keys yazıldı (PERS-003) | Yalnız onaylamadığınız anahtar satırları çıkarılır; onayladıklarınız kalır |
| UID 0 / kopya UID ya da yeni hesap (GAP-016, GAP-042) | Hesap kilitlenir ve süresi doldurulur (`usermod -L -e 1`); geri: `sudo usermod -U -e '' <hesap>` |
| Hesap wheel/sudo/adm grubuna eklendi (GAP-017) | Gruptan çıkarılır; geri: `sudo gpasswd -a <hesap> <grup>` |

Hiç dokunulmayanlar (yalnız alarm): root, masaüstü sahibi (satsuma-reader üyeleri), Satsuma hesapları ve
dosyaları, /etc/passwd, shadow, group, gshadow, sudoers, PAM, /etc/profile, /etc/bashrc, /etc/crontab, fstab,
SELinux yapılandırması. Paket yöneticilerinin (rpm-ostree, dnf, rpm, bootc...) yazmaları geri alınmaz.

Plan teams servisinde yapılır, privd (`remediate` işlemi) her eylemi bağımsız olarak yeniden denetler ve
yalnız o uygular. privd ev dizinlerindeki kalıcılık dosyalarına erişmek için `ProtectHome=no` ile çalışır;
yalnız `satsuma.remediation.FILE_PATTERNS` konumlarına dokunur.

Komutlar:

    sudo satsuma-admin geri-alma durum     # açık mı, son 20 geri alma ve geri koyma komutları
    sudo satsuma-admin geri-alma kapat     # yönetici parolası ister
    sudo satsuma-admin geri-alma ac

## Sahte çekirdek iş parçacığı (SATSUMA-GAP-072)

Kendini `[kworker/0:1]` gibi gösteren kullanıcı süreçleri. Gerçek çekirdek iş parçacıkları PF_KTHREAD
bayrağıyla ayrılır; bayrağı olmayan ama adı ya da komut satırı köşeli parantezli çekirdek adı taşıyan süreç
kritik bulgudur.

## Çekirdek

* `kernel.io_uring_disabled = 2`: io_uring okuma/yazma/bağlantıları auditd'ye hiç ulaşmaz; kapatıldı ve
  çekirdek bekçisi her saniye denetler.
* SELinux çalışırken permissive yapılırsa (`/sys/fs/selinux/enforce`) bekçi enforcing'e geri alır ve alarm
  verir. Sistem permissive kurulmuşsa ya da açılış satırında `enforcing=0` varsa dokunmaz.
* Çekirdek bekçisinin geri yazdığı her değişiklik (sysctl, SELinux, açılış satırı, bağlamalar, birimler) artık
  panelde bulgudur (SATSUMA-KGUARD-*). Önceden yalnız günlüğe gidiyordu.
* SATSUMA-GAP-073: çekirdek modülünü dosyadan (`insmod x.ko`, `modprobe /yol/x.ko`) ya da zorla
  (`modprobe -f`) yükleme. Açılıştaki olağan `modprobe` izleri (PRIV-017) kayda girmeye devam eder.

Kural sayısı: 304.

## English summary

Automatic remediation of one-shot attacks (firewall restored, persistence files quarantined, unconfirmed
authorized_keys lines removed, new/UID 0 accounts locked, admin-group additions undone), checked twice and
executed only by privd; protected accounts and files are never touched; `satsuma-admin geri-alma`
(off needs the admin password). Fake kernel threads (GAP-072); module loads from a file or forced (GAP-073);
io_uring disabled; SELinux permissive at run time reverted; kernel guard restores reported as findings.
