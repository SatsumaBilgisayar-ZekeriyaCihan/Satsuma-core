# Satsuma Core 2.2.61

## En sıkı mod (sahip, 2026-11-20)

"Bu kuralların kayıt alanlarını ve durdurmayanları durdurana çevir." 306 kuralın 110'u yalnız bildiriyordu.
Bunlardan 62 tanesi artık eşleştiği süreci durdurur (sınıf şüpheliye, önem en az yükseğe çıkar,
"yalnız kayıt" kalkar). Orijinal kural dosyaları değişmedi; değişiklik motor tarafındadır. Varsayılan açıktır;
`sudo satsuma-admin en-siki-mod durum | ac | kapat` (kapatmak yönetici parolası ister).

GAP-036, GAP-037, GAP-052 ve GAP-075 bu modda durdurur. Aynı komutta yeni bir `satsuma-core-*.rpm` kuruluyorsa
(`rpm-ostree uninstall satsuma-core --install ...`) güncelleme sayılır ve alarm verilir. GAP-025 (chattr +i, sahibin
kararı) alarm olarak kalır.

## Yalnız bildirmeye devam eden 48 kural

Her biri işletim sisteminin ya da sahibin her saniye yaptığı bir işle eşleşir; durdurmak saldırganı değil
makineyi durdururdu:

* SATSUMA-COLL-005: Thunderbird/Evolution kendi posta dosyalarını okur.
* SATSUMA-COLL-006: Firefox kendi geçmişini okur.
* SATSUMA-COLL-007: Firefox kendi çerezlerini okur.
* SATSUMA-COLL-008: ssh known_hosts ve config okur.
* SATSUMA-COLL-015: Her oturum açma, ls ve sudo /etc/passwd okur.
* SATSUMA-COLL-016: ssh kendi özel anahtarını okur.
* SATSUMA-COLL-017: gpg-agent kendi anahtarlarını okur.
* SATSUMA-COLL-018: kubectl kendi yapılandırmasını okur.
* SATSUMA-COLL-019: aws aracı kendi kimlik dosyasını okur.
* SATSUMA-COLL-020: docker/podman kendi yapılandırmasını okur.
* SATSUMA-DEV-002: Masaüstü (cosmic-comp) klavye ve fareyi /dev/input üzerinden okur.
* SATSUMA-DEV-003: Disk biçimlendirme (udisksd) ve ürün yazılımı güncellemesi (fwupd) ham diske yazar.
* SATSUMA-DEV-004: Süreç değil, aygıt izni bulgusudur; durdurulacak süreç yoktur.
* SATSUMA-DISC-001: uname, whoami, id: gündelik komutlar.
* SATSUMA-DISC-002: ip addr, ifconfig: gündelik komutlar.
* SATSUMA-DISC-003: getent passwd: gündelik komut.
* SATSUMA-DISC-004: ps aux, top, htop: gündelik komutlar.
* SATSUMA-DISC-005: find, locate, ls -la /: gündelik komutlar.
* SATSUMA-DISC-006: systemctl list-units: gündelik komut.
* SATSUMA-EVAS-009: Sahip kilitli dosyayı düzenlemek için chattr -i kullanır.
* SATSUMA-EVAS-010: Steam, gamemode ve snap LD_PRELOAD kullanır; yazılabilir dizinden yükleme GAP-041 ile durdurulur.
* SATSUMA-EVAS-011: Firefox (snap), Steam ve birçok uygulama LD_LIBRARY_PATH ayarlar.
* SATSUMA-EVAS-012: rkhunter, chkrootkit, unhide: güvenlik taramaları (Satsuma da unhide çalıştırır).
* SATSUMA-EVAS-013: Paket betikleri SELinux modülü kurar.
* SATSUMA-EVAS-014: udev sürücü kaldırır.
* SATSUMA-EVAS-015: systemd ve Satsuma açılışta sysctl yazar; çekirdek bekçisi her saniye geri yazar.
* SATSUMA-EXEC-010: Kabuk betiklerinin çoğu eval kullanır.
* SATSUMA-EXFIL-001: dig +short gündelik bir DNS sorgusudur.
* SATSUMA-EXFIL-005: rsync -av /home yedek almanın olağan yoludur.
* SATSUMA-EXFIL-010: ssh -L sahibin kendi kullanımı (saha geçmişi); ters tünel ssh -R GAP-034 ile durdurulur.
* SATSUMA-EXFIL-016: git clone/push (gh kullanıyorsunuz).
* SATSUMA-GAP-025: Sahibin kararı (2026-11-19): chattr +i sıkılaştırma için elle yapılıyor.
* SATSUMA-IMP-004: systemctl stop/disable sahibin servis yönetimidir.
* SATSUMA-LINUX-CLI-004: Yorumlayıcının kabuk açması paket betiklerinde olağandır.
* SATSUMA-LNX-EVAS-001: Sahip kilitli dosyayı düzenlemek için chattr -i kullanır.
* SATSUMA-LNX-EVAS-005: Açılışta sürücüleri modprobe yükler (GAP-073 durdurur).
* SATSUMA-NET-201: Her yeni dinleyen uygulama (Steam, KDE Connect...) durdurulurdu.
* SATSUMA-NET-202: firewalld kendi yapılandırmasını yazar.
* SATSUMA-NET-203: NetworkManager resolv.conf yazar; internet giderdi.
* SATSUMA-PRIV-001: sudo -i / sudo su: sahibin root kabuğu.
* SATSUMA-PRIV-017: Açılışta sürücüleri modprobe yükler; dosyadan/zorla yükleme GAP-073 ile durdurulur.
* SATSUMA-PRIV-028: sudo -i / sudo bash: sahibin root kabuğu.
* SATSUMA-ROOT-001: Açılışta sürücüleri modprobe yükler (GAP-073 durdurur).
* SATSUMA-ROOT-002: Steam, gamemode ve snap LD_PRELOAD kullanır (GAP-041 durdurur).
* SATSUMA-ROOT-003: Her program /dev/null ve terminaline yazar; her şey durdurulurdu.
* SATSUMA-ROOT-004: rkhunter, chkrootkit, unhide: güvenlik taramaları.
* SATSUMA-SUDO-003: sudoedit sahibin dosya düzenleme aracıdır.
* SATSUMA-SUDO-HARD-003: sudo her çalışmada /etc/sudoers okur; sudo durdurulurdu.
