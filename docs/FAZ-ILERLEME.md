# Satsuma faz bitişi — ilerleme notu (2026-11-20)

Sahip: "kalan işlerin tamamını yap; faz bitişi tamamlanana kadar paket verme".
Çalışma ağacı: /home/claude/src/satsuma-core-2.2.37 (sürüm şu an 2.2.62 olarak işaretli, YAYINLANMADI).
Son yayın: 2.2.61 (sahada kurulu, sorunsuz).

## Sahibin envanter kararları (2026-11-20)
- Kullanılmayan modüller engellenecek: amdgpu (+amdxcp, drm_buddy, gpu_sched, drm_panel_backlight_quirks),
  uinput, slhc, nf_conntrack_netlink, arp_tables, ip_tables, iptable_filter, ip6_tables, ip6table_filter,
  bridge, br_netfilter (+stp, llc yalnız bridge kullanıyor), joydev, pcspkr.
- Kalacak: kvm (Boxes flatpak), tun, i2c_dev ve msr (fwupd), ee1004, donanım/sistem/Satsuma.
- Sahip snap network-manager, gnome-boxes, libreoffice kaldırıyor; tarayıcı snap'leri kalıyor.
- modprobe/insmod/rmmod: yüklü olmayan modülü kullanıcı alanından yükleme ve her kaldırma -> durdur;
  çekirdeğin kendi isteği (ppid 2) serbest.
- En sıkı mod istisnaları: ssh grubu (COLL-008, COLL-016, EXFIL-010), rsync (EXFIL-005), posta (COLL-005),
  kube/aws/docker (COLL-018/019/020), sudoedit (SUDO-003), LD_PRELOAD (EVAS-010, ROOT-002), güncelleme
  istisnası -> durdurana döner. Kalır: git/gh (EXFIL-016), sudo su (PRIV-001/028), chattr, gündelik, sistem.
- Kesinlikle varsayım yapma; sahibin kullanımına dair her şey envantere dayanacak.

## Görevler
- [ ] A: modül engelleri + koşullu modprobe + istisna güncellemesi
- [ ] Faz 2: NoNewPrivileges (8 servis), reader ayrı kullanıcı, KILL/NET_ADMIN privd'de, politika imzası
- [ ] Faz 3: satsuma-network, satsuma-netguard, satsuma-netwatch, satsuma-health
- [ ] Faz 4: satsuma-scan, satsuma-onaccess, satsuma-verify, satsuma-hardening, teams+finding
- [ ] Faz 5: tam koruma eklentisi alt paketi; eski satır temizliği; tek sürüm

## 2026-11-20 — Görev A tamamlandı (paket yok)
- snapd kendi snap.* dosyaları: paket işlemi (yalnız /usr/lib/snapd/snapd ikilisi + snap önekli dosya); silinmiş dosya 'already_gone'.
- En sıkı mod: 73 durdurur, 4 modül kuralı koşullu (yüklü olmayan modül yükleme / her kaldırma; çekirdek ppid 2 serbest), 33 istisna. Güncelleme istisnası kaldırıldı (güncellemede en-siki-mod kapat).
- Modül izin listesi: yalnız bu bilgisayarın yüklediği modüller (kilitte /proc/modules'tan öğrenilir, sonraki açılıştan uygulanır; yeni çekirdekte yalnız yeni adlar bir açılık serbest). 4850 modülün ~4750'si engelli.
- fwupd msr/i2c ve open-vm-tools açılış yüklemeleri geçersiz; msr, i2c_dev engelli.
- open-vm-tools engelli (açılış modül yüklemesi geçersiz, vmtoolsd+vgauthd maskeli); KVM/Boxes/qemu/vbox ajanlarına dokunulmaz. Bluetooth: maskelenmez, modülleri serbest, rfkill ile kapalı.
- initramfs: rpm-ostree initramfs-etc ile aynı modprobe/modules-load dosyaları ilk görüntüye taşınır (Fedora imzalı görüntü korunur, önceki dağıtım menüde kalır).
- Modül kilidi 3 dk → 2 dk.
- Testler: 13 failed + 4 error (taban).
Sıradaki: Faz 2 (NoNewPrivileges 8 servis, okuyucu ayrı kullanıcı, KILL/NET_ADMIN yalnız privd, politika imzası).
- Sanal envanter (2026-11-20): open-vm-tools.conf yalnız 'fuse' → geçersiz kılma geri alındı. Sahip kararı: konuk paketleri imajdan çıkarılır (sahip çalıştırır: rpm-ostree override remove open-vm-tools open-vm-tools-desktop virtualbox-guest-additions qemu-guest-agent spice-vdagent hyperv-daemons hypervkvpd hypervvssd hypervfcopyd). vmtoolsd/vgauthd maskeli kalır. rfkill listesi boş: bu bilgisayarda radyo donanımı yok.
- Sanallaştırma: yalnız Flatpak GNOME Boxes (kendi libvirt'i sandbox'ta). Sistem libvirtd kurulmayacak; bridge/stp/llc engelli kalır. (2026-11-20)

## 2026-11-20 — Faz 2 tamamlandı (paket yok)
- NoNewPrivileges: core-dns-refresh, firewall-watch, image, network-modes, network, quarantine-confirm, quarantine-rollback. ostree-firstboot bilerek yok (paket %pre/%posttrans: useradd, SELinux etiketi) — birim dosyasında gerekçe yazılı.
- satsuma-reader: kendi kullanıcısı (sysusers u satsuma-reader), yalnız CAP_DAC_READ_SEARCH; suricata durumu birimden (hidepid).
- KILL: teams/core/sentinel'den kaldırıldı; SATSUMA_PRIVD_ONLY=1 → privd yoksa iş yapılmaz (geri dönüş yok). privd'e terminate_tree eklendi; kill_process/kill_process_tree privd üzerinden.
- NET_ADMIN: teams ve sentinel'den kaldırıldı. core'da faz 3'e kadar kalıyor (NftPolicyManager kendi nft politikasını uzlaştırıyor).
  Not: CAP_KILL'siz root süreç yine root süreçlere sinyal gönderebilir (aynı uid); kullanıcı süreçlerine gönderemez.
- Politika imzası: saf Python Ed25519 (RFC 8032 vektörleri + cryptography ile eşleşir). Özel anahtar yönetici parolasıyla (scrypt + SHAKE akış + HMAC) şifreli; açık anahtar /etc/satsuma-core/policy-signing.pub + root depoda sabitli. İmzasız/değişmiş/anahtarı değiştirilmiş politika kullanılmaz → son imzalı politika + kritik bulgu SATSUMA-POLICY-SIG-002 (saatlik). Anahtar yokken SIG-001 (yüksek).
  Komutlar: sudo satsuma-admin politika durum | anahtar-olustur [--yenile] | imzala (farkları gösterir, "evet" ister).
  Not: installer/configure.py policy.json'u yeniden yazar (paket çalıştırmıyor); elle çalıştırılırsa yeniden imza gerekir.
- Testler: 13 failed + 4 error (taban).
- Bekleyen veri: Boxes köprü ölçümü (kullanıcı Flatpak Boxes kuruyor).
Sıradaki: Faz 3 (satsuma-network, satsuma-netguard, satsuma-netwatch, satsuma-health birleştirme).
- Köprülü VM ağı (sahip 2026-11-20): bridge/stp/llc/tun serbest ve kilitten önce yüklenir; br_netfilter engelli. Sahip: paketi şimdi hazırla, soru sorma, devam et.

## 2026-11-20 — Faz 3–5 değerlendirmesi (sahip kuralı: korumayı zayıflatan karar yok)
Birim dosyaları karşılaştırıldı; plan birleştirmelerinin her biri ya açılış sırasını bozuyor ya da bir parçaya diğerinin yetkisini veriyor:
- satsuma-network: network (network-pre öncesi, erken açılış) / dns-netns (core-dns öncesi) / network-modes (core-dns SONRASI) → tek oneshot sırası imkânsız.
- satsuma-netguard: sentinel (yalnız DAC_READ_SEARCH, privd-only) + otx/subnet (NET_ADMIN, CHOWN) + suricata-otx-guard (sınırsız root) → birleşim sentinel'e root verir.
- satsuma-netwatch: network-identity (yetkisiz, yalnız AF_UNIX/NETLINK) + mitm-watch (NET_ADMIN, PTRACE, DAC_OVERRIDE) → birleşim zayıflatır.
- satsuma-health: self-health sınırlı yetki; maintenance/firewall-watch/flow-guard sınırsız root → self-health zayıflar.
- satsuma-scan: temporary-scan yalnız AF_UNIX ve dar yazma alanı → birleşim zayıflatır. (scan + scan-now aynı; kazanç yok.)
- satsuma-onaccess: listener sıkı (strict, DRS) + clamonacc SYS_ADMIN → zayıflatır.
- satsuma-verify: early-guard (sysinit, ağ öncesi) / boot-inventory (network-online sonrası, 1 saat) → sıra uyuşmaz.
- satsuma-hardening: boot-lockdown (strict, IPAddressDeny, AF_UNIX) + memory-hardening (SYS_ADMIN/PTRACE) → zayıflatır.
- teams + core-finding: core-finding sıfır yetki → teams yetkileri geçer, zayıflatır.
- Faz 5 tam koruma eklentisi: modül kilidi/AIDE/çekirdek profili isteğe bağlı olur → varsayılan koruma düşer.
Yapılan (birleştirmeden): ortak onarım bütçesi satsuma/repair_budget.py — self-health, maintenance, flow-guard, firewall-watch tek defterden izin alır (birim başına 30 dk'da 3, aynı birime 60 sn içinde ikinci yeniden başlatma yok). NoNewPrivileges zaten firstboot dışındaki 50 serviste açık.
Bekleyen diğer işler: hidepid kalıcı (yeniden başlatma testi), TPM sayfası + Kaldır, DeepSeek panel düğmeleri, unhide iş parçacığı teşhisi.
- Sahip 2026-11-20 "ürün zayıflıyor": 30 dk'da 3 sınırı kaldırıldı (self-health, maintenance birim başlatma, firewall-watch, ortak defter). Yeniden başlatma hiç durmaz; 3'ten sonra aralık 2-4-8 dk, en fazla 10 dk. Tekrar tekrar düşen birim → kritik SATSUMA-HEALTH-RESTART-001 (birim başına saatlik). Testler taban.
- hidepid (2026-11-20 ölçüm): yeniden başlatmada kaybolmuş (/proc seçenekleri düz), unhide 0 gizli → 1456 sahte gizli PID hidepid + tarama servisinin süreçleri görememesinden. Çözüm: satsuma-admin hidepid ac|kapat|durum (satsuma/hidepid.py): fstab'a hidepid=invisible,gid=satsuma-proc; polkit, logind, rtkit, NetworkManager, cosmic-greeter ve tarama servislerine /etc drop-in SupplementaryGroups=satsuma-proc; bir sonraki açılışta geçerli; kapat parola ister. Grup sysusers ile (g satsuma-proc). Drop-in'ler pakette değil (grup yokken polkit düşmesin).
- Flatpak "kurulmuyor": flathub hem system hem user kurulumunda → komut hangi kurulum diye soruyor. --user ile kurulmalı.
- 2.2.63 (2026-11-20): DNS saha teşhisi → DoH adları engelli + Firefox canary; OTX güncelleme sunucularını engellemez (fedoraproject.org OTX ile engellenmişti); core-otx sıcak ekleme systemctl reload ile; Satsuma'nın ExecStop çocukları kendi sayılır (dns-netns teardown GAP-023 ile durduruluyordu); yeniden başlatma sınırı yok; satsuma-admin hidepid. Bilinen: satsuma-core-dns dnsmasq NNP yüzünden dnsmasq_t yerine init_t'de (önceden var) — SELinux modülü ya da NNP kaldırma kararı bekliyor.
- 2026-11-20 17:32 rpm-ostree ile imajdan çıkarılanlar (firefox rpm, systemd-resolved, avahi, gssproxy, brltty, ipp-usb, python3-cups, ibus parçaları, python3-langtable) sahibin kendi işlemi — olay değil.
- 2.2.66 (2026-11-20, sahibin haftalık hakkı %3): boot-lockdown cron yazma, yasaklı paket = RemovedBasePackages, tarayıcı politikası güncellemede yenilenir. AÇIK: core-audit, maintenance, mitm-watch, module-lock, temporary-scan düşüyor (2.2.64) — günlük komutu: for u in core-audit maintenance mitm-watch module-lock temporary-scan; do journalctl -b -u satsuma-$u.service -o cat | tail -12; done. Ayrıca: TPM sayfası, DeepSeek düğmeleri, dnsmasq init_t, main'e alma talimatı bekleniyor.
