# Satsuma Core 2.2.54 — kapsam: görülmeyen saldırılar ve sessiz kurallar

Kaynak: sahadaki makinenin veritabanı analizi (2026-11-19). 1.175.296 audit
kaydı, 66.698 farklı olay Satsuma'nın kendi kural motorundan geçirildi; 109
Linux saldırı tekniği yerel olarak denendi. Sahibinin isteği: korumayı
zayıflatan hiçbir değişiklik yok, saldırı sayılabilecek her komut için kural.

## Yeni kurallar (rules/coverage_gaps.yaml, 50 kural, toplam 281)

109 saldırı tekniğinden önce 49'u durduruluyordu, 51'inin hiç kuralı yoktu.
Şimdi 101'i durduruluyor, 2'si alarm veriyor.

- Ters shell: Python, Perl, PHP, ncat/netcat `-e/--exec`, mkfifo + ağ aracı,
  `openssl s_client`, kabuğun `/dev/tcp` ile bağlantı açması.
- İndirip /tmp'den çalıştırma, /tmp ve /run/user'dan program çalıştırma,
  çekirdek iş parçacığı kılığına girmiş kullanıcı programı.
- Kalıcılık: `ld.so.preload`, udev kuralı, binfmt_misc, `systemd-run --on-*`,
  oturum ortamı/kabuk başlangıç dosyaları.
- Hesap/yetki: UID 0 ya da kopya UID ile hesap, yeni hesap, wheel/sudo grubuna
  ekleme, komutla NOPASSWD ekleme, SUID biti, tehlikeli `setcap` yetenekleri,
  ayrıcalıklı kabuk (`sh -p`), yazılabilir klasörden `LD_PRELOAD`.
- Savunma atlatma: `auditctl -D/-e 0/never`, clamd/auditd/suricata/Satsuma
  süreçlerini öldürme, Satsuma güvenlik duvarı tablosunu silme, günlük
  temizleme, `/proc` üzerine bind mount, `/etc/selinux/config` yazma, zaman
  damgası sahteleme, shred, sistem dosyasından `chattr -i`.
- Kimlik bilgisi: `/proc/PID/mem`, `/dev/input` okuma, unshadow/john/hashcat,
  hydra vb., özel anahtar araması, strace/ltrace `-p`.
- Keşif/tünel: nmap/masscan, chisel/ngrok/frp/ligolo/cloudflared tunnel,
  `ssh -R`, `sudo -l`.
- Etki: kök dizini silme, ostree geri dönüş kopyasını silme, kapsayıcıdan ana
  makine köküne erişim.
- Satsuma'ya saldırı: Satsuma'yı kaldırma, veritabanını silme, yapılandırmayı
  Satsuma dışından değiştirme.

Kalıplar çekirdeğin bildirdiği komut satırına göre yazıldı (tırnaksız,
boşlukla birleştirilmiş argümanlar). Eski kurallardaki tırnak bekleyen
kalıplar (EXEC-002..005, C2-001'in bir kısmı) gerçekte hiç eşleşmiyordu; yeni
kurallar bu saldırıları kapsıyor.

Yalnızca alarm (durdurmaz): GAP-025 `chattr +i` (sahibi bunu sertleştirme için
elle de yapıyor), GAP-036 Satsuma'yı kaldırma (güncellemede sahibi yapıyor),
GAP-037 Satsuma veritabanını silme. `satsuma.enforcement.ALARM_ONLY`.

## Sessiz kurallar artık iz olarak kaydediliyor

231 kuralın 106'sı eşleşse bile hiçbir yere yazılmıyordu (4 Kasım kararı:
yalnızca şüpheli süreçler yazılır). Bunların yüksek ve kritik olanları
(SSH özel anahtarı okuma, çekirdek modülü yükleme, parolasız sudo, klavye
kaydı, ham diske yazma vb.) artık `trace_only` iz olarak kaydediliyor:
görünür, kanıt olur, programı durdurmaz.

## Görülmeyen yerler artık izleniyor

- Audit ev klasörlerindeki kalıcılık ve anahtar girişlerini izler: `.ssh`
  (okuma dahil), `.bashrc`, `.profile`, `.bash_profile`, `.zshrc`,
  `.config/autostart`, `.config/systemd/user`, `.config/environment.d`,
  `.local/share/systemd/user`; aynıları root için. Ayrıca `/var/spool/cron`
  ve Atomic'te `/var/usrlocal`. Ev klasörünün tamamı izlenmez.
- Fedora Atomic bağlantıları (`/home`, `/root`, `/usr/local`) dağıtım
  bağlantısı sayılır; izleme gerçek yola yapılır.
- Kurallar `/var/home` ile `/home`'u, `/var/roothome` ile `/root`'u aynı yer
  olarak görür. authorized_keys, .bashrc, autostart ve kullanıcı systemd
  kuralları Atomic'te ilk kez çalışır.
- Audit: kuyruk 8192 (sahada 64'tü), `--loginuid-immutable` (root bir süreç
  oturum kimliğini değiştirip iz silemez).
- Kural motorunun süre sınırı işlemci süresiyle ölçülür; yoğun makinede sıradan
  bir `ps` komutu geri kalan kuralların atlanmasına yol açmaz.

## Saha hataları

- Anlık koruma (clamonacc) clamd'ye bağlanamıyordu: servis `virusgroup`
  grubuna alındı; kurulum SELinux `antivirus_can_scan_system` ayarını açar.
- `user.max_user_namespaces=0` yüzünden `PrivateUsers=` kullanan servisler
  başlamıyordu: accounts-daemon, chrony-wait, colord, fstrim, nm-priv-helper,
  pcscd için izin dosyası (çekirdek ayarı sıkı kalır).
- PPP engeli `/bin/false` yerine `/bin/true` ile: her açılıştaki
  systemd-modules-load hatası biter, PPP yine yüklenmez.
- `satsuma-memory-hardening` coredump soketiyle başlatma döngüsü kuruyordu.
- Açılış ilişkilendiricisi bilinen zararsız çekirdek mesajlarını (Satsuma'nın
  kendi `debugfs=off` ayarından gelenler dahil) "kritik sorun" saymaz.
- Sağlık: anlık koruma çalışmıyorsa ve ostree eski kopyaları temizleyemiyorsa
  (sahada değiştirilemez dosyalar yüzünden 26 kopya birikmişti) bildirilir.

## Bilinen sınır

Tek seferlik komutlar (nft flush, useradd, tee) milisaniyede biter; durdurma
çoğunlukla geç kalır. Bu sürüm onları görür, kaydeder ve alarm verir; etkiyi
geri alma (karantina, hesap kilitleme) sahibinin kararını bekliyor.
