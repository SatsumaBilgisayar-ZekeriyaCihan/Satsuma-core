# Satsuma Core 2.2.38 (2026-11-18)

Durum: kaynak adayı. RPM bu ortamda derlenmedi (rpmbuild yok); Fedora'da
`SATSUMA_RPM_BUILD_ROOT=$(mktemp -d) bash packaging/build.sh` ile derlenir.
Paket imzasızdır. Fedora'da ve Fedora Atomic (rpm-ostree) cihazında denenmedi.

## Hesap dosyası uyarıları (sahibinin bildirimi 2026-11-18)

- "systemd-sysuser" (çekirdek systemd-sysusers adını 15 karaktere kırpar) ve
  COSMIC'te cosmic-greeter için gelen "parola değişti" alarmları:
  SATSUMA-PRIV-026/027 /etc/passwd ve /etc/shadow'a yapılan **her yazmada**
  kritik alarm veriyordu. Gerçek systemd-sysusers ile denendi: yalnızca kilitli
  (`!*`) yeni servis hesapları ekler, var olan parolalara dokunmaz.
- Yeni `satsuma/account_change.py`: hesapların özeti (UID, kabuk, parola
  durumu ve parmak izi; parola özetinin kendisi tutulmaz, 0600) yazma
  değerlendirilirken karşılaştırılır.
  - Kritik (eskisi gibi durdurulabilir): sistem hesabına kullanılabilir/boş
    parola, ikinci UID 0, hesabın UID 0'a taşınması, root parolasının silinmesi.
  - Bildirim (durdurulmaz): var olan parolanın değişmesi (`passwd`).
  - Önemsiz (düşük, durdurulmaz): kilitli yeni hesap, kilitleme, silme, değişiklik yok.
  - Dosya okunamazsa ya da özet yoksa "bilinmiyor": kural özgün önemini korur.
- Panelde başlık artık "Passwd degistirme" değil, değişikliğin kendisi
  (ör. "Hesap dosyası yazıldı (güvenlik açısından önemsiz): satsuma-dns (UID 999):
  hesap eklendi (kilitli, parolasız)"). Kural dosyaları bayt bayt korundu.
- Kimlik ekibi kuralı `/etc/passwd-` gibi yedekleri önekten eşliyor ve aynı
  yazma için ikinci bir "yüksek" alarm veriyordu; düzeltildi.
- `account_guard`: boş parola alanı, `$` ile başlamayan (DES) özet, ikinci UID 0
  hesabı, 65534 ve systemd dinamik kullanıcıları artık yakalanır ve kilitlenir.

## Deep engine bağlantısı (inactive)

- Servis bütünlük denetimini satsuma-engine kullanıcısıyla yapıyordu; denetim
  yalnız root'un okuyabildiği anahtarı okur, servis hiç başlamıyordu. Denetim
  artık `ExecStartPre=+... --verify` ile root olarak önce çalışır.
- Sonuç soketi teams'in kendi çalışma klasöründe (`/run/satsuma-deep-results`):
  `ProtectSystem=strict` altında `/run/satsuma-deep` teams için salt okunurdu.
  Soket ve klasör `satsuma-core` grubuna verilir (motor sonuç gönderebilir;
  önceki grup root olduğu için gönderemiyordu). Çöken teams'in bıraktığı kendi
  soketi temizlenir; başka bir dosya asla silinmez.
- Bağlantı kurulamazsa 30 saniyede bir yeniden denenir.

## Reader ilk kurulumda

- Veritabanları WAL kipinde, reader için /var/lib salt okunur. Hiçbir yazar
  veritabanını açık tutmuyorken (kurulumdan hemen sonra) salt okunur bağlantı
  -shm oluşturamıyor ve her çağrı "attempt to write a readonly database" ile
  düşüyordu (testte yeniden üretildi). -wal yoksa ana dosya değişmez anlık
  görüntü olarak okunur; -wal varsa hata gerçektir ve bildirilir.
- Kurulumun sonunda (kayıt ve yapılandırmadan sonra) reader temiz başlatılır.

## Genel hata taraması

- `operator_service`: cihaz engelle/izin ver kararı ve yöneticinin IP engelini
  kaldırması her çağrıda `UnboundLocalError` veriyordu (yerel içe aktarma).
- Kayıt kataloğunda `onaccess_rescan` ve `deep_rule_review_events` eksikti.
- Yeniden başlayan her servisin sınırlı yeniden deneme kuralı: satsuma-clamonacc,
  satsuma-onaccess-listener, satsuma-deep-engine.
- Kaynak arşivinde betiklerin yürütme izni yoktu; spec artık `/usr/bin/satsuma-*`
  ve `/usr/libexec` betiklerine 0755 verir (önceden kaynaktan alınıyordu).
- Spec yalnızca kaynakta bulunan belgeleri paketler (arşivde 62 belge yoktu).
- RAM-ClamAV kaldırıldıktan sonra kalan eski testler temizlendi; kural sayısı 231.

## Bakım kiti (sahibinin isteği 2026-11-18)

- Yeni `satsuma/maintenance.py`, `sudo satsuma-admin bakim` ve
  `satsuma-maintenance.timer` (açılıştan 15 dk sonra, sonra 6 saatte bir).
  `sudo satsuma-admin tam-kontrol` artık koruma anahtarlarından sonra bakım
  kitini de çalıştırır: ürünün tamamı (paketin kurduğu her birim, imaj, derin
  motor, reader, olay akışı, çekirdek bekçisi, veritabanları, disk, hesaplar,
  servis kimlikleri, dosya izinleri, ostree ilk açılışı).
- Onarım kuralları self_health ile aynı: imza doğrulanmadan onarım yok,
  maskelenmiş birim açılmaz, 30 dakikada en çok üç onarım, kurcalama işaretleri
  yalnızca bildirilir. Ayrıntı: SELF-REPAIR-GUIDE.md.
- self_health'in 14 servislik listesinde derin motor yoktu; bakım kiti onu da onarır.

## Fedora Atomic (rpm-ostree)

- Yeni `satsuma/ostree.py`: çekirdek bağımsız değişkenleri `rpm-ostree kargs`
  ile (kernel_profile, usb_guard); normal Fedora'da grubby, değişiklik yok.
- ptrace_guard: salt okunur /usr altındaki dosya, aynı adlı /etc/sysctl.d
  dosyasıyla geçersiz kılınır.
- MITRE/KEV tanımları /usr/share/satsuma-core/tanim altına da paketlenir
  (rpm-ostree /var altındaki dosyaları atar).
- rpm-ostree paket yöneticisi sayılır (exec_guard, kernel_guard).
- İmaj bağlama denetimi gerçek yolu sorar (/opt -> var/opt).
- ostree'de USB çekirdek bağımsız değişkeni konmaz: rpm-ostree'nin kaldırma
  betiği onu geri alamaz ve kaldırmadan sonra USB klavye/fare ölü kalırdı.
  USBGuard servis başladığı andan itibaren korur.

## Açık konular

- satsuma-core-windows hâlâ kaldırılmış `satsuma.ram.engine`'i içe aktarıyor
  (DEVAM-TALIMATI adım 2'nin Windows kısmı yapılmadı); Windows sürümü derlenmez.
- ostree'de kaldırmadan önce USBGuard ayarları geri alınmaz:
  `rpm-ostree uninstall` öncesi `sudo python3 -I -B /opt/satsuma-core/main.py --usbguard-restore`.
- Silverblue/Kinoite/COSMIC Atomic cihazında kurulum denenmedi; kullanıcı
  hesaplarının (sysusers) rpm-ostree katmanında oluşması cihazda doğrulanmalı.
- `satsuma/policy_cli_legacy.py` var olmayan `PolicyStore`'u içe aktarıyor;
  hiçbir yerden çağrılmıyor.

## RAM-001 notu

- `rwx_kept`: " (deleted)" ekli program, yalnızca aynı yolda yeniden root'a ait
  ve başkasının yazamadığı bir dosya varsa (çalışırken paket güncellemesiyle
  değişmişse, ör. dnf update sırasında açık Firefox) kaydedilir; gerçek akış
  zaten böyle çalışıyordu, kod ve test bununla uyumlu hâle getirildi. Gizlenmek
  için silinen ya da /tmp'den çalışan program yine durdurulur.
