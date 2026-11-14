# SatsumaSecurity 2.2.0 — ilk test sürümü

2.1.6 üzerine kurulur. Denetimdeki (`docs/denetim/SATSUMA-TAM-DENETIM.md`)
açıkların çoğu kapatıldı ve kullanıcının istediği erken açılış korumaları
eklendi. Bu bir **test sürümüdür**: önce sanal makinede ya da yedek bir
bilgisayarda denenmelidir.

## Kapatılan açıklar

- **K1** Kural motoru artık kilitlenemiyor: 64 KB'lık özel komut satırı
  4 dakika yerine 1 saniyenin altında değerlendiriliyor; 38 kalıp doğrusal
  biçime çevrildi; olay başına zaman bütçesi var.
- **K2** Sahte paketle adres engelletilemiyor: yalnızca tamamlanmış TCP
  bağlantıları engelleniyor; DNS sunucuları hiçbir yolla engellenmiyor.
- **K3** Tek OTX kaydı hiçbir adresi engellemiyor (en az 2 kayıt);
  TeamViewer/AnyDesk aktarıcıları OTX yüzünden kesilmiyor.
- **K4/K6** Her program başlatma çekirdekten anında görülüyor; dosya
  izleme açık ve kilitli (`-e 2`): `/etc`, `/usr/bin`, systemd, `/boot`,
  man, `/usr/local`, fontlar, yerelleştirme. İzlemeyi kapatan kurallar
  otomatik etkisizleştiriliyor (aslı yedekleniyor).
- **K5** `sudo`, `env`, `nohup`, `timeout`, `busybox`, `su -c` ve benzeri
  sarmalayıcılar ile `exec -a` ad gizleme kurallardan kaçamıyor.
- **G1–G4, G6** Root servisleri `PYTHON*`/kullanıcı paket dizinini
  okumuyor; arayüz temiz ortamla başlıyor; `PATH` sabit; kural dizini ortam
  değişkeniyle değiştirilemiyor; arşivi köke açan kod kaldırıldı.

## Yeni korumalar

- **Erken açılış envanteri** (`/var/lib/satsuma-core/boot-inventory.json`):
  erken birimler, generator'lar, initramfs, çekirdek parametreleri,
  modprobe/udev/tmpfiles/sysctl; açılıştan 1 dakika sonra ve 6 saatte bir.
- **İmzalı paket doğrulayıcısı** (`signed-verify.json`): Fedora anahtarı
  henüz sabitlenmedi; o zamana kadar `NO_PINNED_KEY` der, hiçbir şeyi temiz
  saymaz.
- **USBGuard açılışın ilk anından** (`usbguard.json`):
  `usbcore.authorized_default=2`; şifreli disk + haricî klavye ya da USB
  üzerindeki kök dosya sisteminde bu parametre uygulanmaz.
- **SHA-256 kara listesi** ClamAV üzerinden: kaldırılan web konsolunun 77
  dosya özeti; her ClamAV taraması bunları yakalar.

## Kaldırılanlar

- Kullanılmayan web konsolu ve HTTP köprüsü (`optional_components/`)
  ağaçtan ve git geçmişinden silindi; yalnızca SHA-256 özetleri kaldı.
- Ölü `install_candidate19_1.sh` kurulum betiği.

## Bu sürümde henüz olmayanlar

K7 (korumayı kapatırken parolanın yeniden sorulması), K8, K9, kritik
dosya kilidi, belge koruması, yeni ağ arayüzü (telefon/tethering) tespiti,
font ve man taraması, yeni arayüz, sabitlenmiş Fedora anahtarı.
