# Satsuma Core 2.2.62

## Saha öz testi: `sudo satsuma-admin oz-test`

Saha 2026-11-19: dosya karantinası dört sürüm boyunca çalışmadı, testler ise geçti; testler privd'nin yerine
geçiyor, gerçek istemciyi hiç kullanmıyordu. Öz test her koruma yolunu bu makinede, zararsız hedeflerle ve
gerçek zincirle (algılayıcı → kural → karar → privd → etki) çalıştırır, her adımdan sonra temizler:

| Yol | Ne yapılır | Geçme koşulu |
|---|---|---|
| privd | Gerçek soketten, dosya yolu taşıyan istek (değişiklik yok: geçersiz yol) | privd yanıt verir ve reddeder |
| Süreç durdurma | `sleep 120; curl http://127.0.0.1:9/... \| sh` kalıbında süreç (nobody olarak) | 45 sn içinde Satsuma durdurur |
| Dosya karantinası | `/etc/cron.d/oztest-…` (tek yorum satırı) | 60 sn içinde karantinaya alınır |
| Güvenlik duvarı | Satsuma'nın OTX koruma tablosu silinir | 75 sn içinde geri gelir; gelmezse test kendisi kurar, KALDI |
| Hesap kilitleme | Geçici `oztest…` hesabı | 45 sn içinde kilitlenir; hesap her durumda silinir |

Durdurma politikası kapalıysa privd dışındaki adımlar atlanır. Sonuç kayda yazılır (`self_test_last`).

## Saatlik privd denetimi

Teams saatte bir gerçek istemciyle privd'ye dosya yolu taşıyan bir istek gönderir; yanıt gelmezse kritik
SATSUMA-PRIVD-001 bulgusu verir. Bir koruma yolunun sessizce kırık kalması artık en geç bir saatte görünür.

## Envantere göre sıkılaştırma (sahip kararları 2026-11-20)

- **Modül izin listesi.** Çekirdekte 4.850 modül var, bu bilgisayar ~100'ünü kullanıyor. Yalnız bu bilgisayarın
  kendi yüklediği modüller yüklenebilir; geri kalan her modül `install X /bin/true` ile engellenir
  (`/etc/modprobe.d/satsuma-module-allowlist.conf`). Liste modül kilidi kapanırken `/proc/modules`'tan öğrenilir,
  sonraki açılıştan uygulanır. Yeni çekirdekte yalnız adı yeni olan modüllere bir açılışlık izin verilir.
  Bluetooth modülleri ve köprülü sanal makine ağı (`bridge`, `stp`, `llc`, `tun`) serbesttir.
- **initramfs.** Fedora'nın genel ilk açılış görüntüsü 835 modül ve kendi modules-load.d dosyalarını taşır.
  `rpm-ostree initramfs-etc` aynı engel dosyalarını görüntüye ekler (Fedora'nın imzalı görüntüsü korunur;
  değişiklik yeni dağıtım olarak bir sonraki açılışta geçerli olur, önceki dağıtım menüde kalır).
- **Modül kilidi** açılıştan 2 dakika sonra (önce 3). Köprü ve tun kilitten önce yüklenir.
- fwupd'nin `msr`/`i2c_dev` açılış yüklemeleri geçersiz, bu modüller engelli. Kullanılmayan modüller
  (amdgpu, uinput, slhc, eski iptables, br_netfilter, joydev, pcspkr) engelli.
- open-vm-tools servisleri (vmtoolsd, vgauthd) maskeli. Sahip konuk paketlerini imajdan çıkarır.
- **En sıkı mod:** 73 kural durdurur (ssh, rsync, e-posta, kubectl/aws/docker, sudoedit, Steam araçları bu
  bilgisayarda kullanılmıyor), 4 modül kuralı koşullu: kullanıcı alanından **yüklü olmayan** modülü yükleme ve
  her kaldırma durdurur; çekirdeğin kendi isteği ve Satsuma'nın kendi ön yüklemesi durdurmaz. 33 istisna kalır.
  **Güncelleme istisnası kaldırıldı:** Satsuma güncellemesinden önce `sudo satsuma-admin en-siki-mod kapat`
  (parola), sonra `ac`.
- snapd'nin kendi `snap.*` dosyaları (yalnız paketli snapd ikilisi) paket işlemi sayılır; silinmiş dosya
  "zaten yok" olarak kaydedilir, başarısızlık değil.

## Faz 2: yetki

- **Politika imzası.** `/etc/satsuma-core/policy.json` yalnız sahibin Ed25519 imzasıyla (`policy.json.sig`)
  kullanılır. Özel anahtar yönetici parolasıyla şifreli; açık anahtar `/etc/satsuma-core/policy-signing.pub`
  ve root depoda sabitli. İmzasız, imzadan sonra değişmiş ya da anahtarı değiştirilmiş politika kullanılmaz:
  son imzalı politika sürer, saat başı kritik SATSUMA-POLICY-SIG-002. Anahtar yokken SATSUMA-POLICY-SIG-001.
  Kurulumdan sonra bir kez:
  `sudo satsuma-admin politika anahtar-olustur` ve `sudo satsuma-admin politika imzala`
  (imzala, kullanılan politikadan farkları gösterir ve "evet" ister).
- **Süreç durdurma ve adres engelleme yalnız privd'de.** teams, core, sentinel CAP_KILL'siz; teams ve sentinel
  CAP_NET_ADMIN'siz (core faz 3'e kadar kendi nft politikası için tutar). `SATSUMA_PRIVD_ONLY=1`: privd yoksa
  iş yapılmaz, geri dönüş yok. privd'ye `terminate_tree` eklendi.
- **NoNewPrivileges:** core-dns-refresh, firewall-watch, image, network-modes, network, quarantine-confirm,
  quarantine-rollback. ostree-firstboot bilerek hariç (paket kurulum betikleri).
- **satsuma-reader** kendi kullanıcısıyla, yalnız CAP_DAC_READ_SEARCH ile çalışır.
