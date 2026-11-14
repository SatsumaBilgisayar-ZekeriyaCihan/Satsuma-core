# SatsumaBilgisayar OpenPGP imzalama kimliği

Kimlik: **SatsumaBilgisayar**. E-posta adresi verilmediği için uydurma adres
eklenmedi. Anahtar yerel ve internetsiz oluşturuldu; keyserver'a yüklenmedi.

Ana sertifika anahtarı: RSA-4096, certification-only.

```
9134 83F4 FD53 BAD8 8F35 DD39 073C 0B49 B017 69D9
```

İmzalama alt anahtarı: RSA-4096, signing-only.

```
8556 E88B BF8E 4B6D 794B 3594 32DE EF39 BFFD 1BB6
```

Geçerlilik sonu: **22 Ekim 2028**. Tarih dolmadan güvenilir anahtar sahibi
tarafından süre uzatılmalı veya yeni anahtar geçişi yayımlanmalıdır.

## Açık anahtar ve güven başlangıcı

Açık anahtar kaynakta
`packaging/root/etc/pki/rpm-gpg/RPM-GPG-KEY-SatsumaBilgisayar`, RPM kurulumunda
`/etc/pki/rpm-gpg/RPM-GPG-KEY-SatsumaBilgisayar` konumundadır. Pakete açık
anahtar koymak paketi kendiliğinden güvenilir yapmaz. İlk kullanımda tam
parmak izini yukarıdaki bağımsız bilgiyle karşılaştırın; kısa key ID ile
yetinmeyin.

```bash
gpg --show-keys --fingerprint RPM-GPG-KEY-SatsumaBilgisayar
```

Teslim arşivinin detached imzasını ayrı, geçici anahtarlıkla doğrulama:

```bash
verify_home=$(mktemp -d)
chmod 700 "$verify_home"
gpg --no-options --homedir "$verify_home" --batch --import RPM-GPG-KEY-SatsumaBilgisayar
gpg --no-options --homedir "$verify_home" --batch --verify \
  satsuma-memory-update-bundle.tar.gz.asc satsuma-memory-update-bundle.tar.gz
```

GOOD signature ve tam parmak izi birlikte değerlendirilmelidir. Bu geçici
anahtarlıkta ownertrust bilinmediği uyarısı imzanın bozuk olduğu anlamına
gelmez; kimlik güvencesi tam parmak izini bağımsız doğrulamaktan gelir.
İmza doğrulanmadan arşivi çıkarmayın. Çıkardıktan sonra iç dizinde
`sha256sum -c SHA256SUMS` ile dosya özetlerini de kontrol edin.

## Özel anahtarın teslimi

Özel anahtar, kaynak deposuna veya herkese açık teslim arşivine konmadı.
Bulut makinesinde yalnızca kullanıcıya ait 0700 izinli
`/workspace/setup/satsuma-signing/` altında bulunur:

- `gnupg/`: yerel anahtarlık;
- `private/SatsumaBilgisayar-private.asc`: parola korumalı özel anahtar yedeği;
- `private/key-passphrase`: rastgele üretilmiş parola, 0600 izinli;
- `private/revocation-certificate.rev`: iptal sertifikası, 0600 izinli.

Parola sohbet veya test çıktısında gösterilmez. Bu özel dosyaları güvenilir
çevrimdışı imzalama cihazına güvenli biçimde taşıyın. Parola ile anahtar
yedeğini ayrı güvenli ortamlarda saklayın. Paylaşılacak/publish edilecek
ortam snapshot'ında bu özel dizini bırakmayın. Saklandığını doğrulamadan
tek özel anahtar kopyasını silmeyin. İptal sertifikası da herkese açık
dağıtım dosyası değildir; anahtarı iptal edebilir.

İmzalama cihazında kullanıcıya ait 0700 bir GnuPG dizinine özel yedeği
`gpg --homedir /guvenli/gnupg --import /guvenli/SatsumaBilgisayar-private.asc`
ile alın. Gerekirse `gpg --homedir /guvenli/gnupg --edit-key
913483F4FD53BAD88F35DD39073C0B49B01769D9` oturumunda `passwd` ile parolayı
yerel pinentry üzerinden değiştirin. Parolayı komut satırına yazmayın.

## RPM imzalama

Fedora 44 container ortamında native RPM üretildi; rpmsign ile imzalandı
ve yalnızca bu açık anahtarı içeren ayrı RPM veritabanında doğrulandı.
Header OpenPGP V4 RSA/SHA512 imzası, Header SHA256 ve Payload SHA256
denetimleri başarılıdır. Kaynak ve kurulum kiti ayrıca detached GPG imzası
taşır. Gerçek hedef PC üzerinde reboot/SELinux kabul testi ayrı gerekliliktir.

Fedora 44 imzalama makinesinde `rpm-sign` paketi kurulu olmalıdır. Kurulu
değilse yalnızca yerel cache kullanarak `sudo dnf --cacheonly install rpm-sign`
denenebilir. İnternet üzerinden kurulum ayrı izin gerektirir.

Özel anahtarın bulunduğu imzalama makinesinde:

```bash
GNUPGHOME=/guvenli/gnupg rpmsign \
  --define '_openpgp_sign gpg' \
  --define '_openpgp_sign_id 913483F4FD53BAD88F35DD39073C0B49B01769D9' \
  --define '_gpg_name 913483F4FD53BAD88F35DD39073C0B49B01769D9' \
  --addsign satsuma-core-2.1.6-1.fc44.x86_64.rpm
```

Parola yerel pinentry aracılığıyla girilir. Özel anahtar istemci PC'lere
dağıtılmaz. İmzalı RPM'in alıcısında, önce açık anahtarın tam parmak izini
doğrulayıp yalnızca sonra:

```bash
sudo rpm --import RPM-GPG-KEY-SatsumaBilgisayar
rpmkeys --checksig --verbose satsuma-core-2.1.6-1.fc44.x86_64.rpm
```

Beklenen sonuç imza ve digest için doğrulama başarısıdır; `NOKEY`, `NOT OK`
veya yalnızca digest başarısı yayın imzasının doğrulandığı anlamına gelmez.
İmza/GPG kontrollerini kapatan seçenekler kullanılmaz.

Satsuma package-trust deposu politikası ayrıca kaynak URL'si ve depo kimliği
ile tam parmak izi sabitlemesi ister. Gerçek yayın deposu URL'si verilmediği
için repositories politikasına hayali URL veya otomatik genel güven eklenmedi.
