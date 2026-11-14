# Aşama 29 — AK'nin EK ile aynı TPM'de kullanıldığının kanıtı

## Güven modeli

Satsuma `tpm_credential_activation` bileşeni **bağımsız doğrulayıcı makinede** çalışır. TPM aygıt dosyasını açmaz ve TPM'ye hiçbir komut göndermez. `tpm2_makecredential --tcti=none`, EK sertifikasından alınan açık anahtar ve AK'nin TPM2B_NAME değeriyle **32 baytlık rastgele** sır için şifreli challenge oluşturur. EK sertifikası, bağımsız pinlenmiş üretici CA ile; EK SPKI ve AK Name de bağımsız pinlerle doğrulanır.

Kullanıcının yönettiği **hedef cihazdaki ayrı TPM aracı**, mevcut EK ve AK bağlamlarını kullanarak `tpm2_activatecredential` çalıştırabilir. Bu komut TPM ile etkileşir fakat kalıcı TPM nesnesi, NV kayıtları, firmware veya anahtar üretimi yapmaz; cihazın TPM politikası oturum gerektirebilir. Satsuma otomatik AK/EK anahtar oluşturmaz veya TPM komutu çalıştırmaz. EK/AK nesnelerinin önceden kullanılabilir olması gerekir. Otomatik ve yetkisiz aktivasyon yoktur.

Sır doğru geri alınırsa doğrulayıcı, belirtilen AK **Name** ve EK public için credential activation'ın gerçekleştiği sonucunu verir. **Bu tek başına** ayrı bir quote PEM dosyasının aynı AK Name'den türetildiğini, TPM üretici sertifikasının güncel firmware'i kanıtladığını, AK/EK sahipliğinin üretici onaylı olduğunu veya Secure Boot'un güvenilirliğini kanıtlamaz. Tam attestasyon için quote açık anahtarı ile AK Name'in doğrulanmış TPMT_PUBLIC üzerinden bağlanması ve yetkili üretici EK/AK referansı gerekir.

## Bağımsız doğrulayıcıda challenge oluşturma

`python -m satsuma.tpm_credential_activation issue --state-dir <PRIVATE_DIR> --ek-certificate <EK_CERT.pem> --manufacturer-ca <PINNED_CA.pem> --expected-ca-sha256 <CA_FILE_SHA256> --expected-ek-spki-sha256 <EK_SPKI_SHA256> --ak-name-hex <TPM2B_NAME_HEX> --expected-ak-name-sha256 <INDEPENDENT_AK_NAME_SHA256>`

`state-dir` yalnız doğrulayıcının erişebildiği, kendisinin sahip olduğu `0700` özel dizin olmalıdır. Satsuma rastgele challenge kimliği, `.credential` şifreli blob ve `.pending` bekleyen durum dosyası oluşturur. Ham sır, kalıcı dosyaya yazılmaz; `tpm2_makecredential` işlemine stdin üzerinden gönderilir. Challenge ömrü 300 saniyedir.

## Hedef cihazdaki isteğe bağlı operatör işlemi

Mevcut AK ve EK TPM bağlamlarının sağlandığı, doğru yetkilendirmeyle kurulmuş oturum kullanılır. `tpm2_activatecredential -c <EXISTING_AK_CONTEXT> -C <EXISTING_EK_CONTEXT> -i <CREDENTIAL_BLOB> -o <ACTIVATED_SECRET>` çağrısı TPM özelliklerine göre bir policy session gerektirebilir; `tpm2-tools` dökümantasyonuna başvurulmalıdır. EK/AK üretimi, `EvictControl`, `NV_Write`, `Clear` veya firmware güncelleme bu iş akışının parçası değildir.

## Bağımsız doğrulayıcıda yanıtı doğrulama

`python -m satsuma.tpm_credential_activation verify --state-dir <PRIVATE_DIR> --challenge-id <ID> --activated-secret <ACTIVATED_SECRET>`

Yanıt kabul edilse de reddedilse de challenge `.pending` dosyası tüketilir. Aynı challenge ikinci kez kabul edilemez. Uygulama tek doğrulayıcı proses ve erişimi yalnız kendi UID'sinde olan özel dizin için tasarlanmıştır; dağıtık doğrulayıcı, güvenilmeyen paylaşımlı dosya sistemi veya eşzamanlı çok düğümlü kullanım için veritabanı tabanlı tek seferlik tüketim gerekir.

**Gizlilik:** `ACTIVATED_SECRET` 32 baytlık kısa ömürlü bir güven kanıtıdır; rapora, sistem günlüğüne veya Git deposuna koymayın. İşlem bitince güvenli biçimde yönetilmelidir. `.consumed` ve `.credential` dosyalarında ham sır bulunmaz. Dosyalar ve referanslar güvenli kanaldan aktarılmalıdır.

## Doğrulama kapsamı

- Kontrollü test: sahte `tpm2_makecredential` çıktısı ve aktivasyon yanıtı ile başarı, reddetme, sürenin aşılması ve tekrar deneme.
- Gerçek cihaz testi: **yapılmadı**. Gerçek `tpm2_makecredential` ikilisi de bu ortamda mevcut değildi.
- Hedef Fedora TPM'sinde AK/EK bağının gerçekten kanıtlandığı ileri sürülmez.

Kaynaklar: https://github.com/tpm2-software/tpm2-tools/blob/master/man/tpm2_makecredential.1.md ve https://tpm2-tools.readthedocs.io/en/stable/man/tpm2_activatecredential.1/
