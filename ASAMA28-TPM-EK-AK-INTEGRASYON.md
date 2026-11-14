# Aşama 28 — TPM EK sertifika zinciri ve quote kanıt korelasyonu

## Kaynakta uygulanmış

- `satsuma/tpm_trust_bundle.py`: çevrimdışı EK sertifikası/üretici CA zinciri doğrulama, dışarıdan verilmiş CA sertifika SHA-256 pini, EK açık anahtar SPKI SHA-256 pini ve mevcut `tpm_quote_verifier` çağrısının birleştirilmesi.
- Tek doğrulayıcı çalıştırması EK ve quote sonuçlarını **ayrı** tutar. İki kontrol de başarılı olsa `ek_ak_binding_verified`, `platform_identity_verified`, `trusted_boot_verified` alanları **false** kalır.
- `satsuma/dashboard_api.py`, `satsuma/dashboard_qt/panels/host_provenance.py`: dış EK kanıtı sunulmadığında `EXTERNAL_EK_CERTIFICATE_NOT_SUBMITTED` durumunu açık gösterir; başarılı gibi göstermez.
- `packaging/satsuma-core.spec`: çevrimdışı doğrulama için `python3-cryptography` ve `openssl` paket bağımlılıkları eklendi. Yeni paket kurulumu henüz gerçekleştirilmedi.
- `tests/test_tpm_trust_bundle.py`: gerçek OpenSSL ile geçerli test sertifika zinciri; bozuk CA, yanlış pin, symlink reddi; EK ve quote kanıtlarının AK/EK kimlik bağı olarak sunulmaması.

## Kullanım (ayrı doğrulayıcı makinede)

`python -m satsuma.tpm_trust_bundle --ek-certificate EK.pem --manufacturer-ca trusted-manufacturer-ca.pem --expected-ca-sha256 <bagimsiz-pin> --expected-ek-spki-sha256 <bagimsiz-pin> --ak-public AK.pem --message quote.msg --signature quote.sig --pcr quote.pcr --expected-ak-sha256 <bagimsiz-pin> --expected-pcr-sha256 <bagimsiz-pin> --nonce-hex <bagimsiz-benzersiz-nonce>`

Bütün pinler farklı güvenilir kanaldan edinilmeli. Aynı şüpheli sistemden alınan pinler bağımsız güven kökü oluşturmaz. Nonce benzersizliği ve ömrü bağımsız doğrulayıcı sorumluluğundadır.

## Kalan kritik engel

TPM EK özel anahtarına sahip olunduğunu ve AK'nin aynı TPM'ye bağlı olduğunu gösterecek **TPM credential activation** (`MakeCredential`/`ActivateCredential`) protokolü bu aşamada **uygulanmadı**. EK sertifikası zinciri ve AK quote imzasının birlikte başarılı olması tek başına AK/EK bağı kanıtı değildir. EK sertifika doğrulaması için gerçek üretici CA'sı ve referans imzaları da hedef cihaz üzerinde doğrulanmadı. Gerçek PCR değerinin güvenilir ölçümlü açılışı gösterdiği de kanıtlanmadı.

Kayıtlar salt okunur; TPM, boot zinciri, SELinux, DNS, ağ filtreleri, Suricata, OTX, ClamAV ve servisler değiştirilmedi. RPM içerik ve bağımlılık tanımı değişti; kurulumda bunların tedarik edilmesi gerekir. Geri alma: önceki ZIP kaynak sürümüne dönmek; RPM dağıtımı yapılmışsa ayrı paket geri alma prosedürü gerekir.
