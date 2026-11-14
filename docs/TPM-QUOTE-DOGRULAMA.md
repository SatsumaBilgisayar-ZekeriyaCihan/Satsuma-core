# Satsuma 25 — Offline TPM 2.0 quote doğrulama

Bu modül **kanıt doğrulayıcısıdır**; TPM AK üretmez, quote toplamaz, TPM politikası değiştirmez. TPM2 cihazında çalışma iddiası yoktur. `tpm2_checkquote` (tpm2-tools) kurulu olmalıdır.

## Bağımsız denetleyici akışı

1. Güvenilen bir denetleyici, her deneme için en az 16 bayt kriptografik rastgele nonce üretir. **Nonce'u attester belirlememelidir**. Denetleyici, nonce kullanımını tek seferlik ve zaman sınırlı tutar. Bu yaşam döngüsü henüz Satsuma tarafından yönetilmez.
2. Denetleyici AK açık anahtarının SHA-256 bayt özetini güvenli bir kanaldan alır. Bu özet **AK'nin TPM veya EK ile sertifikalı bağlılığının kanıtı değildir**.
3. Denetleyici, beklenen PCR ölçüm veri dosyasının SHA-256 özetini onaylı, bağımsız kaynaktan alır. PCR dosyasının salt bayt eşitliği hangi firmware/çekirdek/bileşenin güvenilir olduğunu kanıtlamaz.
4. TPM tarafı aynı nonce ile `tpm2_quote` kullanarak `quote.msg`, `quote.sig`, `quote.pcrs` ve `akpub.pem` üretir. `-o` ile üretilmiş **serialized** PCR dosyası kullanılır.
5. Denetleyici (mümkünse farklı güvenilir makinede) aşağıdaki komutu çalıştırır:

```sh
python -m satsuma.tpm_quote_verifier \
  --ak-public akpub.pem --message quote.msg --signature quote.sig \
  --pcr quote.pcrs \
  --expected-ak-sha256 "<BAGIMSIZ_ONAYLI_64_HEX>" \
  --expected-pcr-sha256 "<BAGIMSIZ_ONAYLI_64_HEX>" \
  --nonce-hex "<DENETLEYICININ_ONCEDEN_URETTIGI_32_128_HEX>"
```

Başarılı `tpm2_checkquote` yalnız quote imzası, nonce ve sunulan PCR verisinin imzaya uyumunu ve **haricen pinlenmiş PCR blob eşleşmesini** doğrular. EK sertifikası, AK sertifikasyonu, firmware tedarik zinciri, TPM yaşam döngüsü, PCR değerlerinin güvenilir açılışa ait olması, event-log replay, çalışan işletim sistemi ve rootfs bütünlüğü kapsam dışıdır.

Panelde `EXTERNAL_QUOTE_NOT_SUBMITTED` gösterilir; CLI sonucu otomatik olarak sistem güvenilirliğine yükseltilmez. Çıktı hassas imza / PCR verisi veya komut stderr/stdout içermez. Yollar uygulama tarafından kullanılmadan önce kısıtlı okunur; güvenli olmayan, paylaşılan dizinlerde dosya değiştirme yarışları hâlâ risk oluşturabilir. Yetkisiz kullanıcıyla dosya yolu veya doğrulama girdisi paylaşılmamalıdır.

Kaynaklar: https://tpm2-tools.readthedocs.io/en/latest/man/tpm2_checkquote.1/ , https://github.com/tpm2-software/tpm2-tools/blob/master/man/tpm2_quote.1.md , TCG 2025 Integrity Measurements and Event Log Processing.
