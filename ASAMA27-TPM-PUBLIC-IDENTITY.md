# Satsuma-core 27. aşama — TPM açık nesne kimliği

## Uygulanan kapsam

Yeni `satsuma/tpm_public_inventory.py`, önceki `tpm_integrity_guard.collect()` envanterinden sonra `tpm2_readpublic -c <doğrulanmış 0x81... tanıtıcı>` ile kalıcı nesnelerin TPM `Name` / `Qualified Name` değerlerini okur. `tpm2_nvreadpublic` ile NV indekslerin yalnız **açık** metaverisini okur ve alanların kanonik temsilinin SHA-256 özetini çıkarır. NV veri içeriği, özel anahtar, yetkilendirme sırrı veya TPM firmware içeriği okunmaz.

Bütün işlemler salt okunur TPM komutlarıdır. İşlemlerin sonucu **yalnızca yerel gözlem** niteliğindedir; aynı makinenin ele geçirilmiş işletim sistemi bu çıktıları değiştirebilir. Doğrulama, TPM sertifikalı attestasyon veya firmware bütünlüğü anlamına gelmez.

## Komut satırı

```
python -m satsuma.tpm_public_inventory
python -m satsuma.tpm_public_inventory --baseline PUBLIC_BASELINE.json --expected-baseline-sha256 BAGIMSIZ_SHA256
```

Harici referans şeması örneği:

```
{"schema":2,"persistent":{"0x81000001":{"name":"000b<64 hexadecimal>","qualified_name":"000b<64 hexadecimal>"}},"nv_indices":{"0x01000001":{"public_metadata_sha256":"<64 hexadecimal>","metadata_source":"local_tpm2_nvreadpublic_not_signed"}}}
```

Bu yalnız örnek şemadır; yer tutucular yerine gerçek envanter kullanılmalıdır. SHA-256 özeti güvenilir, bağımsız kanaldan alınmalı; *hash pin* kaynak kimliğini doğrulayan dijital imza yerine geçmez. Baseline oluşturma otomatik yapılmaz; saldırıya uğramış makinenin mevcut durumu güvenilir referans ilan edilmez.

## Etki ve erişim sınırları

- TPM: `tpm2_getcap`, `tpm2_readpublic`, `tpm2_nvreadpublic` komutlarından başka komut çağrılmaz. `nvread`, `nvwrite`, `evictcontrol`, `clear`, firmware güncelleme yok.
- systemd: yeni servis, yeni yetki veya cihaz ACL değişikliği yok; mevcut panel API isteğiyle çalışır. Kullanıcı/servis TPM'ye okuma izni almamışsa `UNAVAILABLE`/`PUBLIC_READ_FAILED` durumu döner.
- Ağ, DNS, nftables, Suricata, OTX, SELinux, ClamAV, RAM kontrolleri ve kurulum/başlatma davranışları değiştirilmedi.
- API çıktılarına açık `Name` ve NV metaveri hash'leri eklendi; envanter raporu cihaz tanımlayıcı bilgileri içerebilir, saklama/erişim kapsamı sınırlandırılmalıdır.
- İşlem sayısı her kategoride en fazla 128 ile sınırlandı; daha fazla nesne bulunduğunda doğrulama `PUBLIC_INVENTORY_LIMIT` döner. Her komutun zaman aşımı 8 saniye, çıktı boyutu sınırlı. Yoğun envanterlerde panel yanıt süresi uzayabilir; daha sonraki aşamada ayrı kısıtlı işçiye taşınması gerekiyor.
- Geri alma: yeni `tpm_public_inventory.py`, `dashboard_api.py` ve `dashboard_qt/panels/host_provenance.py` entegrasyonunu ve testleri geri almak yeterli; cihazda kalıcı değişiklik yapılmadı.

## Kalan sınırlamalar

* Aynı handle'da nesne değişikliği yalnız gerçek baseline sağlanırsa görülebilir.
* NV açık metaveri özeti **TPM Name değil**, yerel araç çıktı alanlarının SHA-256 özetidir; NV veri içeriğinde metaveri sabit kalırken yapılan değişiklikler bu modülde görünmez.
* `Qualified Name` / `Name` değerleri bağımsız quote/EK/AK sertifikası değildir.
* Envanter alımı sırasında handle seti yeniden okunur, ancak aynı handle'ın çok kısa sürede değiştirilip eski kimliğine dönmesi gibi yarışlar tümüyle engellenmez.
* TPM'ye erişim, servis sandbox/SELinux uyumu, dashboard görsel çalışması ve gerçek Fedora aygıtı doğrulanmadı.
