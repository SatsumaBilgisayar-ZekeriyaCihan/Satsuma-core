# SatsumaSecurity — birleşik geliştirme ve güvenlik denetimi

**Tarih:** 31 Ekim 2026 · **Dal:** `inceleme-2026` · **Sürüm:** 2.2.15.

Bu rapor DeepSeek, ortak tespit/müdahale paketi, GPG, 228 Smart Rule,
çoklu kanıt, bellek kapsamı, Qt6 ve Suricata/OTX/paketleme çalışmalarını birlikte
kapsar. Üretim Fedora kurulumu, nftables/NFQUEUE 100/201, DNS, SELinux,
ptrace_scope veya çalışan servisler değiştirilmedi. `main` dalına merge/push yok.
Dal bu teslimde yereldir; uzak GitHub dalına push yapılmadı.

## 1. Commitler ve doğrulama sınırı

| Commit | İçerik |
| --- | --- |
| `9441354429a7b81227fc80ed46eb2a3fc69bde54` | Bu çalışma öncesi referans; önceki Reader düzeltmesi |
| `10bf05853fe299464b41129f11f42446c8d128af` | AI ortak paket, yetkili inceleme/imza/aktivasyon, kural bazlı özgün kanıt kapısı, privd fixture düzeltmesi |
| `87e9dc81b291a960c5b2be65f03b3836fe792cee` | Sınırlı yürütülebilir bellek incelemesi, ayrık bayt kategorileri ve geçersizleştirme |
| `e4987a94b8aa6fa156df9c688f39c6e10c54aece` | Gerçek Qt6 arayüzü, Suricata anomali sınıflandırması, OTX/nft görünürlüğü ve Fedora payload kapsamı |

Son rapor/kanıt commitinin SHA'sı teslim mesajında belirtilir; bu dosyanın kendi
commit SHA'sı dosyanın içine kendine referans verecek biçimde yazılmaz.

## 2. Son test sonucu

**513 ana test: 512 PASS, 1 FAIL (aşağıdaki tarihsel artefakt engeli), 0 SKIP, 0 ERROR. Ayrıca 5 alt test PASS.** Beklenmeyen hata: 0. Pytest çıkış kodu 1; bütün koşu yeşil olarak sunulmaz. Test edilen ürün kodu: `e4987a94b8aa6fa156df9c688f39c6e10c54aece`.

- Önceki `94 PASS / 1 FAIL` grubundaki **aynı 95 test, 95 PASS** oldu.
  Sonraki tüm yeni negatif/hash/bellek testleri de geniş koşuya dahil edildi.
- **Smart Rule karşılaştırması: 228/228 PASS, unexpected_changes=0.**
- `BLOCKED — missing historical artifact`:
  `tests/test_release_script.py::test_published_digest_matches_the_package_everywhere[2.2.12]`.
  Eksik dosya: `release/2.2.12/satsuma-core-2.2.12-1.fc44.x86_64.rpm`.
  Dosya referans commitin Git ağacında da yoktur. Test kaldırılmadı, xfail/skip
  yapılmadı, beklenen özet değiştirilmedi ve yerine paket üretilmedi.
- Canlı süreç sonlandıran eski testler (`test_auto_process.py` ve
  `test_memory_validation.py` içindeki canlı durdurma senaryoları gibi)
  kullanıcının müdahalesiz test koşulu nedeniyle bu seçilmiş grupta çalıştırılmadı.
  Bunlar başarılı ya da atlanmış test olarak sayılmadı. Aynı güvenlik kararları
  yeni sentetik/depo/FakeWorker testlerinde doğrulandı.

Tekrar çalıştırma (yeni güvenlik testlerinde deselection yok):

```bash
cd /workspace/SatsumaSecurity
PYTHONPATH=. /workspace/setup/satsuma-venv/bin/python tools/run_integrated_checks.py
```

Araç, pytest'in çıkış kodunu korur; eski artefakt eksikse süreç 1 döndürür.
`/workspace/artifacts/integrated-tests.xml` ve `integrated-summary.json` ham
sonuçları saklar. `BLOCKED` sınıflaması başarısız testi geçmiş gibi göstermez.

## 3. 228 kuralın bağımsız önce/sonra karşılaştırması

Referans: `9441354429a7b81227fc80ed46eb2a3fc69bde54`.
Araç: `tools/audit_rule_behavior.py`. Önceki motor, politika ve aksiyon sözleşmesi
`git show <ref>:<dosya>` ile yüklenir. Önceki kural dosyaları Git ağacından
**ayrı geçici dizine** çıkarılır; yeni motor çalışma ağacındaki `rules/` dizinini
okur. Önceki politika eski canonical action eşlemesini kullanır.

Kanıt: `docs/RULE-BEHAVIOR-AUDIT-2026.json` içindeki
`baseline_source.materialized_from_git=true`, `uses_worktree_rule_files=false`,
`current_source.separate_from_baseline_directory=true` ve dosya bazlı eski/yeni
SHA256 değerleri. Referans `rules` Git ağacı:
`ca1b3bbdb87a1ddeaf2de943cc8c1212a4be9f45`.

Her kural için gerçek matcher koşullarından pozitif sentetik olay hazırlanır;
pozitif olayın o kuralı veya dedup içindeki matched_rules kimliğini gerçekten
ürettiği doğrulanır. Pozitif, negatif, yanlış kaynak ve eski olay aynı iki
motorda çalıştırılır: **912 karşılaştırma**. Tespit kimliği/sınıfı/önemi/skoru,
aksiyonlar, kanıt planı, gerçek broker'ın metadata-evidence çıktısı ve mevcut
müdahale politika kapısı kararı karşılaştırılır. Hiçbir komut metni çalıştırılmaz.

Sonuç: 228 önce/sonra kural, 228 benzersiz kimlik, 228 pozitif tanık,
0 tanıksız kural, 0 beklenmeyen davranış farkı. Kaynak YAML aksiyonları da
bayt/dosya ve kayıt bazında değişmedi. Yeni hash/provenance alanları ek metadata'dır;
gizli bir aksiyon genişlemesi değildir.

**Sınır:** Bu karşılaştırma politika kararını ölçer; gerçek PID kimliği,
sinyal teslimi veya ağ DROP sonucu değildir. Hedef güvenliği ve müdahale öncesi
kontroller ayrı izole primitive testleriyle doğrulandı. `unexpected_changes=0`,
aşağıdaki açık politika değişikliklerinin de eşdeğer olduğu anlamına gelmez.

Envanter: `docs/RULE-RESPONSE-INVENTORY-2026.csv` ve
`schemas/rule-response-catalog-v1.json`. Her kuralın kimliği/adı, telemetrisi,
eşleşmesi, mevcut aksiyon/uygunluğu, önerilen müdahalesi, kanıt/tazelik/hedef
koşulları, yanlış pozitif riski, kapasite boşlukları ve geri dönüşü ayrı kayıttadır.
Öneriler, desteklenen aktör telemetrisi ve gerçek doğrulama yollarına dayanır;
yalnız isim/önemden durdurma üretilmez. Envanter önerileri `applied=false`'tır.

## 4. Tek tespit politikası ile zorunlu çoklu kanıtın birlikte uygulanması

`enforcement.eligible/automatic_allowed` uygunluk ön elemesidir; yetki vermez.
Varsayılan 228 kural politikası topluca değiştirilmedi. Yetkili operatör
`rule_response_set_requirement` ile **tek kural kimliği ve içerik hash'ine**
bağlı koşul kaydeder. Bu politika değişikliği mevcut Operator oturumu ve yeniden
yönetici doğrulaması gerektirir. Bir kurala min_sources=2/3 atanırsa genel
tek-tespit veya user_enforcement politikası bu şartı geçersiz kılamaz.

Karar kapısı, güvenilir Store'daki `normalized` kayıtlarını ve onların özgün
`events` kayıtlarını yeniden okur. Doğrulayıcı:

- Aynı normalized/raw ID'yi veya yalnız kaynak etiketi değiştirilmiş aynı
  ham içeriği iki bağımsız kanıt saymaz.
- Gerçek kaynak ailesini özgün kayıtla karşılaştırır; kaynak adları listesi,
  `multi_source_verified` veya AI beyanı yeterli değildir.
- Aynı PID + çekirdek starttime (jiffies) + executable kimliği ve en fazla
  60 saniyelik, gelecekten olmayan gözlem ister.
- Ağ hedefinde aynı açık target_ip ve uygun ağ sensörünü, dosya hedefinde
  yol/içerik kimliğini ister. DNS sorgusundan kendiliğinden saldırı hedefi üretmez.
- Belirli sensör ailesi zorunluysa başka bir geçerli aileyle yerine koymaz.
- `rule_content_hash` / `matched_rule_hashes` değerlerini onaylı kural hash'iyle
  bağlar. GPG doğrulanmış AI kuralında hash imzalı detection'ın kanonik hash'idir.

Kapı AutoAction, auto_process, auto_network ve ilgili manuel/broker yollarına
bağlandı. `kill_process`, `kill_process_tree`, `auto_kill`, `terminate_process`
girişlerinde ve sinyalden hemen önce tekrar denetlenir. Privd üzerinden aktarım
öncesi ve sunucu tarafı aynı ResponseWorker denetimi geçerlidir. Aynı yetkili
root ilkelinin kimliksiz doğrudan kullanımını dış saldırganın erişebileceği yeni
bir API olarak açan değişiklik yapılmadı. Mevcut oturum, pause, replay, korunan
süreç ve canlı kimlik kontrolleri korunur. Eksik kanıtta kayıt/inceleme sürer,
yıkıcı primitive çağrılmaz.

### Beklenen 128 ek ret

Senaryo: her kural ayrı ayrı min_sources=2 ile açıkça yapılandırılır;
yetkili özgün kanıt deposu sağlanmadan durdurma değerlendirmesi yapılır.
Önceki genel politika 128 kuralda izin verirken yeni kapı reddeder.
Bu **gerçek Fedora'ya uygulanmış 128 politika değişikliği değildir** ve eski
katmanda mutlaka süreç öldürüleceği anlamına gelmez; önceki son hedef kontrolleri
zaten başka nedenlerle reddedebilir. 128 fark, ek kanıt kapısının amaçlanan etkisidir.

Tam karşılaştırma CSV'si: `docs/EXPECTED-POLICY-DENIALS-2026.csv`.
Aşağıdaki her satırda müdahale `process_kill`; eksik koşul
`trusted_evidence_store_unavailable` (yetkili bağımsız kanıt yok); güvenlik
nedeni genel tek-tespit politikasının kuralın çoklu kanıt şartını atlayamamasıdır.

| Kural kimliği | Müdahale | Önce → yeni | Eksik koşul | Güvenlik gerekçesi |
| --- | --- | --- | --- | --- |
| `SATSUMA-BPF-CLI-002` | `process_kill` | izin → ret | `trusted_evidence_store_unavailable` | Zorunlu iki bağımsız kanıt olmadan durdurma yok |
| `SATSUMA-BPF-CLI-003` | `process_kill` | izin → ret | `trusted_evidence_store_unavailable` | Zorunlu iki bağımsız kanıt olmadan durdurma yok |
| `SATSUMA-BPF-CLI-004` | `process_kill` | izin → ret | `trusted_evidence_store_unavailable` | Zorunlu iki bağımsız kanıt olmadan durdurma yok |
| `SATSUMA-BPF-CLI-005` | `process_kill` | izin → ret | `trusted_evidence_store_unavailable` | Zorunlu iki bağımsız kanıt olmadan durdurma yok |
| `SATSUMA-BPF-CLI-006` | `process_kill` | izin → ret | `trusted_evidence_store_unavailable` | Zorunlu iki bağımsız kanıt olmadan durdurma yok |
| `SATSUMA-BPF-CLI-007` | `process_kill` | izin → ret | `trusted_evidence_store_unavailable` | Zorunlu iki bağımsız kanıt olmadan durdurma yok |
| `SATSUMA-LINUX-CLI-003` | `process_kill` | izin → ret | `trusted_evidence_store_unavailable` | Zorunlu iki bağımsız kanıt olmadan durdurma yok |
| `SATSUMA-COLL-003` | `process_kill` | izin → ret | `trusted_evidence_store_unavailable` | Zorunlu iki bağımsız kanıt olmadan durdurma yok |
| `SATSUMA-COLL-008` | `process_kill` | izin → ret | `trusted_evidence_store_unavailable` | Zorunlu iki bağımsız kanıt olmadan durdurma yok |
| `SATSUMA-COLL-012` | `process_kill` | izin → ret | `trusted_evidence_store_unavailable` | Zorunlu iki bağımsız kanıt olmadan durdurma yok |
| `SATSUMA-COLL-015` | `process_kill` | izin → ret | `trusted_evidence_store_unavailable` | Zorunlu iki bağımsız kanıt olmadan durdurma yok |
| `SATSUMA-COLL-016` | `process_kill` | izin → ret | `trusted_evidence_store_unavailable` | Zorunlu iki bağımsız kanıt olmadan durdurma yok |
| `SATSUMA-COLL-017` | `process_kill` | izin → ret | `trusted_evidence_store_unavailable` | Zorunlu iki bağımsız kanıt olmadan durdurma yok |
| `SATSUMA-COLL-018` | `process_kill` | izin → ret | `trusted_evidence_store_unavailable` | Zorunlu iki bağımsız kanıt olmadan durdurma yok |
| `SATSUMA-COLL-019` | `process_kill` | izin → ret | `trusted_evidence_store_unavailable` | Zorunlu iki bağımsız kanıt olmadan durdurma yok |
| `SATSUMA-C2-001` | `process_kill` | izin → ret | `trusted_evidence_store_unavailable` | Zorunlu iki bağımsız kanıt olmadan durdurma yok |
| `SATSUMA-C2-002` | `process_kill` | izin → ret | `trusted_evidence_store_unavailable` | Zorunlu iki bağımsız kanıt olmadan durdurma yok |
| `SATSUMA-C2-003` | `process_kill` | izin → ret | `trusted_evidence_store_unavailable` | Zorunlu iki bağımsız kanıt olmadan durdurma yok |
| `SATSUMA-C2-005` | `process_kill` | izin → ret | `trusted_evidence_store_unavailable` | Zorunlu iki bağımsız kanıt olmadan durdurma yok |
| `SATSUMA-CRED-001` | `process_kill` | izin → ret | `trusted_evidence_store_unavailable` | Zorunlu iki bağımsız kanıt olmadan durdurma yok |
| `SATSUMA-CRED-002` | `process_kill` | izin → ret | `trusted_evidence_store_unavailable` | Zorunlu iki bağımsız kanıt olmadan durdurma yok |
| `SATSUMA-CRED-003` | `process_kill` | izin → ret | `trusted_evidence_store_unavailable` | Zorunlu iki bağımsız kanıt olmadan durdurma yok |
| `SATSUMA-CRED-004` | `process_kill` | izin → ret | `trusted_evidence_store_unavailable` | Zorunlu iki bağımsız kanıt olmadan durdurma yok |
| `SATSUMA-CRED-005` | `process_kill` | izin → ret | `trusted_evidence_store_unavailable` | Zorunlu iki bağımsız kanıt olmadan durdurma yok |
| `SATSUMA-CRED-006` | `process_kill` | izin → ret | `trusted_evidence_store_unavailable` | Zorunlu iki bağımsız kanıt olmadan durdurma yok |
| `SATSUMA-KERNEL-001` | `process_kill` | izin → ret | `trusted_evidence_store_unavailable` | Zorunlu iki bağımsız kanıt olmadan durdurma yok |
| `SATSUMA-KERNEL-002` | `process_kill` | izin → ret | `trusted_evidence_store_unavailable` | Zorunlu iki bağımsız kanıt olmadan durdurma yok |
| `SATSUMA-KERNEL-003` | `process_kill` | izin → ret | `trusted_evidence_store_unavailable` | Zorunlu iki bağımsız kanıt olmadan durdurma yok |
| `SATSUMA-KERNEL-004` | `process_kill` | izin → ret | `trusted_evidence_store_unavailable` | Zorunlu iki bağımsız kanıt olmadan durdurma yok |
| `SATSUMA-KERNEL-005` | `process_kill` | izin → ret | `trusted_evidence_store_unavailable` | Zorunlu iki bağımsız kanıt olmadan durdurma yok |
| `SATSUMA-KERNEL-006` | `process_kill` | izin → ret | `trusted_evidence_store_unavailable` | Zorunlu iki bağımsız kanıt olmadan durdurma yok |
| `SATSUMA-KERNEL-007` | `process_kill` | izin → ret | `trusted_evidence_store_unavailable` | Zorunlu iki bağımsız kanıt olmadan durdurma yok |
| `SATSUMA-KERNEL-008` | `process_kill` | izin → ret | `trusted_evidence_store_unavailable` | Zorunlu iki bağımsız kanıt olmadan durdurma yok |
| `SATSUMA-KERNEL-009` | `process_kill` | izin → ret | `trusted_evidence_store_unavailable` | Zorunlu iki bağımsız kanıt olmadan durdurma yok |
| `SATSUMA-KERNEL-010` | `process_kill` | izin → ret | `trusted_evidence_store_unavailable` | Zorunlu iki bağımsız kanıt olmadan durdurma yok |
| `SATSUMA-POLKIT-001` | `process_kill` | izin → ret | `trusted_evidence_store_unavailable` | Zorunlu iki bağımsız kanıt olmadan durdurma yok |
| `SATSUMA-SUDO-001` | `process_kill` | izin → ret | `trusted_evidence_store_unavailable` | Zorunlu iki bağımsız kanıt olmadan durdurma yok |
| `SATSUMA-SUDO-002` | `process_kill` | izin → ret | `trusted_evidence_store_unavailable` | Zorunlu iki bağımsız kanıt olmadan durdurma yok |
| `SATSUMA-SUDO-005` | `process_kill` | izin → ret | `trusted_evidence_store_unavailable` | Zorunlu iki bağımsız kanıt olmadan durdurma yok |
| `SATSUMA-SUID-003` | `process_kill` | izin → ret | `trusted_evidence_store_unavailable` | Zorunlu iki bağımsız kanıt olmadan durdurma yok |
| `SATSUMA-CONT-001` | `process_kill` | izin → ret | `trusted_evidence_store_unavailable` | Zorunlu iki bağımsız kanıt olmadan durdurma yok |
| `SATSUMA-CONT-002` | `process_kill` | izin → ret | `trusted_evidence_store_unavailable` | Zorunlu iki bağımsız kanıt olmadan durdurma yok |
| `SATSUMA-CONT-003` | `process_kill` | izin → ret | `trusted_evidence_store_unavailable` | Zorunlu iki bağımsız kanıt olmadan durdurma yok |
| `SATSUMA-LNX-EVAS-002` | `process_kill` | izin → ret | `trusted_evidence_store_unavailable` | Zorunlu iki bağımsız kanıt olmadan durdurma yok |
| `SATSUMA-LNX-EVAS-003` | `process_kill` | izin → ret | `trusted_evidence_store_unavailable` | Zorunlu iki bağımsız kanıt olmadan durdurma yok |
| `SATSUMA-LNX-EVAS-004` | `process_kill` | izin → ret | `trusted_evidence_store_unavailable` | Zorunlu iki bağımsız kanıt olmadan durdurma yok |
| `SATSUMA-LNX-DISC-001` | `process_kill` | izin → ret | `trusted_evidence_store_unavailable` | Zorunlu iki bağımsız kanıt olmadan durdurma yok |
| `SATSUMA-LNX-DISC-002` | `process_kill` | izin → ret | `trusted_evidence_store_unavailable` | Zorunlu iki bağımsız kanıt olmadan durdurma yok |
| `SATSUMA-LNX-DISC-003` | `process_kill` | izin → ret | `trusted_evidence_store_unavailable` | Zorunlu iki bağımsız kanıt olmadan durdurma yok |
| `SATSUMA-LNX-EXFIL-001` | `process_kill` | izin → ret | `trusted_evidence_store_unavailable` | Zorunlu iki bağımsız kanıt olmadan durdurma yok |
| `SATSUMA-EVAS-001` | `process_kill` | izin → ret | `trusted_evidence_store_unavailable` | Zorunlu iki bağımsız kanıt olmadan durdurma yok |
| `SATSUMA-EVAS-002` | `process_kill` | izin → ret | `trusted_evidence_store_unavailable` | Zorunlu iki bağımsız kanıt olmadan durdurma yok |
| `SATSUMA-EVAS-003` | `process_kill` | izin → ret | `trusted_evidence_store_unavailable` | Zorunlu iki bağımsız kanıt olmadan durdurma yok |
| `SATSUMA-EVAS-004` | `process_kill` | izin → ret | `trusted_evidence_store_unavailable` | Zorunlu iki bağımsız kanıt olmadan durdurma yok |
| `SATSUMA-EVAS-005` | `process_kill` | izin → ret | `trusted_evidence_store_unavailable` | Zorunlu iki bağımsız kanıt olmadan durdurma yok |
| `SATSUMA-EVAS-018` | `process_kill` | izin → ret | `trusted_evidence_store_unavailable` | Zorunlu iki bağımsız kanıt olmadan durdurma yok |
| `SATSUMA-EXEC-001` | `process_kill` | izin → ret | `trusted_evidence_store_unavailable` | Zorunlu iki bağımsız kanıt olmadan durdurma yok |
| `SATSUMA-EXEC-002` | `process_kill` | izin → ret | `trusted_evidence_store_unavailable` | Zorunlu iki bağımsız kanıt olmadan durdurma yok |
| `SATSUMA-EXEC-003` | `process_kill` | izin → ret | `trusted_evidence_store_unavailable` | Zorunlu iki bağımsız kanıt olmadan durdurma yok |
| `SATSUMA-EXEC-004` | `process_kill` | izin → ret | `trusted_evidence_store_unavailable` | Zorunlu iki bağımsız kanıt olmadan durdurma yok |
| `SATSUMA-EXEC-005` | `process_kill` | izin → ret | `trusted_evidence_store_unavailable` | Zorunlu iki bağımsız kanıt olmadan durdurma yok |
| `SATSUMA-EXEC-006` | `process_kill` | izin → ret | `trusted_evidence_store_unavailable` | Zorunlu iki bağımsız kanıt olmadan durdurma yok |
| `SATSUMA-EXEC-007` | `process_kill` | izin → ret | `trusted_evidence_store_unavailable` | Zorunlu iki bağımsız kanıt olmadan durdurma yok |
| `SATSUMA-EXEC-008` | `process_kill` | izin → ret | `trusted_evidence_store_unavailable` | Zorunlu iki bağımsız kanıt olmadan durdurma yok |
| `SATSUMA-EXEC-009` | `process_kill` | izin → ret | `trusted_evidence_store_unavailable` | Zorunlu iki bağımsız kanıt olmadan durdurma yok |
| `SATSUMA-EXEC-011` | `process_kill` | izin → ret | `trusted_evidence_store_unavailable` | Zorunlu iki bağımsız kanıt olmadan durdurma yok |
| `SATSUMA-EXEC-012` | `process_kill` | izin → ret | `trusted_evidence_store_unavailable` | Zorunlu iki bağımsız kanıt olmadan durdurma yok |
| `SATSUMA-EXEC-013` | `process_kill` | izin → ret | `trusted_evidence_store_unavailable` | Zorunlu iki bağımsız kanıt olmadan durdurma yok |
| `SATSUMA-EXEC-015` | `process_kill` | izin → ret | `trusted_evidence_store_unavailable` | Zorunlu iki bağımsız kanıt olmadan durdurma yok |
| `SATSUMA-EXFIL-006` | `process_kill` | izin → ret | `trusted_evidence_store_unavailable` | Zorunlu iki bağımsız kanıt olmadan durdurma yok |
| `SATSUMA-EXFIL-011` | `process_kill` | izin → ret | `trusted_evidence_store_unavailable` | Zorunlu iki bağımsız kanıt olmadan durdurma yok |
| `SATSUMA-IMP-002` | `process_kill` | izin → ret | `trusted_evidence_store_unavailable` | Zorunlu iki bağımsız kanıt olmadan durdurma yok |
| `SATSUMA-RAM-005` | `process_kill` | izin → ret | `trusted_evidence_store_unavailable` | Zorunlu iki bağımsız kanıt olmadan durdurma yok |
| `SATSUMA-PERS-001` | `process_kill` | izin → ret | `trusted_evidence_store_unavailable` | Zorunlu iki bağımsız kanıt olmadan durdurma yok |
| `SATSUMA-PERS-002` | `process_kill` | izin → ret | `trusted_evidence_store_unavailable` | Zorunlu iki bağımsız kanıt olmadan durdurma yok |
| `SATSUMA-PERS-003` | `process_kill` | izin → ret | `trusted_evidence_store_unavailable` | Zorunlu iki bağımsız kanıt olmadan durdurma yok |
| `SATSUMA-PERS-004` | `process_kill` | izin → ret | `trusted_evidence_store_unavailable` | Zorunlu iki bağımsız kanıt olmadan durdurma yok |
| `SATSUMA-PERS-005` | `process_kill` | izin → ret | `trusted_evidence_store_unavailable` | Zorunlu iki bağımsız kanıt olmadan durdurma yok |
| `SATSUMA-PERS-006` | `process_kill` | izin → ret | `trusted_evidence_store_unavailable` | Zorunlu iki bağımsız kanıt olmadan durdurma yok |
| `SATSUMA-PERS-007` | `process_kill` | izin → ret | `trusted_evidence_store_unavailable` | Zorunlu iki bağımsız kanıt olmadan durdurma yok |
| `SATSUMA-PERS-008` | `process_kill` | izin → ret | `trusted_evidence_store_unavailable` | Zorunlu iki bağımsız kanıt olmadan durdurma yok |
| `SATSUMA-PRIV-002` | `process_kill` | izin → ret | `trusted_evidence_store_unavailable` | Zorunlu iki bağımsız kanıt olmadan durdurma yok |
| `SATSUMA-PRIV-005` | `process_kill` | izin → ret | `trusted_evidence_store_unavailable` | Zorunlu iki bağımsız kanıt olmadan durdurma yok |
| `SATSUMA-PRIV-006` | `process_kill` | izin → ret | `trusted_evidence_store_unavailable` | Zorunlu iki bağımsız kanıt olmadan durdurma yok |
| `SATSUMA-PRIV-007` | `process_kill` | izin → ret | `trusted_evidence_store_unavailable` | Zorunlu iki bağımsız kanıt olmadan durdurma yok |
| `SATSUMA-PRIV-011` | `process_kill` | izin → ret | `trusted_evidence_store_unavailable` | Zorunlu iki bağımsız kanıt olmadan durdurma yok |
| `SATSUMA-PRIV-012` | `process_kill` | izin → ret | `trusted_evidence_store_unavailable` | Zorunlu iki bağımsız kanıt olmadan durdurma yok |
| `SATSUMA-PRIV-013` | `process_kill` | izin → ret | `trusted_evidence_store_unavailable` | Zorunlu iki bağımsız kanıt olmadan durdurma yok |
| `SATSUMA-PRIV-014` | `process_kill` | izin → ret | `trusted_evidence_store_unavailable` | Zorunlu iki bağımsız kanıt olmadan durdurma yok |
| `SATSUMA-PRIV-016` | `process_kill` | izin → ret | `trusted_evidence_store_unavailable` | Zorunlu iki bağımsız kanıt olmadan durdurma yok |
| `SATSUMA-PRIV-017` | `process_kill` | izin → ret | `trusted_evidence_store_unavailable` | Zorunlu iki bağımsız kanıt olmadan durdurma yok |
| `SATSUMA-PRIV-018` | `process_kill` | izin → ret | `trusted_evidence_store_unavailable` | Zorunlu iki bağımsız kanıt olmadan durdurma yok |
| `SATSUMA-PRIV-019` | `process_kill` | izin → ret | `trusted_evidence_store_unavailable` | Zorunlu iki bağımsız kanıt olmadan durdurma yok |
| `SATSUMA-PRIV-020` | `process_kill` | izin → ret | `trusted_evidence_store_unavailable` | Zorunlu iki bağımsız kanıt olmadan durdurma yok |
| `SATSUMA-PRIV-021` | `process_kill` | izin → ret | `trusted_evidence_store_unavailable` | Zorunlu iki bağımsız kanıt olmadan durdurma yok |
| `SATSUMA-PRIV-022` | `process_kill` | izin → ret | `trusted_evidence_store_unavailable` | Zorunlu iki bağımsız kanıt olmadan durdurma yok |
| `SATSUMA-PRIV-023` | `process_kill` | izin → ret | `trusted_evidence_store_unavailable` | Zorunlu iki bağımsız kanıt olmadan durdurma yok |
| `SATSUMA-PRIV-025` | `process_kill` | izin → ret | `trusted_evidence_store_unavailable` | Zorunlu iki bağımsız kanıt olmadan durdurma yok |
| `SATSUMA-PRIV-026` | `process_kill` | izin → ret | `trusted_evidence_store_unavailable` | Zorunlu iki bağımsız kanıt olmadan durdurma yok |
| `SATSUMA-PRIV-027` | `process_kill` | izin → ret | `trusted_evidence_store_unavailable` | Zorunlu iki bağımsız kanıt olmadan durdurma yok |
| `SATSUMA-PRIV-029` | `process_kill` | izin → ret | `trusted_evidence_store_unavailable` | Zorunlu iki bağımsız kanıt olmadan durdurma yok |
| `SATSUMA-PRIV-030` | `process_kill` | izin → ret | `trusted_evidence_store_unavailable` | Zorunlu iki bağımsız kanıt olmadan durdurma yok |
| `SATSUMA-SUDO-HARD-001` | `process_kill` | izin → ret | `trusted_evidence_store_unavailable` | Zorunlu iki bağımsız kanıt olmadan durdurma yok |
| `SATSUMA-SUDO-HARD-002` | `process_kill` | izin → ret | `trusted_evidence_store_unavailable` | Zorunlu iki bağımsız kanıt olmadan durdurma yok |
| `SATSUMA-LOL-001` | `process_kill` | izin → ret | `trusted_evidence_store_unavailable` | Zorunlu iki bağımsız kanıt olmadan durdurma yok |
| `SATSUMA-LOL-002` | `process_kill` | izin → ret | `trusted_evidence_store_unavailable` | Zorunlu iki bağımsız kanıt olmadan durdurma yok |
| `SATSUMA-LOL-003` | `process_kill` | izin → ret | `trusted_evidence_store_unavailable` | Zorunlu iki bağımsız kanıt olmadan durdurma yok |
| `SATSUMA-LOL-004` | `process_kill` | izin → ret | `trusted_evidence_store_unavailable` | Zorunlu iki bağımsız kanıt olmadan durdurma yok |
| `SATSUMA-FILELESS-001` | `process_kill` | izin → ret | `trusted_evidence_store_unavailable` | Zorunlu iki bağımsız kanıt olmadan durdurma yok |
| `SATSUMA-FILELESS-002` | `process_kill` | izin → ret | `trusted_evidence_store_unavailable` | Zorunlu iki bağımsız kanıt olmadan durdurma yok |
| `SATSUMA-FILELESS-003` | `process_kill` | izin → ret | `trusted_evidence_store_unavailable` | Zorunlu iki bağımsız kanıt olmadan durdurma yok |
| `SATSUMA-CONT-101` | `process_kill` | izin → ret | `trusted_evidence_store_unavailable` | Zorunlu iki bağımsız kanıt olmadan durdurma yok |
| `SATSUMA-CONT-102` | `process_kill` | izin → ret | `trusted_evidence_store_unavailable` | Zorunlu iki bağımsız kanıt olmadan durdurma yok |
| `SATSUMA-CLOUD-001` | `process_kill` | izin → ret | `trusted_evidence_store_unavailable` | Zorunlu iki bağımsız kanıt olmadan durdurma yok |
| `SATSUMA-CRED-101` | `process_kill` | izin → ret | `trusted_evidence_store_unavailable` | Zorunlu iki bağımsız kanıt olmadan durdurma yok |
| `SATSUMA-CRED-102` | `process_kill` | izin → ret | `trusted_evidence_store_unavailable` | Zorunlu iki bağımsız kanıt olmadan durdurma yok |
| `SATSUMA-CRED-103` | `process_kill` | izin → ret | `trusted_evidence_store_unavailable` | Zorunlu iki bağımsız kanıt olmadan durdurma yok |
| `SATSUMA-PERSIST-001` | `process_kill` | izin → ret | `trusted_evidence_store_unavailable` | Zorunlu iki bağımsız kanıt olmadan durdurma yok |
| `SATSUMA-PERSIST-002` | `process_kill` | izin → ret | `trusted_evidence_store_unavailable` | Zorunlu iki bağımsız kanıt olmadan durdurma yok |
| `SATSUMA-PERSIST-003` | `process_kill` | izin → ret | `trusted_evidence_store_unavailable` | Zorunlu iki bağımsız kanıt olmadan durdurma yok |
| `SATSUMA-EVASION-001` | `process_kill` | izin → ret | `trusted_evidence_store_unavailable` | Zorunlu iki bağımsız kanıt olmadan durdurma yok |
| `SATSUMA-EVASION-002` | `process_kill` | izin → ret | `trusted_evidence_store_unavailable` | Zorunlu iki bağımsız kanıt olmadan durdurma yok |
| `SATSUMA-EVASION-003` | `process_kill` | izin → ret | `trusted_evidence_store_unavailable` | Zorunlu iki bağımsız kanıt olmadan durdurma yok |
| `SATSUMA-EXFIL-101` | `process_kill` | izin → ret | `trusted_evidence_store_unavailable` | Zorunlu iki bağımsız kanıt olmadan durdurma yok |
| `SATSUMA-EXFIL-102` | `process_kill` | izin → ret | `trusted_evidence_store_unavailable` | Zorunlu iki bağımsız kanıt olmadan durdurma yok |
| `SATSUMA-MINE-001` | `process_kill` | izin → ret | `trusted_evidence_store_unavailable` | Zorunlu iki bağımsız kanıt olmadan durdurma yok |
| `SATSUMA-RANSOM-001` | `process_kill` | izin → ret | `trusted_evidence_store_unavailable` | Zorunlu iki bağımsız kanıt olmadan durdurma yok |
| `SATSUMA-RANSOM-002` | `process_kill` | izin → ret | `trusted_evidence_store_unavailable` | Zorunlu iki bağımsız kanıt olmadan durdurma yok |

## 5. DeepSeek ortak paketi ve GPG güven zinciri

Paket sürümlüdür; detection gerçek Smart Rule v1 sözleşmesinin sıkı alt kümesidir.
Desteklenen kaynaklar `sys_proc` ve mevcut beş memory eylemidir. Desteklenmeyen
telemetri, ek alan, eksik match, uydurulmuş koşul, kimlik/sürüm/hash çakışması
ve ticket/auto_action/yıkıcı detection aksiyonu reddedilir. Eksik eşleşme kural
adından türetilmez, tehlikeli alanlar sessizce temizlenmez.

Response proposal aynı rule_id/sürüm/detection_sha256 ile bağlıdır; minimum
bağımsız kaynak, gerekli sensörler, doğrulama seviyesi, kanıt, yetki, etki ve geri
dönüş koşullarını taşır. Bunlar **öneridir**; DeepSeek gerçekleştiğini doğrulayamaz.
Kanonik detection hash'i modelin tahminine bırakılmaz; eksikse yerelde yalnız
bu mekanik bağ hesaplanır. Yanlış mevcut hash otomatik düzeltilmez.

Akış: generated → şema doğrulaması → izole işlev testi → pending_review →
approved_for_signing → signed → activated. Ret ve signing/activation failure
ayrıdır. Duplicate ID/tekrar onay geçmişi üzerine yazılmaz; koşullu durum
geçişleri, transaction ve istek kimliği tekrarını önleme kullanılır. Eski kuyruk
kayıtları korunur; yeni kolonlar yalnız yazma yolunda eklenir. Read/list yolu
DDL veya commit yapmaz. Eski adaylar yeni kimlik ve testlerle yeniden sunulmalıdır.

İmza, **paketin tamamını ve operatör onayını** kapsar. Salt tespit bölümünü
imzalayıp müdahaleyi değiştirme yolu yoktur. Root servis imzalama yapmaz ve özel
anahtar kabul etmez. Açık keyring: `/etc/satsuma-core/trust/deepseek-rules.gpg`;
root-owned, değiştirilemeyen normal dosya denetlenir. GPG network key retrieval
kapalıdır. İmzasız/değişmiş paket gerçek SmartRuleEngine yükleme yolunda reddedilir.
Mevcut 228 kurala ani zorunlu yeni imza formatı uygulanmadı; bunların geçişi
sabit baseline/ürün imzası ve ayrı operatör manifest incelemesi gerektirir.

Aktivasyonda önce şema/test/imza yeniden denetlenir, staging dizinindeki dosyalar
fsync edilir, gerçek yükleyiciyle doğrulanır ve benzersiz hedef dizine atomik
yayınlanır. Başarısız yayım activated yazmaz; staging temizlenir. Dosyaya yayın,
yükleyici kabulü, canlı Brain ack ve gerçek müdahale ayrı göstergelerdir.
Her 10 saniyelik kontrollü managed-rule yenilemesi ve Brain state ack yolu vardır;
Fedora'da çalıştırıldığı iddia edilmez. Aktivasyon durumu ayrıca dosya/imza
bütünlüğünü kontrol eder; geçmiş onay/imza, başarısız yeniden doğrulamayla silinmez.

AI bulguları ticket→auto_action veya başka dolaylı yol üzerinden durdurma yetkisi
alamaz. SafeActionBroker, AutoActionEngine, response_policy ve son process
primitive'leri bunu reddeder. Kuralın aktif olması müdahalenin yapıldığı değildir.

## 6. Gerçek API ve gizli bilgi durumu

**Gerçek DeepSeek API testi: ÇALIŞTIRILMADI / dış ön koşul bekliyor.**
Bulut ortamında `/etc/satsuma-core/deepseek.key` yok, DeepSeek değişken/secret
bağlantısı yok ve `api.deepseek.com` mevcut izin listesinde değil. Kullanıcının
Fedora cihazındaki 0600 root:root dosyası bu makinede mevcut sayılmadı.
Gizli değer istenmedi, görüntülenmedi ve dışarı gönderilmedi.

Uygulanan transport: sabit HTTPS endpoint, TLS doğrulaması, redirect reddi,
1–45 saniye sınırlı timeout, 256 KiB cevap, sınırlı token, sekiz istek/saat ve
10 saniye aralık; her ücretli istekte açık kullanıcı onayı ve Operator oturumu.
Yalnız MITRE tekniği, seçilen tehdit türü ve kamuya açık şema gönderilir.
Yerel olay/PID/IP/bellek ve özel imza anahtarı gönderilmez. Anahtar yalnız root
arka uçta 0600 root:root normal dosyadan okunur; grup erişimi otomatik açılmaz.
Hatalar güvenli kodlardır; anahtarın ilk/son karakterleri bile gösterilmez.
CLI'lar da Operator IPC kullanır; eski fragment basan test betiği kaldırıldı.

## 7. Privd hatası ve pozitif/negatif yetkilendirme

Kök neden test ortamıdır: gerçek peer UID/GID 1000, `satsuma-priv` grubu yok.
Mevcut sözleşme root veya doğrulanmış birincil satsuma-priv GID'ini kabul eder.
Orijinal test yetkisiz kullanıcıyı koşulsuz başarılı varsayıyordu. Önceki commitin
**değiştirilmemiş** testi aynı reddi verdi. `satsuma/privd.py`, peer credentials,
socket 0660 ve systemd grup dosyası referansa göre değiştirilmedi.

Pozitif fixture gerçek SO_PEERCRED kimliğini korur, mevcut allowed fonksiyonunu
çağırır ve yalnız test grup lookup'ını peer'in gerçek GID'ine eşler. Host grubu
oluşturulmaz, socket izinleri genişlemez, tüm çağırıcıları kabul eden üretim
kodu eklenmez. Negatif testte açıkça yabancı UID/GID doğrulanır; FakeWorker
hiç çağrılmaz. Root ortamındaki negatif dalın sentetik non-root kimliği olduğu
testte açıkça belirtilir. Gerçek yetkili Fedora çağrısının reddedildiğine dair
kanıt yok; o ortamda gerçek servis/kimlik testi henüz yapılmadı.

Gerçek ayrı Operator Unix soketi testi de yapıldı: gerçek framing ve
SO_PEERCRED ile yetkisiz token reddi, duplicate istek, submit, approve,
GPG verify, atomik activate ve ayrı runtime state doğrulandı. Yönetici oturumu,
anahtar sahipliği ve GPG anahtarı **izole test fixture'ıdır**; üretim kimlik
ve anahtarları kullanıldığı iddia edilmez.

## 8. Bellek kapsamı: gerçekten okunan, üstveri, erişilemeyen

Ek tarayıcı bütün yürütülebilir mapping sınıflarını ele alır: dosya destekli,
anonim/JIT olası, memfd, silinmiş destek ve çekirdek özel mapping'leri.
JIT/memfd kullanımı tek başına zararlı sayılmaz. Ham bellek saklanmaz.
Güvenilir referans sağlayıcısı yoksa karşılaştırma varmış/temizmiş gibi sunulmaz;
mevcut Fedora RPM referanslarına bağlanmış geniş kapsam sağlayıcı henüz
**yapılandırılmadı**. Yalnız sağlayıcı sınırı ve sentetik trusted-reference testi
mevcuttur. Eski ana executable doğrulaması ayrı ve mevcut politika kapılı kalır.

Sınırlar: süreç başına 2 MiB ve 50 ms, tur başına ek taramada 8 MiB/500 ms,
16 KiB chunk, 256 mapping özeti, 1 MiB maps girdisi. Büyük mapping içinde
cursor sonraki turda devam eder; PID/starttime/exe/maps değişirse cursor sıfırlanır.
CPU süresi ayrıca ölçülür. Bu değerler ek bölge taramasının sınırlarıdır;
önceden var olan ana executable karşılaştırmasının süresini kapsayan bir
bütün servis SLA'sı değildir.

Ayrık bayt bölümleri:

- `valid_snapshot_read_bytes`: kararlı kimlik/eşleme altında gerçekten okunan.
- `metadata_only_bytes`: yalnız açıkça üstveriyle sınırlanan kernel mapping'i;
  kalan baytların farkından türetilmez.
- `budget_skipped_bytes`: bu tur byte/time/region bütçesiyle okunmayan.
- `access_denied_bytes` ve `unreadable_bytes`: ayrı erişim/I/O veya short-read kalanları.
- `identity_changed_bytes` / `mapping_changed_bytes`: ilk snapshot'ın geçersizleşen
  kapsamı; bu durumda okunan fiziksel baytlar valid kapsamdan çıkarılır.
- `unclassified_bytes`: boyutu bilinen ama sınıfı okunamayan mapping. Boyutu dahi
  bilinmeyen kayıtlar denominator-incomplete bayrağıyla ayrı bildirilir.

Bölümlerin toplamı bilinen snapshot aday baytlarına eşittir; `bytes_read` fiziksel
okuma olgusudur ve bu toplamın üzerine **ikinci kez eklenmez**. Güvenilir referansla
karşılaştırılan bayt da valid read'in alt kümesidir.

Tam payda biliniyorsa yüzde = `100 * valid_snapshot_read_bytes / candidate_bytes`.
Payda eksikse kesin `read_coverage_percent=None`; varsa yalnız
`partial_observed_coverage_percent` ve Qt6'da **“KISMİ GÖZLENEN KAPSAM · Payda eksik”**
gösterilir. Kimlik/maps değişiminde yüzde ve trusted reference kapsamı geçersizleşir.
Bu oran sistemin tüm RAM'i değil, bu turdaki süreçlerin yürütülebilir mapping
kapsamıdır. Taranamayan alanlar temiz sayılmaz.

**Bulut gerçek okuma gözlemi:** Python test sürecinin `/proc/self/mem` alanından
65.536 bayt gerçekten okundu. Harita değiştiği için `MAPPINGS_CHANGED`,
`valid_snapshot_read_bytes=0`, `invalidated_read_bytes=65536`, yüzde=null ve
`reference_verified_bytes=0` kaydedildi. Bu yalnız bulut test ortamıdır;
Fedora tam bellek taraması olarak sunulmaz. Kanıt: `memory-cloud-read-2026.json`.

Mevcut ptrace/SELinux politikası değiştirilmedi. Bulutta ptrace_scope dosyası
yoktu: UNKNOWN. Fedora'nın bildirilen 2 değeri burada doğrulanmış sayılmadı.
Sentetik ptrace_scope=3 testi de politika düşürülmeden ACCESS_DENIED/erişimsizlik
sunumunu doğrular. Sınırlandırılmış model mevcut read-only /proc izinleridir;
eklenecek istisna gerekiyorsa ayrı mimari/SELinux denetimi ve onay gerekir.

## 9. Suricata, OTX ve nftables görünürlüğü

Doğrulanan kod hatası: max_priority=3 iken engine STREAM olayları da gerçek
imza gibi fast_block yoluna girebiliyordu. SYN retransmission/invalid timestamp;
ağ kaybı, sıralama, middlebox ve saat özelliklerinden etkilenebilen motor
anomalileridir. Tek başına saldırı niyeti veya kalıcı ban gerekçesi değildir.
`response_outcome=BLOCKED` ve nft set/readback, müdahalenin kurulduğunu gösterir;
saldırının doğru teşhis edildiğini ya da paket düşmesinin ölçüldüğünü göstermez.

Yeni sınıflar: `engine_anomaly`, `unverified_signature`, `attack_signature_candidate`.
STREAM/decoder SID aralığı ve motor bilgisi anomaliyi ayırır; yalnız priority ile
karar verilmez. Engine/kimliği doğrulanamayan olay kayıt/inceleme olarak kalır,
OTX olumlu görünse bile bu olaydan otomatik blok başlatılmaz. Gerçek saldırı
imzası için mevcut hedef/yön/politika yolu korunur. Bu hedefli güvenlik değişikliği
228 Smart Rule eşdeğerlik sonucunun içine gizlenmez.

OTX farklı bir itibar kanıtıdır; TLS veya pulse sayısı tek başına gerçek saldırı
imzası değildir. Legacy worker, bağımsız `satsuma-core-otx` servisi ve guard'ın
OTX anahtarı/işlevi ayrı olabilir. Reader artık otx_health'i `otx_service` olarak
ayrı gösterir; eski worker=false bunu kapalıya çeviremez. Servisin gerçek 60 s
çevrimine uygun 120 s gözlem penceresi kullanılır. Guard enabled/key-available
bilgilerini değer sızdırmadan heartbeat'e yazar. Kullanıcının gerçek Fedora
cihazındaki kesin kapalı durumu, journal ve dosya durumu olmadan doğrulanmadı.

Engel sayıları önce sınırlı Core/guard DB kayıt pencerelerinden geliyordu;
son 200 satır ve iki farklı kaynak kernel üyeliğiyle aynı sayaç değildir.
Yeni read-only `nft -j list ruleset` envanteri yalnız Satsuma-owned setleri
sayarak tablo/küme sayısını ve tablolar arası benzersiz IP birleşimini ayrı verir.
Okunamayan/parse edilemeyen küme 0 diye sunulmaz. Kayıt sayısı ile kernel sayısı
Qt6'da ayrıdır. Komut mutation/setup/flush yapmaz. Gerçek Fedora nft, NFQUEUE
100/201, DNS ve servis değişikliği yok; kullanıcı örneğindeki canlı sayı farkının
birebir hedef ölçümü henüz yapılmadı.

## 10. Gerçek Qt6 ürünü ve paketleme

Tasarım ayrı bir maket değildir: mevcut `theme.py`, HeaderBar, NavigationBar,
Overview, Rules, MemoryDefense ve NetworkResponse bileşenlerine uygulanmıştır.
Native Qt6 mint/grafit tema, hiyerarşik kartlar ve üç aşamalı araştırma çalışma
alanı kullanılır. 1000×680 kompakt pencerede yerleşim doğrulandı.
Ekran görüntüleri fixture backend önizlemesidir; canlı koruma kanıtı değildir.

DeepSeek paneli mevcut yönetici oturumunu ve Operator soketini kullanır.
Durum, sınırlı bağlantı testi, araştırma, kural üretimi, iki şema/kimlik
kontrolü, izole test, politika değerlendirmesi, submit/list, gerekçeli reject,
approve, imza export/import/verify, aktivasyon ve aktivasyon durumu ayrı gerçek
metotlara bağlıdır. İş arka plandadır, tekrar tıklama birleştirilir; panel
geçişinde durum korunur. Qt6 API key veya SQLite okumaz. Reader salt okunurdur.

Rules panelinde tespit, gerekli/doğrulanmış kanıt, eksik koşul, öneri, politika,
imza, aktivasyon ve gerçek müdahale ayrı alanlardır. Gözlem yoksa UNKNOWN/None
kalır; “servis çalışıyor = tarama tamamlandı = tehdit yok” eşitliği kurulmaz.

RPM spec payload'ına gerçek Python modülleri/şemalar dahil edilir; iki yetkili
CLI sabit `/usr/bin/python3 -I -B` launcher'larıyla paketlenir. Public trust dizini
ve 0700 managed-rule dizinleri tanımlıdır; özel anahtar/API key paketlenmez,
mevcut key dosyası chmod edilmez. Kaynak arşivinden `.git`/`.venv` çıkarılır.
Staged/extracted payload derleme/import, schema ve 228-rule yükleme testi geçti.
**Native Fedora RPM build/install/systemd başlangıcı doğrulanmadı:** bu Debian
ortamında rpmbuild yok. Üretim RPM'si veya servis paketi kurulmadı/değiştirilmedi.

## 11. Kod / izole test / Fedora ayrımı

| Bileşen | Kodda uygulandı | İzole ortamda doğrulandı | Hedef Fedora'da doğrulandı |
| --- | --- | --- | --- |
| DeepSeek güvenli transport | Evet | HTTP/API hata, limit, onay, anahtar mahremiyeti mock testleri | Hayır; gerçek API yapılmadı |
| Ortak paket ve lifecycle | Evet | Geçici SQLite; duplicate/race/durum geçişi | Hayır |
| GPG imza zinciri | Evet | Gerçek GPG, yalnız geçici test anahtarı | Kullanıcının önceki testi bu yeni zincirin testi sayılmadı |
| Operator IPC / privd | Evet | Gerçek Unix soketi/SO_PEERCRED; oturum/grup fixture'ları açıkça belgeli | Hayır |
| 228 kural | Mevcut aksiyonlar korundu | Ayrı eski/yeni dosyalarla 228/228 davranış karşılaştırması | Hayır |
| Çoklu kanıt | Evet | Aynı sensör, raw-ID/content tekrarı, yanlış hedef, eski/gelecek kanıt, zorunlu aile/hash ve son primitive | Hayır |
| Geniş bellek gözlemi | Evet | Sentetik mappings/short read/denial/JIT/memfd/identity; bulut self-read ayrıca geçersiz | Hayır; tam RAM temizliği iddiası yok |
| Modern Qt6 | Evet, ürün kodunda | Gerçek Qt6/işlev/arka plan ve backend testleri | Hayır |
| Suricata/OTX/nft sayımı | Evet | Sentetik EVE/fast ve kernel JSON; yan etkisiz runner | Hayır |
| Fedora paketleme | Spec/payload/CLI güncellendi | Staged payload ve kaynak arşivi | RPM install/startup hayır |

## 12. Geri alma ve dış ön koşullar

Kod rollback'i yalnız inceleme dalında, kullanıcı gözden geçirmesinden sonra:

```bash
git revert e4987a94b8aa6fa156df9c688f39c6e10c54aece
git revert 87e9dc81b291a960c5b2be65f03b3836fe792cee
git revert 10bf05853fe299464b41129f11f42446c8d128af
```

Üretime kurulum yapılmadığından bu çalışmada canlı DB/firewall geri alma işlemi
uygulanmaz. Üretim denemesinde önceden DB/yapılandırma yedeği alınmalı; additive
queue kolonları ve audit geçmişi geri dönüşte silinmemeli. Bir imzalı paket
sonradan aktive edilecekse geri çekme ayrı onaylı dosya/Brain-state prosedürüyle
ve doğru rule_id/hash üzerinden yapılmalıdır; nft veya servis toplu sıfırlaması
önerilmez. Yeni kapı kaldırılarak eski güvenlik zaafının üretime taşınması
“otomatik rollback” olarak yapılmamalıdır.

Özel ürün imzalama anahtarı kullanıcıda kalır. İmzalama, mimari inceleme ve
kullanıcı onayı tamamlanmadan main aktarımı yapılmaz. Tam kabul için hâlâ canlı
DeepSeek onaylı testi, trusted reference yapılandırması, Fedora build/install,
servis/SELinux/ptrace izinleri ve gerçek veriyle salt okunur doğrulama gerekir.
Bu rapor kodu tek başına üretim için onaylamaz.

## 13. Değişen dosyalar ve commit eşlemesi

| Dosya | Son değişiklik commiti |
| --- | --- |
| `bin/satsuma-deepseek-test.py` | `10bf058` |
| `bin/satsuma-research.py` | `10bf058` |
| `docs/EXPECTED-POLICY-DENIALS-2026.csv` | `teslim raporu/kanıt commiti (teslim mesajında)` |
| `docs/INTEGRATED-AUDIT-2026.md` | `teslim raporu/kanıt commiti (teslim mesajında)` |
| `docs/RULE-BEHAVIOR-AUDIT-2026.json` | `teslim raporu/kanıt commiti (teslim mesajında)` |
| `docs/RULE-RESPONSE-INVENTORY-2026.csv` | `10bf058` |
| `docs/integrated-test-summary-2026.json` | `teslim raporu/kanıt commiti (teslim mesajında)` |
| `docs/integrated-tests-2026.xml` | `teslim raporu/kanıt commiti (teslim mesajında)` |
| `docs/memory-cloud-read-2026.json` | `teslim raporu/kanıt commiti (teslim mesajında)` |
| `integrations/satsuma_guard.py` | `e4987a9` |
| `packaging/build.sh` | `e4987a9` |
| `packaging/check_ai_payload.py` | `e4987a9` |
| `packaging/root/usr/bin/satsuma-deepseek-test` | `e4987a9` |
| `packaging/root/usr/bin/satsuma-research` | `e4987a9` |
| `packaging/satsuma-core.spec` | `e4987a9` |
| `run_satsuma_teams.py` | `10bf058` |
| `satsuma/action_contract.py` | `10bf058` |
| `satsuma/action_executor.py` | `10bf058` |
| `satsuma/ai_rule_package.py` | `10bf058` |
| `satsuma/auto_action.py` | `10bf058` |
| `satsuma/auto_network.py` | `10bf058` |
| `satsuma/auto_process.py` | `10bf058` |
| `satsuma/config.py` | `10bf058` |
| `satsuma/dashboard_api.py` | `e4987a9` |
| `satsuma/dashboard_qt/panels/deepseek.py` | `e4987a9` |
| `satsuma/dashboard_qt/panels/defense_sections.py` | `e4987a9` |
| `satsuma/dashboard_qt/panels/investigation.py` | `e4987a9` |
| `satsuma/dashboard_qt/panels/network_response.py` | `e4987a9` |
| `satsuma/dashboard_qt/panels/overview.py` | `e4987a9` |
| `satsuma/dashboard_qt/panels/rules.py` | `e4987a9` |
| `satsuma/dashboard_qt/style/theme.py` | `e4987a9` |
| `satsuma/dashboard_qt/windows/header.py` | `e4987a9` |
| `satsuma/dashboard_qt/windows/nav.py` | `e4987a9` |
| `satsuma/deepseek_client.py` | `10bf058` |
| `satsuma/deepseek_workflow.py` | `10bf058` |
| `satsuma/enforcement.py` | `10bf058` |
| `satsuma/full_check.py` | `10bf058` |
| `satsuma/memory_scope.py` | `87e9dc8` |
| `satsuma/nft_inventory.py` | `e4987a9` |
| `satsuma/onay_worker.py` | `10bf058` |
| `satsuma/operator_service.py` | `10bf058` |
| `satsuma/response.py` | `10bf058` |
| `satsuma/response_policy.py` | `10bf058` |
| `satsuma/rule_adapter.py` | `10bf058` |
| `satsuma/rule_response.py` | `10bf058` |
| `satsuma/rule_schema.py` | `10bf058` |
| `satsuma/rule_signing.py` | `10bf058` |
| `satsuma/sentinel.py` | `10bf058` |
| `satsuma/smart_rules.py` | `10bf058` |
| `satsuma/worker_memory.py` | `87e9dc8` |
| `schemas/ai-rule-package-v1.schema.json` | `10bf058` |
| `schemas/rule-response-catalog-v1.json` | `10bf058` |
| `tests/fixtures/rule-audit-events-2026.json` | `teslim raporu/kanıt commiti (teslim mesajında)` |
| `tests/test_ai_package_payload.py` | `e4987a9` |
| `tests/test_deepseek_operator_socket.py` | `teslim raporu/kanıt commiti (teslim mesajında)` |
| `tests/test_deepseek_qt.py` | `e4987a9` |
| `tests/test_deepseek_secure_workflow.py` | `10bf058` |
| `tests/test_deepseek_transport.py` | `10bf058` |
| `tests/test_guard_stream_evidence.py` | `e4987a9` |
| `tests/test_memory_scope_bounded.py` | `87e9dc8` |
| `tests/test_privd.py` | `10bf058` |
| `tests/test_rule_response_evidence.py` | `10bf058` |
| `tools/audit_rule_behavior.py` | `teslim raporu/kanıt commiti (teslim mesajında)` |
| `tools/build_rule_response_inventory.py` | `10bf058` |
| `tools/run_integrated_checks.py` | `teslim raporu/kanıt commiti (teslim mesajında)` |

## 14. Fedora 40 RPM teslim eki

Kullanıcı hedefi Fedora 40 ve aktif sürümü 2.2.15 olarak netleştirdi.
`3beaccf8d58a1866bf098418e472fc3d199edd55` kaynak ağacından
`satsuma-core-2.2.15-2.inceleme1.fc40.x86_64.rpm` üretildi. Kaynak spec'in yalnız
Release alanı dış build kopyasında `2.inceleme1%{?dist}` yapıldı; dist `.fc40`.
Üretim RPM dosyaları değiştirilmedi. Derleme Debian üzerinde çalışma alanına
çıkarılmış RPM 4.20 araçlarıyla yapıldı; native Fedora derlemesi değildir.
Resmi Fedora 40 konteynerinde RPM 4.19.1.1 ile digests OK, metadata okuma,
script/trigger çalıştırmadan ayrı köke çıkarma ve Python 3.12.8 compileall geçti.
Boş kökte satsuma-dns grubu olmadığından çıkarma root fallback uyarısı verdi;
bu kontrollü çıkarma gerçek kullanıcı/grup veya kurulum testi sayılmaz.
Bağımlılık çözümü, pre/post scriptleri, systemd, SELinux, ağ ve hedef Fedora
kurulumu doğrulanmadı. RPM GPG imzasızdır; kullanıcı ürün imzasını uygulayacaktır.
Paketin mevcut kurulum scriptleri servis/ağ/koruma ayarlarına etki edebilir;
üretime otomatik kurulum yapılmadı. Önceki raporun RPM üretilemedi kaydı bu ekle
yalnız artefakt üretimi bakımından güncellenir; üretim kabulü anlamına gelmez.
Artefaktlar: `/workspace/artifacts/fedora40/` — RPM, SHA256SUMS, build spec ve
build/validation günlükleri. Main/push yok. Kod testi toplamları değişmedi.
