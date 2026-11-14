# Satsuma-core 2.2.37 — kurtarma çalışması ve sınırlar

## Kaynak ve özgünlük
- Başlangıç: kullanıcının yüklediği `SatsumaSecurity-22be562-kaynak.tar(1).gz`.
- Kaynak SHA-256: `e34c31c3029f5f463d7610e36fddef25513a7a4be6f71d6eb44ed50f2cacd5bf`.
- RPM SHA-256: `50559af9f301aa118c91946db2486feb1b956c3ce5f32424b32c6a928c6f67d7`.
- Kullanıcının bu konuşmada sağladığı 2.2.37 `main.py` kurtarma kopyasına eklendi.
- Kaynakta doğrulanmış `.git` geçmişi, `VERSION`, tam `docs/` ve `release/` bulunmuyor.
- `CLAUDE.md` geçersiz sayılmıştır, kullanılmadı ve oluşturulmadı.

## Uygulanan değişiklikler
1. `main.py` eklendi (kullanıcı tarafından verilen içerik). Başlangıçtaki bütünlük kontrolü veya hata-kilit davranışı değiştirilmedi.
2. `tests/test_recovered_entrypoint.py` eklendi: normal açılış, yardım/sürüm muafiyetleri ve bütünlük denetimi başarısızlığında başlangıcın engellenmesi.

## Bu ortamda test
- `tests/test_recovered_entrypoint.py`: 5 passed.
- `tests/test_reader_channel.py`, `tests/test_dns_readiness_probe_name.py`, `tests/test_dns_resolver_alignment.py`, `tests/test_recovered_entrypoint.py`: toplam 17 passed.
- Tam test takımı çalıştırılmadı. Fedora/OSTree üzerinde servis, nftables, SELinux, Suricata veya RPM kurulumu doğrulanmadı.

## İncelenen ancak uygulanmayan büyük değişiklikler
- DNS ağ ad alanı, veth, DNAT, nftables forward/NFQUEUE ve systemd bağımlılıklarının **birlikte** değiştirilmesi gerekiyor. Arşivde dnsmasq hâlâ `127.0.0.1:53053` kullanıyor; `satsuma-core-dns.service` için `CapabilityBoundingSet=` boş. Yalnızca unit'e `CAP_NET_BIND_SERVICE` eklemek eski DNS düzenini onarmış sayılmaz.
- Ürün içi web araştırması: `satsuma/web_research.py` ve çağıranları hâlâ mevcut.
- Dashboard redaksiyonu, yönetici tarama ekranı, `ClamAV` bellek ayrımı, root servislerin izin daraltılması, otomatik systemd sertleştirme ve yayın öncesi çok motorlu RPM kapısı bu kopyada henüz uygulanmadı.
- Kullanıcının onaylamadığı davranış/politika değişiklikleri notlardaki 'sahibin kararı' ifadelerine dayanılarak uygulanmadı.

## Yayın güvenliği
Bu çıktı **kaynak kurtarma kopyasıdır**, yayın adayı veya doğrulanmış çalışır Fedora paketi değildir. RPM yeniden oluşturulmadı; mevcut RPM ve hedef sistem üzerinde hiçbir değişiklik yapılmadı. Özellikle ağ kesme, sysctl değişikliği, servis durdurma, paket kurma/kaldırma veya ana dala push uygulanmadı.
