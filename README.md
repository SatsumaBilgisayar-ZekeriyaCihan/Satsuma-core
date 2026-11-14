# SatsumaSecurity 2.2.36

Bu depodaki `packaging/satsuma-core.spec` sürümü **2.2.36** olarak tanımlar.
Fedora 44 x86_64 için RPM paketi `packaging/build.sh` ile derlenir; sürüm notları: [RELEASE-2.2.36](docs/RELEASE-2.2.36.md).
Aşağıdaki OTX, ardışık IP gözlemi ve Suricata ağ müdahale notları önceki sürümden devralınan özellikleri özetler; çalışan cihazdaki korumayı tek başına doğrulamaz.

- OTX: tek kayıt (pulse) hiçbir adresi engellemez (denetim K3). Bloklama
  modunda en az iki kayıt, operatörün eşiği ve güncel kayıt gerekir;
  eski `any_pulse` ayarı `threshold` olarak okunur.
- Ardışık IP gözlemi: 300 saniye içinde farklı IP'ler sayılır; mevcut
  10 IP eşiği ve subnet/IP hedef sınırları korunur.
- Suricata: bir uygun alarm, OTX onayı aramadan belirlenen uzak IP için
  müdahale başlatır; host giden ve gelen bağlantılar kapsam dahilindedir.
- Bütünlük kontrolü, operator pause, trusted CIDR/IP ve çekirdek nft set
  doğrulaması korunur; karar ile gerçekten düşürülen paket ayrıdır.

## Geliştirme ve doğrulama

```bash
PYTHONPATH=. QT_QPA_PLATFORM=offscreen python3 -m pytest -q tests/test_network_single_signal_2016.py tests/test_suricata_otx_guard.py tests/test_network_features.py tests/test_strict_network.py tests/test_suricata_outcomes.py
bash packaging/build.sh
```

Fedora 44 RPM paketi `packaging/build.sh` ile derlenir;
yayımlanan paketin özeti `packaging/release.sh` tarafından `release/<sürüm>/SHA256SUMS` dosyasına yazılır.
Kaynak testleri veya paketin depoda bulunması, hedef Fedora cihazında kurulumun ya da canlı DROP davranışının doğrulandığı anlamına gelmez.

[2.2.16 sürüm notları](docs/RELEASE-2.2.16.md) · [2.2.15 notları](docs/RELEASE-2.2.15.md) · [Önceki 2.1.6 notları](docs/RELEASE-2.1.6.md) ·
[Politika yapılandırması](docs/POLICY-CONFIGURATION.md) ·
[Ağ doğrulama planı](docs/NETWORK-PROTECTION-PLAN.md).
