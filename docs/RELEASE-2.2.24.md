# SatsumaSecurity 2.2.24

- **Aynı konuda birden fazla kural.** DeepSeek aynı kimliği tekrar verirse Satsuma kurala içerikten türetilen benzersiz bir kimlik verir (ör. `SATSUMA-AI-PRIVESC-SETUID-SHELL-3FA2C1`). Birebir aynı kural için "zaten var" denir.
- **Geçerli durdurma önerisi.** DeepSeek'e süreç durdurma (`process_kill`), ağ izolasyonu ve dosya karantinası önerilerinin kurallara uygun biçimi anlatılır.
- **MITRE ATT&CK ve CISA KEV tanımları** `/var/lib/satsuma-core/tanim/` altında gelir. DeepSeek'e teknik numarasıyla birlikte tanımı gönderilir; iptal edilen numaralar (ör. T1562.001 → T1685) otomatik çevrilir. Tam kontrol tanım sayılarını gösterir. Tanımlar `tools/tanim_guncelle.py` ile yenilenebilir.
