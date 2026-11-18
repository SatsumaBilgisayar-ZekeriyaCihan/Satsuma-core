# Satsuma Core 2.2.46 (2026-11-18)

Durum: kaynak adayı; RPM GitHub Actions'ta Fedora 44 içinde derlenir. İmzasız.

## SATSUMA-FILELESS-002 birkaç saniyede bir: kaynağı Satsuma'nın kendisiydi

Saha kaydı (Fedora COSMIC Atomic, bootc dağıtımı): `/tmp/.tmpR0JZc2` için
"Fileless — /dev/shm veya /tmp'den yürütme", komut `bootc status --format=json
--format-version=1`, üst süreç Satsuma okuyucusu (`satsuma.dashboard_api`).

- "Sistem kökeni ve paket riski" sayfası her 3 saniyede okuyucuya soruyordu;
  okuyucu her seferinde `rpm -qa`, `rpm-ostree status` ve `bootc status`
  çalıştırıyordu. bootc kendini `/tmp/.tmpXXXXXX` adlı geçici bir kopyaya yazıp
  oradan yeniden çalıştırıyor; kural da her seferinde bunu yakalıyordu.
- Sayfa artık kendiliğinden yenilenmez (açılışta ve "Yenile" ile); okuyucu
  raporu 10 dakika saklar.
- `satsuma.self_copy`: bootc'nin kendi kopyası yalnızca kanıtla tanınır — aynı
  süreç bir an önce aynı argümanlarla root'a ait `/usr/bin/bootc`'yi çalıştırmış
  ve okumuş olmalı (çekirdek denetim kaydı, süreç zinciri). Bu durumda bulgu
  kaydedilmez. Kanıt yoksa `/tmp`'den çalışan her şey eskisi gibi bulgudur;
  kabuk, yorumlayıcı ya da başka bir ad, kullanıcı veya argüman tanınmaz.

2.2.45'teki panel yeniden tasarımı ve 2.2.44'teki DNS ağ alanı bu sürümde de var.
