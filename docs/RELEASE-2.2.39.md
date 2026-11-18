# Satsuma Core 2.2.39 (2026-11-18)

Durum: kaynak adayı; RPM GitHub Actions'ta Fedora 44 içinde derlenir
(.github/workflows/rpm.yml). İmzasız. Fedora Atomic cihazında yeniden denenmedi.

## Fedora Atomic saha raporu (2026-11-18)

- 2.2.38 Fedora Atomic'te: "Kurulum bütünlüğü: NotADirectoryError: [Errno 20]
  Not a directory: 'opt'"; kendini doğrulayan tüm servisler (core, teams, reader,
  derin motor, ...) başlayamadı, bakım kiti kuralı gereği hiçbir şeyi onarmadı.
- Neden: bütünlük okuyucusu yolu her adımda bağ izlemeden açıyordu; Atomic'te
  /opt, /home, /root, /srv, /mnt ve /usr/local /var'a giden bağlardır.
- Düzeltme (`installer/integrity.py` `open_parent`): bir bağ yalnızca root'a
  aitse ve başkasının yazamadığı root klasöründeyse izlenir. Başkasının
  yazabildiği klasördeki bağ, başka kullanıcının bağı, dosyanın kendisinin bağ
  olması ve bağ döngüsü reddedilir (tests/test_atomic_links.py).
- Karantina aynı yol açıcıyı kullanır ve Atomic'in /var köklerini kabul eder
  (/var/home, /var/opt, /var/roothome, /var/usrlocal, /var/srv); önceden
  Atomic'te ev klasöründeki hiçbir dosya karantinaya alınamazdı.

