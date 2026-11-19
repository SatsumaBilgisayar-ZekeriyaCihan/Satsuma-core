# Satsuma Core 2.2.60

Saha 2026-11-19: otomatik geri alma hiçbir dosyayı karantinaya alamıyordu.

`privd.request(op, timeout=15, path=SOCKET_PATH, **params)` soketin yolunu `path` adıyla alıyordu.
Geri alma isteği karantinaya alınacak dosyayı da `path=` ile gönderdiği için istemci privd'ye değil o
dosyaya bağlanmaya çalıştı ve "Connection refused" aldı. 2.2.56–2.2.59 arasında dosya karantinası
(cron, systemd birimi, autostart, authorized_keys, ld.so.preload, udev, sudoers.d, polkit kuralı) ve
`.wants` bağlantısı silme hiç çalışmadı; güvenlik duvarını geri yükleme ve hesap kilitleme `path`
kullanmadığı için etkilenmedi. Testler privd'yi taklit ederek istemci fonksiyonunu atlıyordu.

* Soket ayarları artık `socket_path` ve `socket_timeout`; hiçbir istek alanıyla çakışmaz.
* Gerçek bir Unix soketi üzerinden `path` alanı taşıyan uçtan uca test.
* Geri alma privd'ye ulaşamazsa kritik bulgu: SATSUMA-PRIVD-001 (en çok saatte bir).
