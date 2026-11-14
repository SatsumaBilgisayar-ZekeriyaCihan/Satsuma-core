# Aşama 36 — Python giriş kimliği ve Exec Guard panel kayıtları

## Mimari ve anlam sınırları

- `satsuma.exec_guard`, `FAN_OPEN_EXEC_PERM` ile çekirdeğin **ikili çalıştırma** iznini değerlendirir. Bu aşamada mevcut engelleme politikaları **değişmedi**.
- Fanotify karar anında `/proc/<pid>/cmdline` yeni Python betiğini güvenilir biçimde yansıtmayabilir. Bu nedenle Exec Guard'ın karar yoluna betik çözümleme eklenmedi. Python betiği kimliği, **çalışan süreç** üzerindeki App-Control atıf aşamasında doğrulanır.
- `satsuma.python_entry`, süreç başlangıç kimliği, exe, cwd ve cmdline kararlılığını kontrol eder; gerçek normal dosyayı tanıtıcıdan SHA-256 ile okur; `-c`, `-m`, stdin, okunamayan veya 8 MiB sınırını aşan girişleri doğrulanmamış olarak raporlar. Komut satırının argümanları kaydedilmez.
- Aynı Python yorumlayıcısını kullanan iki **doğrulanmış farklı betik**, artık `application_key` değerini paylaşmaz. Giriş kimliği doğrulanamayan Python işlemleri için kalıcı `always` ve `application` izni reddedilir; tek bağlantı kararı ayrı tutulur.
- İlgili App-Control onayı **ağ bağlantısı iznidir**. “Teyit Edildi” ifadesi programın veya betiğin zararsız olduğunu kanıtlamaz.
- `exec_guard_view.events` Exec Guard kayıtlarını salt okunur, sınırlı boyutta ve symlink izlemeksizin sunar. Reader `exec_guard_events` metodunu dışa açar.
- **Durdurulan İşlemler** panelindeki mevcut tablo yalnız gerçekten sinyalle sonlandırılıp çıkışı doğrulanmış süreçleri gösterir; yeni ikinci tablo Exec Guard'ın **çalıştırmayı engellediği girişimleri** gösterir. Engellenen girişim, sonlandırılmış süreç değildir. PID ve `/proc/PID` yolu olay anına aittir; canlı süreç hâlâ mevcut olmayabilir.

## Bilinçli olarak değiştirilmemiş sınırlar

- Yeni fanotify olay türü, systemd servis yetkisi, PID sonlandırma, SELinux, Suricata, nftables, DNS, OTX, ClamAV, RAM okuma veya karantina politikası eklenmedi.
- `-m` ve `-c` ile yürütülen Python girişlerinin gerçek ithal modül/dinamik kod kimliğini tam belirlemek bu sürümün kapsamında değildir. Bir betiğin disk özetinin eşleşmesi, çalışan yorumlayıcı belleğinin aynı kodu yürüttüğünü ispatlamaz.
- PyQt6 olmadan panel işleyişi test edilemedi; bu aşama Fedora gerçek cihaz doğrulaması değildir.

## Geri dönüş

Bu kaynak değişiklikleri geri almak için bu aşamanın değiştirdiği Python modüllerini 35. aşama ZIP paketindeki özgün sürümlerine döndürün; yeni `satsuma/python_entry.py`, `satsuma/exec_guard_view.py`, `tests/test_python_app_identity_stage36.py` ve bu belgeyi kaldırın. Canlı servis, veritabanı veya güvenlik ayarı değiştirilmediğinden sistemsel geri alma işlemi bu aşamada gerekli değildir.
