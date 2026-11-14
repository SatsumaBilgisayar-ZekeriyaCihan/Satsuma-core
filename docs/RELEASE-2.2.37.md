# SatsumaSecurity 2.2.37

## Neden bu sürüm
- 10 Kasım'da yayımlanan 2.2.36 paketi ile ana daldaki 2.2.36 kaynağı farklıydı: kaynağa sonradan eklenenler (exec-guard, SATSUMA-RAM-001'in durdurulması, Windows ile ortak bellek kararı) pakette yoktu. 2.2.37 ana dalın tamamını içerir.

## RAM bellek modülü: engellenmesine karşı
- **ptrace_scope 3 artık "daha sıkı" sayılmıyor.** 3, bellek tarayıcısını kör eder ve çekirdek onu yeniden başlatmaya kadar düşürmez (sahibinin kararı 2026-11-10: 2 kalır). Çekirdek bekçisi 3'ü görünce "RAM tarayıcısı kör edildi" alarmı verir.
- **Kaynağı geri alınır.** 3'ü yazan sysctl dosyası satırı yorum satırına çevrilir; Satsuma'nın dosyasını gölgeleyen aynı adlı dosya kanıt klasörüne taşınır; 3 içeren açılış bağımsız değişkeni bütün çekirdeklerden kaldırılır. Hiçbir dosya silinmez; özgün hâli `/var/lib/satsuma-core/kernel-guard/ptrace-sources/` altında saklanır. Fedora'nın kendi `10-default-yama-scope.conf` dosyasına dokunulmaz (Satsuma'nın değeri onu geçersiz kılar).
- **Dakikada bir denetim.** Değer ve bütün kaynakları dakikada bir, bekçi başlar başlamaz da bir kez denetlenir; değerin kendisi yine saniyede bir okunur.
- **Tarayıcı kimliği.** RAM tarayıcısı yalnızca `satsuma-ram-clamd.service` içindeki clamd'ye güvenir. Önceden aynı `clamscan` kullanıcısıyla çalışan herhangi bir süreç (Fedora'nın sistem clamd'si de bu kullanıcıyla çalışır) soketi değiştirip her bellek parçasına "temiz" diyebilirdi.
- **clamd kopyaları taranır.** Önceden `/usr/sbin/clamd` programının her süreci taramadan atlanıyordu; artık yalnızca sistem servisi olarak çalışan clamd atlanır.
- **Durdurulamaz.** `satsuma-ram-clamd` her çıkıştan sonra yeniden başlar, vazgeçmez, açılışta kendiliğinden başlar. Çekirdek bekçisi durdurulan `satsuma-ram-clamd`'yi ve RAM işçisini çalıştıran `satsuma-core`'u yeniden başlatır (rpm/dnf çalışırken değil). Panelden durdurulan `satsuma-core` da yaklaşık 30 saniyede yeniden başlar.
- `satsuma-temporary-scan` var olmayan bir birime bağlıydı; artık RAM clamd'sine bağlı.

## Doğrulama sınırı
- Kaynak testleri: 2251 geçti, 0 başarısız, 7 atlandı (yalnızca Fedora'da çalışan testler; Ubuntu 24.04 kapsayıcısı).
- Paket yerelde derlendi ve imzalanmadı. Fedora cihazında denenmedi.
- Varsayım: çekirdek ve systemd sürümünüzde davranış testlerdekiyle aynıdır. Kurulumdan sonra `cat /proc/sys/kernel/yama/ptrace_scope` 2 olmalı; 3 ise bilgisayar yeniden başlatılmalı. `dns_filter_health` doğrulanmalı.
