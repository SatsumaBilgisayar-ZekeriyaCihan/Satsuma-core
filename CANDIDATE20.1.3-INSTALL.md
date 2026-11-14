# 20.1.3 test RPM — kurulum, yükseltme ve kaldırma

Bu **tam ve imzasız** RPM, 20.1.2 kaynaklarından hazırlanan yeni adaydır. GPG
anahtarı içermez. Debian üzerinde Fedora 44 hedef metadata'sıyla derlenmiştir.
Gerçek Fedora 44 kurulum kabulü tamamlanmamıştır. Mevcut ana makine yerine yerel
konsolu olan ayrı Fedora 44 x86_64 test sisteminde kabul testi yapın. Ağ filtresi
kurulum sırasında etkinleşir; uzaktan erişim kesilebilir.

Ön koşul: Suricata >=7, NFQUEUE desteği, geçerli Suricata yapılandırması ve en az
bir başarıyla yüklenen algılama kuralı. RPM bu kontrolleri çalıştırır; eksikse
kurulumu reddeder. Fedora bağımlılıkları DNF tarafından çözülmelidir.

Aynı klasöre indirdiğiniz dosyalar için önce:

```bash
sha256sum -c SHA256SUMS
```

Sonra ilk kurulum veya mevcut sürümün yükseltilmesi için:

```bash
sudo dnf install ./satsuma-core-2.0.0-0.candidate20.1.3.fc44.x86_64.rpm
```

Komut hata verirse sonraki adıma geçmeyin. İmzasız paketi sistem politikası
reddederse denemeyi durdurun; imza denetimini atlamayın. SELinux'u kapatmayın,
/etc/passwd, group, shadow veya gshadow izinlerini değiştirmeyin.

Başarılı kurulumdan sonra masaüstü hesabını hazırlayın:

```bash
sudo satsuma-setup --user "$USER"
sudo satsuma-status
```

Grup üyeliği için oturumu kapatıp açın. Paneli normal kullanıcı olarak çalıştırın:

```bash
satsuma-dashboard
```

Yönetim → Yönetici erişimi ve doğrulama sayfasında oturum açın. App Control karar
penceresindeki “Bir kez” yalnız gösterilen bağlantı için en fazla 5 dakikadır.
“Bu uygulama için hatırla” aynı doğrulanmış dosya kimliği ve kullanıcı altındaki
alt süreçleri kapsar. REQUESTED uygulama sonucu değildir; kararın uygulanmasını
bekleyin. Uygulama tamamen kapalıysa bildirim penceresi çalışmaz.

Aşağıdaki salt okunur tanılar kurulum/servis sorununu incelemek içindir:

```bash
systemctl show satsuma-core-gateway.service satsuma-core-sentinel.service satsuma-teams.service satsuma-app-control.service -p Id -p ActiveState -p SubState -p Result -p NRestarts -p ExecMainStatus --no-pager
sudo journalctl -b -u satsuma-core-gateway.service -u satsuma-core-sentinel.service -u satsuma-teams.service -u satsuma-app-control.service --no-pager
getenforce
```

Kaldırma:

```bash
sudo dnf remove satsuma-core
```

Kaldırma hata verirse zorla unmount, toplu firewall flush veya bağımlılık atlama
uygulamayın. Mevcut kaldırma akışı önce zamanlayıcıları durdurur; yalnız Satsuma
kurallarını temizlemeyi dener. Meşgul/yabancı mount hata sayılır. Kullanıcı/grup
kimlikleri ve güvenlik kayıtları otomatik silinmez; bu bir tam veri silme işlemi
değildir. Gerçek Fedora kaldırma ve yeniden başlatma davranışı henüz doğrulanmadı.

Geri dönüş gerekiyorsa önce tanı ve yapılandırma yedeğini alın. Önceki paketler
değiştirilmedi; doğrulanmamış otomatik downgrade/kurtarma betiği bu teslime eklenmedi.
