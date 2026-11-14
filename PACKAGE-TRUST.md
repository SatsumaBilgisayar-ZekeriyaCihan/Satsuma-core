# DNF paket güveni — candidate.10

Bu sürüm libdnf5 plugin API 2.1 için yerel bir işlem engelleme eklentisi içerir.
DNF4 desteği henüz uygulanmamıştır. `dnf` komut adı tek başına sürümü belirlemez.
Ana paket ve mimariye özgü satsuma-core-dnf-guard paketi birlikte kurulmalıdır.

## Güven kaynağı

Başlangıç politikası boştur: mevcut RPM anahtarları, indirilen anahtarlar ve yerel
RPM veritabanı otomatik olarak güvenilir sayılmaz. Onaysız depolar reddedilir.
Tam anahtar parmak izi bağımsız bir kanaldan doğrulandıktan sonra yönetici açıkça
Satsuma üzerinden kaydeder:

```sh
satsuma-package-trust --repo DEPO_KIMLIGI \
  --source https://dogrulanmis-depo.example/metadata/ \
  --key-file /guvenilir-ortam/public.asc --fingerprint TAM_BUYUK_HARF_PARMAK_IZI
```

Kaynak, gerçek baseurl/metalink/mirrorlist değeriyle tam eşleşmelidir. Birden fazla
kaynak için --source tekrarlanır. Bu komut açıkça onaylanan anahtarı RPM denetimi
için de kaydeder; DNF içindeki otomatik anahtar alma yolu her zaman reddedilir.
Politika yerel bütünlük anahtarıyla HMAC doğrulanır; sertifikalar politikadaki tam
parmak izine karşı kontrol edilir. HMAC dış bir otoritenin dijital imzası değildir.
Dinamik güven dizini AIDE temelinden hariçtir; her paket geçidinde ayrıca doğrulanır.

## İşlem sırası

- Depolar kullanılmadan önce HTTPS kaynakları ve sabit anahtarlar doğrulanır.
  TLS, paket ve metadata imzası denetimleri zorlanır; hatalı depoyu atlama kapatılır.
  Metadata anahtar önbelleğine yalnız açıkça onaylı anahtarlar yüklenir.
- Çözülmüş indirme planı için depo, tam paket kimliği, boyut ve güçlü özet zorunludur.
  Sürüm düşürme reddedilir.
- RPM işlemi başlamadan önce açık dosyanın boyutu ve özeti karşılaştırılır. Her
  deponun sadece onaylı anahtarlarını taşıyan geçici RPM veritabanında gerçek imza
  doğrulanır; yalnız başarılı payload özeti yeterli değildir. Paket kimliği ayrıca
  karşılaştırılır. Hata veya zaman aşımı işlemi durdurur.
- Başarılı ve reddedilen geçitler korumalı package-trust/audit.jsonl dosyasına yazılır.

Metadata imzası olmayan depolar bu katı politikayla çalışmaz; Fedora varsayılan
kaynağının bu koşulu sağladığı varsayılmamalıdır. İmzasız yerel RPM kurulumu da
varsayılan olarak desteklenmez. Yalnız indirme yapan komutlar için indirme biter
bitmez ek doğrulama garantisi yoktur; gerçek dosya denetimi kurulumdan önce yapılır.

## Sınırlar ve doğrulama

Bu eklenti root veya çekirdeği ele geçirilmiş bir işletim sistemine karşı güven
kökü oluşturmaz. Root eklentiyi kapatabilir, doğrudan RPM kullanabilir veya belleği
ve yerel bütünlük anahtarını değiştirebilir. Güvenilir ilk kurulum ve anahtar kaydı
harici doğrulanmış ortamdan yapılmalıdır. Kurulum sırasında kontrol edilen inode
ile RPM tarafından daha sonra açılan yol arasında kötü niyetli root değişimini
engelleyen çekirdek düzeyinde bir garantisi yoktur.

Kaynak testleri: 240 başarılı. Gerçek GPG/RPM araçlarıyla sabit anahtarlı imzalı
paket kabulü, imzasız paket reddi, özet değişikliği ve bozulmuş payload reddi denendi.
Testlerde yerel dosya sahipliği taklit edildi; kriptografik işlemler gerçektir.
C++ eklentisi Fedora 44 üzerinde libdnf5 5.4.6.0 ile derlendi, iki RPM
birlikte kuruldu ve DNF tarafından yüklenmesi doğrulandı. Boş güven politikasıyla
gerçek DNF metadata isteği Satsuma tarafından reddedildi. Onaylı gerçek depo
üzerinden başarılı paket kurulumu bu aşamada henüz doğrulanmadı. DNF4 veya
bu eklentiyi yüklemeyen bir istemci için koruma etkin kabul edilmemelidir.
