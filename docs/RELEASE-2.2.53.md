# Satsuma Core 2.2.53 (2026-11-19)

Durum: kaynak adayı; RPM GitHub Actions'ta Fedora 44 içinde derlenir. İmzasız.
2.2.51 ve 2.2.52'nin düzeltmelerini de içerir.

## Her açılışta çıkan kritik yanlış alarm

Saha ekranı (Olanlar → Bulgular): her yeniden başlatmada aynı saniyede iki
"Kritik · Doğrulanmış" bulgu: "Bütünlük denetimi başarısız: /opt/satsuma-core" ve
"Dosya veya dizin kimliği değişti: /etc/satsuma-core".

Neden: kritik yol bekçisi Satsuma dosyalarının kimliğini (inode) izler ve her
açılışta bu kaydı sıfırlar; ama yalnızca açılışın ilk uygulama doğrulaması
başarılıysa. Açılışın ilk saniyelerinde doğrulama henüz tamamlanmadığında hem
"doğrulama başarısız" yazılıyor hem de rpm-ostree'nin her açılışta yeniden
oluşturduğu /etc/satsuma-core önceki açılışın kaydıyla karşılaştırılıp
"kimliği değişti" sayılıyordu.

Şimdi: her yeni açılış yeni bir karşılaştırma kaydıyla başlar. Doğrulama iki
dakika boyunca yeniden denenir; ancak sonra da başarısızsa bildirilir. Açılış
sırasında gerçekten değiştirilen bir yol yine kritik bulgudur. Bu bulgular artık
`SATSUMA-GUARD-PATH` kuralını ve "Dosya bütünlüğü" türünü taşır.

Önceki açılışlarda yazılmış bu bulgular geçmiş olarak listede kalır.

## "Bilinmiyor" alanları

Bir sürece bağlı olmayan bulgularda (dosya bütünlüğü, ağ) Süreç ve PID artık
"Bilinmiyor" değil "—" gösterir: bilgi eksik değil, bu bulgular için yoktur.
Güven ("Orta"), Durum ("Yeni") ve Olay ("Dosya bütünlüğü") Türkçe etiketlerle;
her zaman boş olan "Hedef sistem" sütunu listeden kaldırıldı (ayrıntıda durur).

## Satsuma'nın ilk parola ekranı kendi kuralına takılıyordu

Saha ekranı: "[CRITICAL] Şüpheli pkexec hedef/argüman kullanımı … PID 5440
python3.15: öldürülecek süreç". Panelin ilk parola ekranı
`pkexec /usr/bin/satsuma-enroll-desktop --user KULLANICI --password-stdin`
çalıştırır. SATSUMA-POLKIT-001 "pkexec" ve "--user" sözcüklerini komutun
herhangi bir yerinde arıyordu; oysa bu `--user` pkexec'in değil, çalıştırdığı
programın argümanıdır. Kural "şüpheli/kritik" olduğu için otomatik durdurma
kapsamındaydı.

Kural artık pkexec'in sözdizimine göre bakar: `--user` yalnızca pkexec'in
hemen ardından, çalıştırılacak programdan önce gelirse sayılır; /tmp, /dev/shm
ve /var/tmp'den çalıştırma yine yakalanır. Yanıt kataloğundaki parmak izi
güncellendi.
