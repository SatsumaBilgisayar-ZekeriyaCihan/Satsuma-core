# Satsuma Core 2.2.48 (2026-11-19)

Durum: kaynak adayı; RPM GitHub Actions'ta Fedora 44 içinde derlenir. İmzasız.

## unhide: iş parçacıkları artık gizli süreç sayılmıyor

Saha bildirimi: "unhide birçok gizli süreç tespit ediyor, sonlandıracak düğme
yok." Bulguların çoğu gizli süreç değildi. Bir iş parçacığı `kill(TID, 0)`
sorusuna yanıt verir ama `/proc` listesinde görünmez; doğrulama yalnızca bu
ikisine baktığı için her programın her iş parçacığı "gizli süreç" sayılıyordu.
Bunlardan birine sinyal göndermek programın tamamını (ör. tarayıcıyı) kapatırdı.

- Doğrulama artık `/proc/PID/status` içindeki `Tgid`'e bakar: süreç grubu
  `/proc` listesinde görünen bir TID iş parçacığıdır, bulgu olmaz.
- Açık gizli süreç bulguları her taramadan sonra ve "Yeniden doğrula" ile
  yeniden denetlenir. İş parçacığı çıkanlar (hangi programa ait olduğu ile) ve
  artık var olmayanlar gerekçesiyle kapatılır.

## Gizli süreci sonlandırma

Antivirüs → Taramalar'daki "unhide · gizli süreçler" kartında "Sonlandır…":

1. Yalnızca son taramanın açık bulgularındaki bir süreç seçilebilir.
2. Satsuma o anda yeniden doğrular; süreç hâlâ gizli değilse hiçbir şey
   sonlandırılmaz, bulgu gerekçesiyle kapatılır.
3. Süreç `pidfd` ile sabitlenir (PID başka bir sürece geçemez), bir kez daha
   doğrulanır, önce SIGTERM, 3 saniyede kapanmazsa SIGKILL gönderilir.
4. Çekirdek iş parçacıkları, Satsuma'nın kendisi ve iş parçacıkları (pidfd
   alınamaz) reddedilir.
5. Program yolu, komut satırı ve sonuç "Satsuma'nın işlemleri"ne kaydedilir.

## Derin motor kayıtları anlamlı

- "Derin motor kural incelemeleri" artık `pending` yerine "Sistem bilgisi
  toplama: onayınızı bekliyor", "yanlış alarm olarak işaretlendi" gibi cümleler
  yazar; ayrıntıda kural, program ve önem görünür.
- `deep_engine_evidence` kataloğa eklendi ("Derin motor gözlemleri"); kural
  adı kural dosyalarından okunur ("Yıkıcı dosya silme komutu · derin motor
  gözlemi", "48 olaylık pencere").
- Kaydın kendi ISO zaman metni yerine kayıt zamanı gösterilir.
