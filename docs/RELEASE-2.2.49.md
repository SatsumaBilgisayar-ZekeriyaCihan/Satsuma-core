# Satsuma Core 2.2.49 (2026-11-19)

Durum: kaynak adayı; RPM GitHub Actions'ta Fedora 44 içinde derlenir. İmzasız.

## Kurallar sayfası gerçekte ne olduğunu söylüyor

Saha sorusu: "Kurallar neden durdurmuyor?" Sayfa "0 tanesi programı doğrudan
durdurabilir · 251 tanesi yalnızca bildirir" diyordu. Bu sayı yalnızca kural
dosyasına yazılmış "kill" eylemlerini sayıyordu; hiçbir kural dosyasında yok,
çünkü durdurmaya merkezi otomatik durdurma ilkesi (satsuma.enforcement) karar
verir. Gerçekte temel 231 kuraldan 136'sı ilke açıkken eşleşince programı
durdurur.

- Her kuralın "Ne yapar" sütunu: "Programı durdurur", "Yalnızca bildirir
  (sıradan programların da yaptığı bir iş; bilerek durdurulmaz)", otomatik
  durdurma kapalıysa "Durdurabilir, ama … şu an yalnızca bildirir", DeepSeek
  kurallarında onaylı önerinin durdurma olup olmadığı.
- Özet satırı otomatik durdurmanın açık/kapalı olduğunu ve son 24 saatte
  otomatik durdurmaların nasıl bittiğini söyler: durdurulan, sinyal gitmeden
  zaten kapanmış olan, güvenlik denetiminin izin vermediği, başarısız olan.
- Sütunlar sadeleşti (Kural, Ne yapar, Önem, Tür, Son müdahale, Kimlik); kanıt
  şartları, imza ve ilke kararı seçili kuralın teknik görünümündedir.

Yalnızca bildiren 95 kural ekran görüntüsü, pano okuma, `ps`, BPF araçları
gibi sıradan programların da her gün yaptığı işleri tanır; bunlar durdurulsa
masaüstü programları da dururdu. Durdurma, program hâlâ çalışıyorsa yapılabilir:
milisaniyede biten bir komut sinyal gitmeden biter ve "zaten kapanmıştı" olarak
kaydedilir.
