# SatsumaSecurity 2.2.18

DeepSeek araştırma stüdyosunun elden geçirilmesi.

- **Gerçek hata gösterilir.** Panel her hatayı "Yetkili arka uca erişilemedi" diye gizliyordu. Artık sebep Türkçe ve kodla yazılır: oturum süresi doldu, onay eksik, saatlik sınır, anahtar izni vb.
- **Oturum düşünce yeniden giriş istenir.** Yükseltme sonrası geçersiz kalan yönetici oturumu temizlenir.
- **"DeepSeek durumunu kontrol et"** anahtarın neden kullanılamadığını (yok, sahip, izin 0600, bağlantı, içerik) ve bu saat kalan istek hakkını (8'de kaç) gösterir.
- **Bellek kuralları artık üretilebilir.** Şema her test olayında `cmd` istiyordu; bellek olaylarında `action` kabul edilir.
- **Kurallar kendi olayını yakalar.** DeepSeek'e eşleştiricilerin tam anlamı anlatılır; yol/adres için `cmd_arg_contains` eklendi.
- **Uçtan uca test.** DeepSeek biçimindeki yanıt → doğrulama → yalıtılmış motor testi → onay → GPG imzası → aktivasyon → gerçek yükleyici → yalnızca kendi olayını yakalama. Gönderilen 231 kural ve bütün şemalar da test edilir.

Kural akışı değişmedi: öneri → doğrulama → izole test → inceleme → sizin GPG imzanız → aktivasyon. Kuralın önerdiği müdahale ayrıca yetkilendirilmeden çalışmaz.
