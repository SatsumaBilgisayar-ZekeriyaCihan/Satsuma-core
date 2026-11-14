# SatsumaSecurity 2.2.20

DeepSeek kural akışı gerçek yanıtlarla çalışır.

- **Gerçek DeepSeek yanıtları kabul edilir.** Düzenleyiciden gönderilen paketlere içerik özeti otomatik eklenir; liste halindeki bellek eylemleri, hedef türü "process" olan bilgi amaçlı öneriler ve müdahale önerisi içermeyen yanıtlar (yalnızca kayıt önerisi eklenir) artık reddedilmez.
- **Sessizce çalışmayan kurallar engellenir.** Motorun anlamadığı puanlama koşulları (`action == ...`) kuralın hiçbir şey yakalamamasına yol açıyordu; artık açık bir hatayla reddedilir ve DeepSeek'e puanlama yazmaması söylenir.
- **GPG imzası gerekmez.** Yönetici onayı kuralı Satsuma'nın yerel anahtarıyla mühürler; onaydan sonra doğrudan etkinleştirilebilir. Değiştirilmiş kural yine yüklenmez. GPG imzası isteğe bağlı olarak kabul edilir.
