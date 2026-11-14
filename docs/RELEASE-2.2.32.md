# SatsumaSecurity 2.2.32

- **Kural motoru 17 kat hızlı.** Olay başına değerlendirme 1,76 ms'den 0,105 ms'ye indi. Olayın alanları artık her kural için değil, olay başına bir kez okunuyor. Komuttaki programla ilgisi olmayan kurallar denenmiyor. 6.000 farklı olayda kararlar öncekiyle birebir aynı.
- **Ham olay kaydı yok; olaylar akışta.** Ana makine ve Suricata olayları veritabanına yazılmıyor, `/run/satsuma-flow/flow.sock` üzerinden kural motoruna akıyor ve 0,25 sn içinde değerlendiriliyor. Kayıt yalnızca süreç şüpheliyse ya da sonlandırma söz konusuysa alınıyor; kayıtla birlikte 30 dakikalık bellek içi geçmişten süreç zinciri ve son olayları da yazılıyor. Daha önce saklanan ham olaylar ve normalized satırları kurulumdan sonra bir kez siliniyor; bulgular, incelemeler ve müdahaleler kalıyor.
- **Akış bekçisi (satsuma-flow-guard).** Akışı 5 saniyede bir denetliyor. Kural motoru susarsa yeniden başlatıyor (en fazla 5 dakikada bir). Olay kaybolursa ya da akışa olay gelmezse "Kayıtlar → Akış bekçisi" altında bildiriyor.
- **Satsuma'nın kendi komutları ayrı.** Servis sağlığı, ağ kimliği, uzak sınırlama ve DNS nöbetçisinin çalıştırdığı komutlar artık olay ya da bulgu olarak görünmüyor; ayrı sayılıyor. Bir olayın Satsuma'nın sayılması için Satsuma sistem biriminden gelmesi ve root sahipli, güvenilir bir program olması gerekiyor. Kabuklar (bash, sh), indirme ve ağ araçları (curl, nc...) ve /tmp, /home altındaki programlar hiçbir zaman kendi olayı sayılmıyor. Sorgu sıklıkları değişmedi.
- **OTX alan adları DNS filtresine ulaşıyor.** OTX işçisinin DNS engel dosyasını yazma yetkisi (CAP_CHOWN) eksikti; bulduğu alan adları hiç engellenmiyordu. Yönetim panelindeki DNS satırı artık OTX'in kaç alan adını engellediğini, kaçını denetlediğini ve son hatasını gösteriyor.

Kurulumdan sonra akışın durumu:

```
sudo sqlite3 /var/lib/satsuma-core/core.db "select body from state where key='flow.health'"
sudo sqlite3 /var/lib/satsuma-core/core.db "select body from state where key='flow_guard.health'"
```
