# SatsumaSecurity 2.2.28

- **DNS yenilemesi kendi servisini her dakika başlatmaz.** Dakikalık DNS yenilemesi, yapılandırma değişmemiş olsa bile her seferinde `systemctl start satsuma-core-dns.service` çalıştırıyordu. Bu komut "Kalıcılık" kuralını günde 222 kez tetikledi ve her seferinde sonlandırma yetkisi verildi. Artık önce servisin çalışıp çalışmadığına bakılıyor; servis yalnızca kapalıysa başlatılıyor.
- **"systemctl cat" birim yazmak sayılmaz.** Kalıcılık kuralındaki cp/mv/tee/cat kalıbı komutun ortasında geçen "cat" sözcüğünü de yakalıyordu. Kalıp artık komutun kendisine bakıyor. Birim dosyalarına cp, mv, tee ve cat ile yazmak, `systemctl enable` ve `systemctl start` yine yakalanır.
