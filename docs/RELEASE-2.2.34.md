# SatsumaSecurity 2.2.34

- **DNS filtresi her dakika yeniden başlamıyor.** Yenileme yeni listeyi deniyor, DNS sınaması başarısız olunca eskisine dönüyor ve bir dakika sonra yeniden deniyordu; her seferinde DNS kısa süre yanıtsız kalıyordu. Listeden yalnızca ad çıkıyorsa dnsmasq artık en fazla 30 dakikada bir yeniden başlıyor; yeni engellenen ad yine hemen uygulanıyor.
- **OpenSnitch DNS filtresini engellemiyor.** Fedora `/usr/sbin`'i `/usr/bin` ile birleştirdiği için Satsuma'nın OpenSnitch izni (`/usr/sbin/dnsmasq`) hiç eşleşmiyordu; DNS filtresinin dış sorguları engelleniyordu. İzin artık iki yolu da kapsıyor.
- **Komut okuma düzeltildi.** `sudo` ve kabuklarda yalnızca programın kendi seçenekleri sayılıyor: `sh -c -- ps -p 28956` artık "SUID shell", `sudo journalctl -n 30` artık "sudo -n" sayılmıyor (`chattr -i`, `ssh -R`, `find -perm` gibi yanlış okumalar da kalktı).
