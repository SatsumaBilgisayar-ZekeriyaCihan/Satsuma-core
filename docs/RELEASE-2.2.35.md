# SatsumaSecurity 2.2.35

- **853 portu (TLS üzerinden DNS) hiçbir Satsuma tablosunda izinli değil.** Bu makinede 853 portundan şifreli veriyle C2 trafiği kanıtlandı; yerel ağ tablosunun DNS istisnaları, Satsuma hiç kullanmadığı hâlde 853'ü kabul ediyordu. Ana tablonun varsayılan düşürmesi yine engelliyordu; açık izin kaldırıldı.
- 2.2.34'teki bütün düzeltmeleri içerir (DNS filtresinin her dakika yeniden başlaması, OpenSnitch /usr/bin/dnsmasq izni, komut okuma). 2.2.34 paketi bir test çalıştırması başarısızken oluştu; onun yerine bu sürümü kurun.
