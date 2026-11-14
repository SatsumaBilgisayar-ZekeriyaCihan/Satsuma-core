# SatsumaSecurity 2.2.27

- **Satsuma kendi kendini bulgu saymaz.** Saha dökümünde günde yaklaşık 5.200 "Ağ keşfi" ve "Servis keşfi" bulgusu Satsuma'nın kendi salt okunur denetimlerinden geliyordu (`ip -j address show dev lo`, `systemctl list-units`). Bu birebir komutlar root olarak çalıştığında yalnızca kayıt amaçlı keşif kuralları onları artık bulgu saymaz; başka kullanıcıların ya da farklı biçimdeki komutlar yine kaydedilir.
- **Güncelleme kendi servislerini saldırı saymaz.** rpm/dnf çalışırken yalnızca satsuma* birimlerine dokunan `systemctl start/enable/stop` komutları kalıcılık ve servis durdurma kurallarını tetiklemez. Başka servisleri durdurmak ya da etkinleştirmek yine yakalanır.
- **RAM v2 durumu doğru.** Okunurken sonlanan ya da değişen tek bir süreç bileşeni "Sorunlu çalışıyor" gösteriyordu. Bu durum artık kapsam bilgisi olarak raporlanıyor; sorunlu durumu yalnızca tarayıcı ya da süreç listesi kullanılamadığında veya süreçlerin çoğu okunamadığında görünür.
- **Müdahale sonuçları doğru okunur.** "Süreç zaten sonlanmıştı", "bağlantı kesildi; doğrulandı" ve "ara adım" sonuçları artık açık metinle gösteriliyor.
