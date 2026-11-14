# SatsumaSecurity 2.2.19

- **DNS filtresi artık devreye giriyor.** Bir engel listesi, hazırlık testinin sorduğu `example.com` adını engelliyordu; her test düşüyor, filtre açılmıyor, OTX ve DeepSeek ad çözemiyordu. Test adı artık hiçbir zaman engellenmez; diğer bütün engeller kalır.
- **DeepSeek istek sınırı.** Saatte 8 yerine varsayılan 60 istek (`deepseek_requests_per_hour`, 1-600), istekler arası 3 saniye. Başarısız istekler (DNS yok, zaman aşımı) hakkı tüketmez. Durum düğmesi kalan hakkı gösterir.
