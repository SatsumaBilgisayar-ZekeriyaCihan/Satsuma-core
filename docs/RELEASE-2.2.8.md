# SatsumaSecurity 2.2.8 — otomatik engelleme ve bellek koruması

2.2.7'nin yerini alır ve onun her şeyini içerir.

## Yeni: otomatik engelleme

Kurallar artık yalnızca bildirmiyor. **Otomatik engelleme** varsayılan olarak
açık: yüksek ya da kritik önemli şüpheli ve muhtemel saldırı kuralları ile
kritik göstergeler (228 kuralın 114'ü) eşleşince, o eşleşmeyi yapan programın
kendisi durdurulur. Kimliği (PID, başlangıç zamanı, program yolu) sinyalden
hemen önce yeniden doğrulanır.

- Asla durdurulmayanlar: Satsuma ve panelden yaptığınız işlemler, TeamViewer,
  AnyDesk, masaüstü (GNOME), paket yöneticisi ve temel sistem servisleri.
- Durdurulan her program bulgularda "Satsuma bir programı durdurdu" diye
  görünür.
- Orta ve düşük önemli kurallar yalnızca bildirir.
- Kapatmak: Yönetim → Ağ koruması → "Otomatik engelleme" (yönetici parolası
  yeniden sorulur). Açmak için oturum yeterli.
- Operatör duraklatması ve bütünlük kilitleri yine geçerlidir.

## Bellek koruması (dış incelemeye göre)

- Bellek farkı nedeniyle bir program durdurulacaksa, SIGTERM'den ve SIGKILL'den
  hemen önce kod yeniden karşılaştırılır; fark kaybolduysa sinyal gönderilmez.
- İşleme bir debugger bağlıysa ya da bu okunamıyorsa bellek kaynaklı otomatik
  durdurma yapılmaz; karar size bırakılır.
- Taramanın kısmi olduğu (büyük programlarda yalnızca ilk 1 MiB) ve atlanan
  bölgeler açıkça bildirilir; tarama sırası belirlidir. Büyük programların
  bellek haritası artık 1 MiB'a kadar okunur.
- Yeni gözlem: dosyası olmayan çalıştırılabilir bellek (anonim, memfd,
  silinmiş dosya) listelenir. Tarayıcı ve Java gibi programlar bunu meşru
  olarak kullanır; yalnızca gözlemdir, hiçbir zaman durdurma yapmaz.

Önceki sürüm: `docs/RELEASE-2.2.7.md`.
