# SatsumaSecurity 2.1.6 — ağ müdahale sürümü

Bu depo tek kaynak sürüm olarak 2.1.6'yı yayımlar; eski binary,
RPM ve kaynak arşivleri yeni kaynak ağacına dahil edilmez. Sürüm
numarasının güncellenmesi güvenli kurulum veya üretim kabulü anlamına gelmez.

## Düzeltmeler

- **OTX**: blocker_mode açıkken varsayılan `any_pulse`; doğrulanmış HTTPS
  yanıtında en az bir OTX pulse varsa ikinci tehdit kaynağına gerek olmadan
  hedef IP engeli istenir. İzin listesi, DNS resolver koruması, kritik bütünlük
  kilidi ve nftables geri okuması geçerliliğini korur.
- **Suricata**: uygun tek alarm, OTX'yi beklemeden müdahale üretir. Hem
  yerel sistemden dışarı çıkan hem içeri giren trafiğin doğru uzak uç IP'si
  hedeflenir. Yönlendirilmiş trafikte conntrack denetimi korunur.
  Yönetilen guard tablosu output yönünü de engeller ve yalnız önceden
  doğrulanmış layout için kademeli geçiş uygular.
- **Ardışık IP**: farklı IP'ler 300 saniyelik pencere boyunca sayılır;
  birbirleriyle eşzamanlı bağlantıda olmaları gerekmez. İlk gözlem
  engellenmez; eşik oluşunca yalnız yeni IP engelleme hedefidir.

## Kanıtın sınırları

Operatörün canlı Fedora çıktılarına göre OTX hizmeti `active`, TLS
`verified=true` ve `match_mode=any_pulse`; OTX 35-pulse bir IP için
engelleme talebi üretmiş ancak `operator_allowlisted` sonucu nedeniyle
o IP'ye blok uygulamamıştır. `satsuma_core` tablosunda paket DROP
sayaçları çalışırken `satsuma_otx_guard` blok setleri boş gözlenmiştir.
Bu nedenle doğrudan **OTX kaynaklı başarılı DROP** henüz kanıtlanmamıştır.

CI Python regresyon testlerini ve Fedora 44 kaynak RPM derlemesini
kontrol etmelidir. Üretim öncesi gerçek Fedora 44 kurulum, yeniden başlatma,
SELinux enforcing, DNS/izin listesi etkileri, nftables düşen paket sayacı,
rollback ve zorunlu iş yükü sürekliliği ayrıca doğrulanmalıdır.

Diğer ürün modüllerine fonksiyonel değişiklik yapılmamıştır; ağ dışındaki
bilinen eksikler giderilmiş kabul edilmez.
