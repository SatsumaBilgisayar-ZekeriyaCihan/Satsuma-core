# SatsumaSecurity 2.2.2 — güvenli kaldırma

2.2.1'in bütün düzeltmelerini içerir ve onun yerini alır. 2.2.1 paketi
yayından çekildi: kaldırıldığında USB klavye ve fareyi çalışmaz bırakabiliyordu.

## Düzeltilen

- **Ürün kaldırılınca USB klavye ve fare çalışmıyordu** (saha bildirimi):
  kaldırma artık ilk iş olarak USB çekirdek parametresini siliyor, bütün
  USB aygıtlarını hemen yeniden yetkilendiriyor, USBGuard ayarlarını ve
  servis durumunu kurulumdan önceki hâline döndürüyor.
- `kur.sh --kaldir`: önce USB girişini kendisi geri verir, sonra ürünü
  kaldırır; eski 2.2.0 kurulu makinede de güvenlidir.

2.2.1'deki düzeltmeler için: `docs/RELEASE-2.2.1.md`.
