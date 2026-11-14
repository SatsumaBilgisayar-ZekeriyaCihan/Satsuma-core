# SatsumaSecurity 2.2.23

- **Kendi güncellemesi saldırı sayılmaz.** Satsuma güncellenirken kurulum betiği kendi servislerini durdurur; bu artık "Savunma atlatma — güvenlik aracı devre dışı" kritik bulgusu üretmez. Yalnızca rpm/dnf çalışırken ve yalnızca satsuma* servisleri için geçerli; auditd, suricata ya da güvenlik duvarını durdurmak yine kritik bulgudur.
