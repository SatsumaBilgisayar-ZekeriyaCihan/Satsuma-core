# SatsumaSecurity 2.2.26

- **DNS uygulama izni beklemez.** Uygulama ağ koruması DNS yönlendirmesinden önce çalıştığı için onaylanmamış programların DNS sorguları (Satsuma'nın kendi DNS testi dahil) bekletiliyor ve zaman aşımına uğruyordu. 53. port artık onay beklemeden Satsuma'nın DNS filtresine gider; filtre ve MITM koruması değişmez, diğer bağlantılar yine onay ister.
- **DNS testi kurulumu bozmaz.** DNS hazırlık testi başarısız olursa kurulum başarısız sayılmaz; sağlık ekranı uyarı gösterir.
