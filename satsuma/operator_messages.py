"""Operator results as one plain Turkish sentence for the panel; no Qt, tested on its own.

Yönetim işlemlerinin sonucunu panel için tek, sade bir Türkçe cümleye çevirir.
"""

DONE = {
    'enforcement': ('Otomatik durdurma açıldı.', 'Otomatik durdurma kapatıldı; zararlı programlar yalnızca bildirilecek.'),
    'interactive_process_test_mode': ('Bundan sonra program durdurmadan önce size sorulacak.', 'Programlar yeniden otomatik durdurulacak.'),
    'auto_network': ('Otomatik ağ engeli açıldı.', 'Otomatik ağ engeli kapatıldı.'),
    'lan_access': ('Yerel ağa erişim açıldı.', 'Yerel ağ kapatıldı; internet ve DNS açık.'),
    'subnet_protection': ('Alt ağ koruması açıldı.', 'Alt ağ koruması kapatıldı.'),
    'otx_enabled': ('OTX sorguları açıldı.', 'OTX sorguları kapatıldı.'),
    'otx_blocker': ('OTX eşik engeli açıldı.', 'OTX eşik engeli kapatıldı.'),
    'dns_filter': ('DNS filtresi açıldı ve sınandı.', 'DNS filtresi kapatıldı.'),
}
SIMPLE = {
    'login': 'Kilit açıldı; 30 dakika boyunca ayarları değiştirebilirsiniz.',
    'logout': 'Kilitlendi.',
    'allow_ip': 'Adres izinli listeye eklendi.', 'remove_allow_ip': 'Adres izinli listeden çıkarıldı.',
    'unblock': 'Adresin engeli kaldırıldı.', 'allow_domain': 'Alan adına izin verildi.',
    'remove_allow_domain': 'Alan adı izni kaldırıldı.', 'custom_list_update': 'Liste indirildi, doğrulandı ve uygulandı.',
    'custom_list_remove': 'Liste kaldırıldı.', 'modem_approve': 'Modem onaylandı.', 'modem_manual': 'Modem onaylandı.',
    'egress_profile': 'İnternet trafiği ayarı uygulandı.', 'process_approval_decide': 'Kararınız uygulandı.',
    'integrity_rebaseline': 'Yeni dosya referansı kaydedildi.', 'quarantine_restore': 'Dosya karantinadan geri yüklendi.',
    'modem_inventory': 'Modem adayları listelendi.',
}
JOBS = {
    'repair': 'Bakım kiti çalışıyor; sorunlar onarılıyor. Sonuç Sağlık bölümünde görünecek.',
    'boot_check': 'Doğrulama başladı; birkaç dakika sürebilir.',
    'security_scan': 'Antivirüs ve rootkit taraması başladı; sonuç Uzman görünümündeki taramalarda.',
    'systemd_security': 'Servis güvenliği denetimi başladı.', 'device_inventory': 'Aygıt envanteri çıkarılıyor.',
}
ERRORS = {
    'invalid_credentials': 'Parola yanlış.',
    'rate_limited': 'Çok fazla hatalı deneme; bir süre sonra yeniden deneyin.',
    'admin_hash_missing': 'Yönetici parolası belirlenmemiş. Bir uçbirimde "sudo satsuma-kur" çalıştırın.',
}
SESSION_LOST = ('Yönetici oturumu gerekli', 'süresi doldu')


def session_lost(error):
    return any(part in str(error or '') for part in SESSION_LOST)


def describe(method, params, result):
    """(tone, sentence) for one operator answer. tone: ok, warn, error."""
    params = params or {}
    result = result if isinstance(result, dict) else {'ok': bool(result)}
    error = result.get('error')
    if error or result.get('ok') is False:
        text = ERRORS.get(str(error), str(error or result.get('reason') or 'İşlem uygulanamadı.'))
        if session_lost(error):
            text = 'Oturumun süresi doldu; kilidi yeniden açın.'
        elif 'K7' in str(error):
            text = 'Bu işlem korumayı azalttığı için parola yeniden gerekli; parola doğrulanamadı.'
        return 'error', text
    if method in JOBS and (result.get('status') in ('RUNNING', 'REQUESTED') or result.get('accepted')):
        return 'ok', JOBS.get(method, 'İşlem başladı.')
    if method in DONE and type(params.get('enabled')) is bool:
        return 'ok', DONE[method][0 if params['enabled'] else 1]
    if method == 'application_control':
        action, decision = params.get('action'), params.get('decision')
        if action == 'decision':
            return 'ok', 'Uygulamaya izin verildi.' if decision == 'allow' else 'Uygulama engellendi.'
        if action in ('enable', 'disable'):
            return 'ok', 'Uygulama izinleri açıldı.' if action == 'enable' else 'Uygulama izinleri kapatıldı.'
        return 'ok', 'Uygulama kuralı güncellendi.'
    if method == 'service':
        return ('ok' if result.get('ok', True) else 'warn'), 'Servis işlemi tamamlandı: ' + str(params.get('name') or '')
    if method == 'wireguard':
        return 'ok', {'import': 'Profil içe aktarıldı.', 'up': 'VPN bağlandı.', 'down': 'VPN bağlantısı kesildi.',
                      'remove': 'Profil silindi.'}.get(params.get('action'), 'VPN işlemi tamamlandı.')
    return 'ok', SIMPLE.get(method, 'İşlem uygulandı.')
