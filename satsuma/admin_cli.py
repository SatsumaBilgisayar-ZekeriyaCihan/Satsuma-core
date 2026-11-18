# -*- coding: utf-8 -*-
"""Root-only interactive provisioning CLI for the dashboard admin credential.

Commands:
    satsuma-admin set-password
    satsuma-admin password-status
    satsuma-admin reset-password

Passwords are read only from an interactive TTY with :mod:`getpass`; plaintext
passwords are never accepted on argv, logged, or written to disk.
"""
from __future__ import annotations

import argparse
import getpass
import json
import os
import sys
import time
from pathlib import Path

from .dashboard_auth import (
    ADMIN_HASH_PATH,
    admin_hash_status,
    hash_password,
    remove_admin_hash,
    write_admin_hash,
)


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="satsuma-admin")
    sub = parser.add_subparsers(dest="command", required=True)

    for command, help_text in (
        ("set-password", "interactively set the dashboard admin password"),
        ("password-status", "show whether the admin password is provisioned"),
        ("reset-password", "remove the admin password hash (fail-closed login)"),
    ):
        item = sub.add_parser(command, help=help_text)
        item.add_argument(
            "--hash-path",
            default=str(ADMIN_HASH_PATH),
            help=argparse.SUPPRESS,
        )
    sub.add_parser("set-otx-key", help="securely provision the OTX API key")
    modem = sub.add_parser("modem", help="enroll the modem: automatic, or the MAC typed with --mac")
    modem.add_argument("--mac", help="modem MAC address from its label")
    quarantine = sub.add_parser("karantina", help="list, quarantine (with boot rollback) or restore files")
    quarantine.add_argument("islem", choices=("liste", "al", "geri-al"))
    quarantine.add_argument("hedef", nargs="?", help="path for 'al', quarantine id for 'geri-al'")
    ssh = sub.add_parser("ssh", help="SSH keys: list, mark known, quarantine; stop the SSH server")
    ssh.add_argument("islem", choices=("liste", "tanidik", "karantina", "sunucu-kapat"))
    ssh.add_argument("hedef", nargs="*", help="fingerprint or private key path; for an authorized key: <file> <fingerprint>")
    sub.add_parser("cekirdek", help="read the kernel security settings and show what the kernel guard changed back (no root needed)")
    hard = sub.add_parser("sertlestirme", help="try systemd hardening on a Satsuma service; roll back if it breaks")
    hard.add_argument("islem", choices=("dene", "uygula", "geri-al", "durum"))
    hard.add_argument("hedef", nargs="?", help="a Satsuma service name, or 'hepsi' for all of them")
    aide = sub.add_parser("aide", help="AIDE snapshot: status, check, take, undo a change (the command is the approval)")
    aide.add_argument("islem", choices=("durum", "kontrol", "ornek-al", "geri-al", "hepsini-geri-al"))
    aide.add_argument("hedef", nargs="?", help="path of a listed change for 'geri-al'")
    check = sub.add_parser("tam-kontrol", help="switch every function on, check the whole product and repair what is safe")
    check.add_argument("--yalniz-kontrol", action="store_true", help="report only; do not switch anything on or repair")
    # 2.2.38 (owner, 2026-11-18): maintenance kit, also run by satsuma-maintenance.timer.
    kit = sub.add_parser("bakim", help="maintenance kit: check every Satsuma part and repair what is safe")
    kit.add_argument("--yalniz-kontrol", action="store_true", help="report only; repair nothing")
    kit.add_argument("--json", action="store_true", help="machine-readable report")
    return parser


def _set_password(args) -> int:
    password = getpass.getpass("New admin password: ")
    confirm = getpass.getpass("Confirm admin password: ")
    if not password:
        print("ERROR: empty password is not allowed", file=sys.stderr)
        return 2
    if password != confirm:
        print("ERROR: passwords do not match", file=sys.stderr)
        return 2
    try:
        encoded = hash_password(password)
        write_admin_hash(encoded, args.hash_path)
    except (PermissionError, ValueError, OSError) as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 1
    print("Admin password updated.")
    return 0


def _password_status(args) -> int:
    status = admin_hash_status(args.hash_path)
    print(json.dumps(status, ensure_ascii=False, indent=2))
    return 0 if status.get("configured") else 1


def _reset_password(args) -> int:
    try:
        removed = remove_admin_hash(args.hash_path)
    except (PermissionError, OSError) as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 1
    if removed:
        print("Admin password hash removed. Dashboard login is fail-closed.")
    else:
        print("Admin password hash was not configured.")
    return 0


def _modem(args) -> int:
    from . import modem_identity
    try:
        if args.mac:
            result = modem_identity.approve_manual(args.mac, os.getuid(), True)
            seen = result.get('observed_mac')
            print('Modem kaydedildi: ' + result['modem']['gateway'] + ' · MAC ' + result['modem']['gateway_mac'])
            if seen and not result['matches_observed']:
                print('DİKKAT: ağda şu an bu adresten cevap veren MAC ' + seen + '; yazdığınızla farklı.')
            return 0
        data = modem_identity.inventory()
        result = modem_identity.approve_automatic(data=data)
        if result['status'] == 'AUTOMATICALLY_ENROLLED':
            print('Modem otomatik tanındı ve kaydedildi: ' + result['modem']['gateway'] + ' · '
                  + result['modem']['interface'] + ' · MAC ' + result['modem']['gateway_mac'])
            return 0
        print('\n'.join(result['reasons']))
        print('Elle kaydetmek için: sudo satsuma-admin modem --mac <modem-etiketindeki-MAC>')
        return 1
    except (OSError, ValueError, RuntimeError, PermissionError) as exc:
        print('Modem kaydedilemedi: ' + str(exc), file=sys.stderr)
        return 1


def _quarantine(args) -> int:
    from . import scan_quarantine
    from .binary_audit import quarantine_allowed, rpm_inventory
    from .store import Store
    store = Store()
    audit = lambda record: store.add('quarantine_actions', {**record, 'source': 'satsuma-admin', 'timestamp': time.time()})
    try:
        if args.islem == 'liste':
            rows = scan_quarantine.list_quarantine()
            for row in rows:
                print(row['quarantine_id'] + '  ' + str(row['path'])
                      + ('  (açılış doğrulaması bekleniyor)' if row['boot_verification_pending'] else ''))
            if not rows:
                print('Karantinada dosya yok.')
            return 0
        if not args.hedef:
            print('Hedef gerekli: karantina al <yol> | karantina geri-al <kimlik>', file=sys.stderr)
            return 2
        if args.islem == 'geri-al':
            result = scan_quarantine.restore_target(args.hedef, audit)
            print('Geri konuldu: ' + result['path'])
            return 0
        path = args.hedef
        owner = rpm_inventory(dirs=(os.path.dirname(path) or '/',)).get(os.path.realpath(path))
        if not quarantine_allowed({'path': path, 'package': owner[0] if owner else None}):
            print('Bu program açılış için gerekli; karantinaya alınmaz. Paketini yeniden kurun: sudo dnf reinstall '
                  + (owner[0] if owner else '<paket>'), file=sys.stderr)
            return 1
        result = scan_quarantine.quarantine_target(scan_quarantine.inspect_target(path), audit, system_ok=True)
        print('Karantinaya alındı: ' + result['source'] + ' · kimlik ' + result['quarantine_id'])
        if result.get('boot_verification'):
            print('Yeniden başlatmadan sonra açılış tamamlanmazsa dosya kendiliğinden geri konur.')
        print('Geri almak için: sudo satsuma-admin karantina geri-al ' + result['quarantine_id'])
        return 0
    except (OSError, ValueError, RuntimeError, PermissionError) as exc:
        print('İşlem yapılamadı: ' + str(exc), file=sys.stderr)
        return 1
    finally:
        store.close()


def _ssh(args) -> int:
    from . import scan_quarantine, ssh_keys
    from .host_store import HostStore
    from .store import Store
    host = HostStore()
    core = Store()
    audit = lambda record: core.add('quarantine_actions', {**record, 'source': 'satsuma-admin ssh', 'timestamp': time.time()})
    try:
        if args.islem == 'sunucu-kapat':
            result = ssh_keys.disable_sshd()
            print('SSH sunucusu kapatıldı: ' + ', '.join(f'{u}: {r}' for u, r in result['units'].items()))
            return 0
        if args.islem == 'liste':
            rows = ssh_keys.run(host)['pending']
            for row in rows:
                if row['kind'] == 'authorized':
                    print(f"[yetkili anahtar] {row['file']} {row['type']} {row['fingerprint']} {row['comment']}")
                else:
                    print(f"[özel anahtar] {row['path']}" + (' (parolasız)' if row['encrypted'] is False else ''))
            if not rows:
                print('Onay bekleyen SSH anahtarı yok.')
            else:
                print('Tanıyorsanız: sudo satsuma-admin ssh tanidik <parmak izi | yol>')
                print('Tanımıyorsanız: sudo satsuma-admin ssh karantina <authorized_keys dosyası> <parmak izi>'
                      ' | sudo satsuma-admin ssh karantina <özel anahtar yolu>')
            return 0
        if args.islem == 'tanidik' and len(args.hedef) == 1:
            ssh_keys.mark_known(host, args.hedef[0])
            print('Tanıdık olarak kaydedildi; bir daha sorulmayacak: ' + args.hedef[0])
            return 0
        if args.islem == 'karantina' and len(args.hedef) == 2:
            result = ssh_keys.quarantine_authorized(args.hedef[0], args.hedef[1], audit)
        elif args.islem == 'karantina' and len(args.hedef) == 1:
            result = scan_quarantine.quarantine_target(scan_quarantine.inspect_target(args.hedef[0]), audit)
        else:
            print('Kullanım: ssh liste | ssh tanidik <hedef> | ssh karantina <dosya> <parmak izi> | '
                  'ssh karantina <özel anahtar> | ssh sunucu-kapat', file=sys.stderr)
            return 2
        print('Karantinaya alındı · kimlik ' + result['quarantine_id'])
        print('Geri almak için: sudo satsuma-admin karantina geri-al ' + result['quarantine_id'])
        return 0
    except (OSError, ValueError, RuntimeError, PermissionError) as exc:
        print('İşlem yapılamadı: ' + str(exc), file=sys.stderr)
        return 1
    finally:
        host.close()
        core.close()


def _kernel(args) -> int:
    from . import kernel_guard
    print(kernel_guard.report(kernel_guard.PROC_SYS))
    try:
        state = json.loads((kernel_guard.STATE_DIR / 'state.json').read_text())
    except (OSError, ValueError):
        print('\nBekçi durumu okunamadı: satsuma-kernel-guard çalışmıyor olabilir (systemctl status satsuma-kernel-guard).')
        return 0
    age = max(0, int(time.time() - state.get('updated_at', 0)))
    print(f"\nBekçi: {'geri yazıyor' if state.get('writing_back') else 'YALNIZCA OKUYOR (duraklatıldı ya da root değil)'}; "
          f"son güncelleme {age} sn önce; izlenen ayar {state.get('watched_settings')}, tamam {state.get('settings_ok')}")
    print('Sayaçlar:', json.dumps(state.get('counts', {}), ensure_ascii=False, sort_keys=True))
    for event in state.get('last_events', [])[-10:]:
        print(' ', time.strftime('%H:%M:%S', time.localtime(event.get('time', 0))), event.get('kind'), event.get('key'),
              'geri alındı' if event.get('restored') else 'GERİ ALINAMADI')
    return 0


def _hardening(args) -> int:
    from . import hardening
    if args.islem == 'durum':
        for row in hardening.status():
            print(f"{row['unit']:<30} {','.join(row['dropin']):<10} {row['score'] or '-'}")
        return 0
    if not args.hedef:
        print("Bir servis adı ya da 'hepsi' verin.", file=sys.stderr)
        return 2
    units = hardening.UNITS if args.hedef == 'hepsi' else (args.hedef,)
    action = {'dene': hardening.trial, 'uygula': hardening.persist, 'geri-al': hardening.rollback}[args.islem]
    failed = 0
    for unit in units:
        try:
            result = action(unit)
        except ValueError:
            print(f'Bilinmeyen servis: {unit}', file=sys.stderr)
            return 2
        failed += 0 if result.get('ok') else 1
        print(json.dumps(result, ensure_ascii=False))
    return 1 if failed else 0


def _full_check(args) -> int:
    from .full_check import check, report
    from .store import Store
    store = Store()
    try:
        rows = check(store, fix=not args.yalniz_kontrol)
    finally:
        store.close()
    print(report(rows))
    # 2.2.38: the full check covers the whole product: the maintenance kit runs
    # after the functions are switched on (satsuma.maintenance).
    # Tam kontrol ürünün tamamını kapsar: bakım kiti ardından çalışır.
    from .maintenance import Kit, report as kit_report
    store = Store()
    try:
        summary = Kit(repair=not args.yalniz_kontrol, store=store).check()
    finally:
        store.close()
    print()
    print('== Bakım kiti ==')
    print(kit_report(summary))
    return 0 if all(row['ok'] for row in rows) and summary['ok'] else 1


def _maintenance(args) -> int:
    import json as _json
    from .maintenance import Kit, report as kit_report
    from .store import Store
    store = Store()
    try:
        summary = Kit(repair=not args.yalniz_kontrol, store=store).check()
    finally:
        store.close()
    print(_json.dumps(summary, ensure_ascii=False) if args.json else kit_report(summary))
    return 0 if summary['ok'] else 1


def _aide(args) -> int:
    """AIDE guard from the root terminal; running geri-al is the approval.

    Root terminalinden AIDE bekçisi; geri-al komutunu çalıştırmak onaydır.
    """
    from .aide_guard import Guard, status_text
    from .store import Store
    store = Store()
    try:
        guard = Guard(store)
        if args.islem == 'ornek-al':
            record = guard.snapshot()
            print('AIDE örneği alındı; kopyalanan ayar dosyası: ' + str(record['copied_files']))
            return 0
        if args.islem == 'kontrol':
            row = guard.check()
            print(status_text(row))
            return 0 if row.get('status') == 'CLEAN' else 1
        if args.islem in ('geri-al', 'hepsini-geri-al'):
            if args.islem == 'geri-al' and not args.hedef:
                print('Kullanım: sudo satsuma-admin aide geri-al <yol>', file=sys.stderr)
                return 2
            # Every undo needs the Satsuma admin password (user decision 2026-11-10).
            password = getpass.getpass('Satsuma yönetici parolası: ')
            pending = (store.get('aide_changes', {}) or {}).get('changes', [])
            targets = [args.hedef] if args.islem == 'geri-al' else [c['path'] for c in pending if c['restore'] != 'none']
            failed = 0
            for path in targets:
                try:
                    done = guard.restore(path, password)
                    print('Geri alındı (' + done['how'] + '): ' + path)
                except PermissionError as exc:
                    print(str(exc), file=sys.stderr)
                    return 1
                except (OSError, RuntimeError) as exc:
                    failed += 1
                    print('Geri alınamadı: ' + path + ': ' + str(exc), file=sys.stderr)
            return 1 if failed else 0
        print(status_text(store.get('aide_changes', None)))
        return 0
    except RuntimeError as exc:
        print(str(exc), file=sys.stderr)
        return 1
    finally:
        store.close()


def main(argv=None) -> int:
    args = _parser().parse_args(argv)
    if args.command == 'cekirdek':
        return _kernel(args)
    if args.command in ('modem', 'tam-kontrol', 'karantina', 'ssh', 'sertlestirme', 'aide', 'bakim'):
        if os.geteuid() != 0:
            print('Root yetkisi gerekli: sudo satsuma-admin ' + args.command, file=sys.stderr)
            return 1
        if args.command == 'karantina':
            return _quarantine(args)
        if args.command == 'ssh':
            return _ssh(args)
        if args.command == 'sertlestirme':
            return _hardening(args)
        if args.command == 'aide':
            return _aide(args)
        if args.command == 'bakim':
            return _maintenance(args)
        return _modem(args) if args.command == 'modem' else _full_check(args)
    if args.command == 'set-otx-key':
        if os.geteuid() != 0:
            print('Root privileges required.', file=sys.stderr)
            return 1
        from .otx import configure_key
        try:
            configure_key(getpass.getpass('OTX API key: '))
        except (OSError, ValueError, RuntimeError) as exc:
            print('OTX setup failed: ' + str(exc), file=sys.stderr)
            return 1
        print('OTX anahtarı kaydedildi; sorgulama ve eşik engeli açıldı, servis başlatıldı. API kabulü ilk sorgu sonucuyla doğrulanır.')
        return 0
    if args.command == "set-password":
        return _set_password(args)
    if args.command == "password-status":
        return _password_status(args)
    if args.command == "reset-password":
        return _reset_password(args)
    return 2


if __name__ == "__main__":
    raise SystemExit(main())
