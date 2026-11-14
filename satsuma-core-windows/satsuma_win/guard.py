"""The Windows network guard: closes 853, locks DNS, refuses incoming connections, then applies the fixed rules.

At start: port 853 is closed, the DNS lock is set and incoming connections
are refused (satsuma_win.inbound); every result is recorded, and a failure
is reported, never hidden. The incoming lock is checked every minute and
written back if something reopened it. Then every poll reads the
connection table once and applies the no-PTR rule and the subnet limit; each
decision is blocked with Windows Firewall and recorded, whether or not the
block succeeded. Protected addresses (gateway, DNS servers, remote support)
are never blocked. Every few seconds the memory of every process is read
(satsuma_win.memory) and what the shared memory rules stop is stopped. A
separate thread scans process memory with Satsuma's own ClamAV
(satsuma_win.ramscan, RAM v2) and stops what the shared rules stop there;
its findings are recorded here. Records: %ProgramData%\\Satsuma\\events.jsonl and
state.json. Needs an administrator account.

Windows ağ bekçisi: 853'ü kapatır, DNS'i kilitler, sonra sabit kuralları iki
saniyede bir uygular. Açılışta 853 kapatılır, DNS kilitlenir ve gelen bağlantılar
reddedilir; her sonuç kaydedilir, başarısızlık gizlenmez, bildirilir. Gelen
bağlantı kilidi dakikada bir denetlenir, biri açarsa geri yazılır. Sonra her turda bağlantı
tablosu bir kez okunur, PTR kuralı ve alt ağ sınırı uygulanır; her karar
Windows Güvenlik Duvarı ile engellenir ve engel başarılı olsun olmasın
kaydedilir. Korunan adresler asla engellenmez. Birkaç saniyede
bir her sürecin belleği okunur ve ortak bellek kurallarının durdurduğu
durdurulur. Ayrı bir iş parçacığı süreç belleğini Satsuma'nın kendi ClamAV'ıyla
tarar (satsuma_win.ramscan, RAM v2) ve ortak kuralların durdurduğunu orada
durdurur; bulguları burada kaydedilir. Kayıtlar:
%ProgramData%\\Satsuma\\events.jsonl ve state.json. Yönetici hesabı gerekir.
"""
import json
import os
import sys
import time
from pathlib import Path

from . import connections, dns, firewall, inbound, protect
from .peers import PeerRule
from .subnet import SubnetRule

POLL_SECONDS = 2.0
INFRASTRUCTURE_EVERY = 60.0
INBOUND_EVERY = 60.0
MEMORY_EVERY = 5.0
ACCOUNTS_EVERY = 60.0
SYSMON_RETRY_EVERY = 60.0
SYSMON_INSTALL_EVERY = 600.0


def sysmon_dir():
    return Path(os.environ.get('ProgramFiles', r'C:\Program Files')) / 'Satsuma' / 'Sysmon'


def state_dir():
    return Path(os.environ.get('ProgramData', r'C:\ProgramData')) / 'Satsuma'


class Guard:
    def __init__(self, runner=None, read=connections.read, clock=time.time, directory=None,
                 peer_rule=None, subnet_rule=None, echo=print, memory_factory=None, key_loader=None,
                 sysmon_factory=None, package_manager_running=None, gateway_factory=None,
                 accounts_factory=None, devices_factory=None, sysmon_installer=None, signature_factory=None):
        self.runner = runner or firewall.safe_run
        self.read, self.clock, self.echo = read, clock, echo
        self.directory = Path(directory) if directory else state_dir()
        self.infrastructure, self.infrastructure_at, self.support = set(), None, set()
        self.peers = peer_rule or PeerRule(self.protected, clock=clock)
        self.subnet = subnet_rule or SubnetRule(self.protected, clock=clock)
        self.counts = {'blocked': 0, 'block_failed': 0, 'skipped_protected': 0,
                       'inbound_changed': 0, 'inbound_restored': 0}
        self.inbound_at = None
        self.startup = {}
        self.memory_factory = memory_factory or default_memory_scanner
        self.memory, self.memory_at = None, None
        self.key = None
        if key_loader is None:
            from . import machine_key
            key_loader = machine_key.ensure
        self.key_loader = key_loader
        self.sysmon_factory = sysmon_factory or default_sysmon_reader
        self.pm_running = package_manager_running or windows_package_manager_running
        self.sysmon, self.sysmon_at, self.sysmon_install_at = None, None, None
        self.sysmon_installer = sysmon_installer or default_sysmon_installer
        self.gateway_factory = gateway_factory or default_gateway
        self.gateway, self.key_created = None, False
        self.accounts_factory = accounts_factory or default_accounts
        self.accounts, self.accounts_at = None, None
        self.devices_factory = devices_factory or default_devices
        self.devices, self.devices_at = None, None
        self.counts.update({'sysmon_events': 0, 'build_tool_stopped': 0, 'build_tool_allowed': 0,
                            'build_tool_stop_failed': 0})
        self.signature_factory = signature_factory or default_signature_monitor
        self.signatures = None

    def protected(self, ip):
        return protect.protected_reason(ip, self.infrastructure, self.support)

    def record(self, kind, **fields):
        event = {'time': self.clock(), 'kind': kind, **fields}
        self.echo(json.dumps(event, ensure_ascii=False, sort_keys=True))
        try:
            self.directory.mkdir(parents=True, exist_ok=True)
            with open(self.directory / 'events.jsonl', 'a', encoding='utf-8') as stream:
                stream.write(json.dumps(event, ensure_ascii=False, sort_keys=True) + '\n')
        except OSError:
            pass
        return event

    def start(self):
        """Close 853, lock DNS and refuse incoming connections; every outcome is recorded."""
        for name, step in (('state_dir_lock', self.lock_state_dir),
                           ('machine_key', self.load_machine_key),
                           ('port_853', lambda: firewall.close_port_853(self.runner)),
                           ('dns_lock', lambda: dns.lock(self.runner)),
                           ('inbound_lock', lambda: inbound.lock(self.runner))):
            try:
                result = step()
            except (firewall.FirewallError, ValueError, OSError) as exc:
                result = {'ok': False, 'status': 'ERROR', 'error': str(exc)[:300]}
            ok = result.get('ok', result.get('status') in ('closed', 'LOCKED'))
            self.startup[name] = {**result, 'ok': bool(ok)}
            self.record('startup_' + name, **self.startup[name])
        self.inbound_at = self.clock()
        self.startup['accounts'] = self.check_accounts(force=True) or {'ok': False, 'status': 'NOT_CHECKED'}
        self.startup['gateway'] = self.start_gateway()
        self.record('startup_gateway', **self.startup['gateway'])
        self.startup['memory'] = self.start_memory()
        self.record('startup_memory', **self.startup['memory'])
        self.startup['sysmon'] = self.start_sysmon()
        self.record('startup_sysmon', **self.startup['sysmon'])
        self.startup['ram_signatures'] = self.start_signatures()
        self.record('startup_ram_signatures', **self.startup['ram_signatures'])
        return self.startup

    def start_signatures(self):
        """Start the ClamAV memory scan thread; it installs and updates ClamAV itself and says so.

        ClamAV bellek tarama iş parçacığını başlatır; ClamAV'ı kendisi kurar, günceller ve bildirir.
        """
        try:
            self.signatures = self.signature_factory(self.directory)
            self.signatures.start()
        except Exception as exc:  # reported in startup_ram_signatures; the rest of the guard keeps running
            self.signatures = None
            return {'ok': False, 'status': 'ERROR', 'error': type(exc).__name__ + ': ' + str(exc)[:300]}
        return {'ok': True, 'status': 'STARTED', 'enforce': self.signatures.enforce}

    def check_signatures(self):
        """Record what the ClamAV memory scan thread found and did since the last poll."""
        if self.signatures is None:
            return []
        return [self.record(event.pop('kind'), **event) for event in self.signatures.drain()]

    def stop(self):
        """Stop the scan thread (and its clamd). Tarama iş parçacığını (ve clamd'yi) durdurur."""
        if self.signatures is not None:
            self.signatures.close()

    def start_gateway(self):
        """Load the approved modem; at the first start (installation) approve the one seen now.

        Onaylı modemi yükler; ilk açılışta (kurulum) o an görüleni onaylar.
        """
        if self.key is None:
            return {'ok': False, 'status': 'NO_MACHINE_KEY'}
        try:
            self.gateway = self.gateway_factory(self.directory, self.key, self.runner, self.record, self.clock)
            approved = self.gateway.load()
            status = 'LOADED'
            if approved is None and self.key_created:
                approved, status = self.gateway.approve_now(), 'APPROVED_AT_INSTALL'
        except Exception as exc:  # reported; without an approved modem the MITM guard cannot compare
            return {'ok': False, 'status': 'ERROR', 'error': type(exc).__name__ + ': ' + str(exc)[:300]}
        if approved is None:
            return {'ok': False, 'status': 'NOT_APPROVED'}
        return {'ok': True, 'status': status, **approved}

    def check_accounts(self, force=False):
        """Every minute: only the owner may log on; other accounts are denied by policy (owner's decision).

        Dakikada bir: yalnızca sahip oturum açabilir; diğer hesaplar ilkeyle reddedilir.
        """
        now = self.clock()
        if not force and self.accounts_at is not None and now - self.accounts_at < ACCOUNTS_EVERY:
            return None
        self.accounts_at = now
        try:
            if self.accounts is None:
                self.accounts = self.accounts_factory(self.directory, self.key, self.runner, self.record)
            state = self.accounts.enforce()
        except Exception as exc:  # recorded; checked again next minute
            state = {'ok': False, 'status': 'ERROR', 'error': type(exc).__name__ + ': ' + str(exc)[:300]}
        if force or not state.get('ok') or state.get('status') == 'WRITTEN' or state.get('disabled'):
            self.record('startup_accounts' if force else 'accounts_' + state.get('status', 'ERROR').lower(), **state)
        return state

    def check_devices(self):
        """Every minute: disable the devices the owner does not allow (owner's decision 2026-11-11)."""
        now = self.clock()
        if self.devices_at is not None and now - self.devices_at < ACCOUNTS_EVERY:
            return []
        self.devices_at = now
        try:
            if self.devices is None:
                self.devices = self.devices_factory(self.directory, self.key, self.runner, self.record)
            return self.devices.check()
        except Exception as exc:  # recorded; checked again next minute
            return [self.record('devices_unreadable', error=type(exc).__name__ + ': ' + str(exc)[:300])]

    def check_gateway(self):
        return self.gateway.check() if self.gateway is not None else []

    def start_sysmon(self):
        """Open the Sysmon event channel; without Sysmon the guard keeps running and says so."""
        try:
            self.sysmon = self.sysmon_factory()
            self.sysmon.read()
        except Exception as exc:  # reported in startup_sysmon: process monitoring is off until it is fixed
            self.sysmon = None
            return {'ok': False, 'status': 'UNAVAILABLE', 'error': type(exc).__name__ + ': ' + str(exc)[:300]}
        return {'ok': True, 'status': 'READING'}

    def check_sysmon(self):
        """New Sysmon events: stop build tools, memory scan the processes the events point at."""
        from satsuma import build_tools
        from . import sysmon
        if self.sysmon is None:
            now = self.clock()
            if self.sysmon_at is None or now - self.sysmon_at >= SYSMON_RETRY_EVERY:
                self.sysmon_at = now
                state = self.start_sysmon()
                if state['ok']:
                    self.record('sysmon_available', **state)
                elif self.sysmon_install_at is None or now - self.sysmon_install_at >= SYSMON_INSTALL_EVERY:
                    # Satsuma installs what it needs by itself (owner's rule); the reason is recorded.
                    # Satsuma gerekeni kendisi kurar; neden kaydedilir.
                    self.sysmon_install_at = now
                    try:
                        result = self.sysmon_installer()
                    except Exception as exc:  # recorded; tried again in ten minutes
                        result = {'ok': False, 'status': 'ERROR', 'error': type(exc).__name__ + ': ' + str(exc)[:300]}
                    self.record('sysmon_install', **result)
            return []
        try:
            events = self.sysmon.read()
        except Exception as exc:  # a broken read is recorded; the next poll tries again
            self.record('sysmon_unreadable', error=type(exc).__name__ + ': ' + str(exc)[:300])
            return []
        self.counts['sysmon_events'] += len(events)
        results, scan = [], []
        for event in events:
            if event['id'] == 1 and build_tools.tool_name(event.get('Image'), windows=True):
                results.append(self.stop_build_tool(event, build_tools))
            if event['id'] in sysmon.SCAN_EVENTS:
                scan.extend(sysmon.pids_to_scan(event))
            if event['id'] == 25:
                results.append(self.record('process_tampering', pid=event.get('ProcessId'),
                                           image=event.get('Image'), type=event.get('Type')))
        if scan and self.memory is not None:
            results.extend(self.memory.scan(sorted(set(scan))))
        return results

    def stop_build_tool(self, event, build_tools):
        decision = build_tools.decide(event.get('Image'), self.pm_running(), windows=True)
        fields = {**decision, 'pid': event.get('ProcessId'), 'parent': event.get('ParentImage'),
                  'command': (event.get('CommandLine') or '')[:500]}
        if not decision['stop']:
            self.counts['build_tool_allowed'] += 1
            return self.record('build_tool_allowed', **fields)
        try:
            outcome = self.memory.reader.stop_if_image(int(event['ProcessId']), event['Image'])
        except (AttributeError, KeyError, ValueError, OSError) as exc:
            self.counts['build_tool_stop_failed'] += 1
            return self.record('build_tool_stop_failed', error=str(exc)[:300], **fields)
        if outcome == 'stopped':
            self.counts['build_tool_stopped'] += 1
        return self.record('build_tool_stopped' if outcome == 'stopped' else 'build_tool_' + outcome, **fields)

    def lock_state_dir(self):
        """Only SYSTEM and Administrators may write the records and the setup approvals.

        Kayıtları ve kurulum onaylarını yalnızca SYSTEM ve Yöneticiler yazabilir.
        """
        self.directory.mkdir(parents=True, exist_ok=True)
        result = self.runner(['icacls', str(self.directory), '/inheritance:r', '/grant:r',
                              '*S-1-5-18:(OI)(CI)F', '*S-1-5-32-544:(OI)(CI)F'],
                             capture_output=True, text=True, timeout=60)
        ok = result.returncode == 0
        return {'ok': ok, 'status': 'LOCKED' if ok else 'OPEN',
                **({} if ok else {'error': (result.stderr or result.stdout or '')[:300]})}

    def load_machine_key(self):
        """Create this computer's Satsuma key the first time (during installation), then load it."""
        try:
            self.key, created = self.key_loader(self.directory)
            self.key_created = created
        except Exception as exc:  # reported; without the key no setup approval is accepted
            self.key = None
            return {'ok': False, 'status': 'ERROR', 'error': type(exc).__name__ + ': ' + str(exc)[:300]}
        fingerprint = __import__('hashlib').sha256(self.key.public_bytes).hexdigest()[:16]
        from . import memory
        try:
            approvals = memory.apply_install_approvals(self.directory, self.key, created)
        except (OSError, ValueError) as exc:
            approvals = {'error': str(exc)[:300]}
        result = {'ok': True, 'status': 'CREATED' if created else 'LOADED', 'fingerprint': fingerprint}
        if getattr(self.key, 'replaced', None):
            result['replaced_unreadable_key'] = self.key.replaced
        if approvals is not None:
            result['install_approvals'] = approvals
        return result

    def start_memory(self):
        """Load the shared memory rules and open the reader; a failure is reported, never hidden."""
        try:
            self.memory = self.memory_factory(self.record, self.directory, lambda: self.key)
        except Exception as exc:  # reported in startup_memory; the network guard keeps running
            self.memory = None
            return {'ok': False, 'status': 'ERROR', 'error': type(exc).__name__ + ': ' + str(exc)[:300]}
        return {'ok': True, 'status': 'ACTIVE', 'enforce': self.memory.enforce,
                'debug_privilege': getattr(self.memory.reader, 'debug_privilege', None)}

    def check_memory(self):
        """Every MEMORY_EVERY seconds: read every process and stop what the shared rules stop."""
        now = self.clock()
        if self.memory is None or (self.memory_at is not None and now - self.memory_at < MEMORY_EVERY):
            return []
        self.memory_at = now
        return self.memory.scan()

    def check_inbound(self):
        """Every minute: if something reopened incoming access, write it back and record it.

        Dakikada bir: gelen erişimi yeniden açan bir değişiklik varsa geri yazılır ve kaydedilir.
        """
        now = self.clock()
        if self.inbound_at is not None and now - self.inbound_at < INBOUND_EVERY:
            return None
        self.inbound_at = now
        try:
            state = inbound.check(self.runner)
            if state['ok']:
                return state
            self.counts['inbound_changed'] += 1
            restored = inbound.lock(self.runner)
            if restored['ok']:
                self.counts['inbound_restored'] += 1
            return self.record('inbound_changed', open=state['open'], restored=restored['ok'],
                               still_open=restored['open'])
        except (firewall.FirewallError, ValueError, OSError) as exc:
            return self.record('inbound_unreadable', error=str(exc)[:300])

    def refresh_infrastructure(self):
        now = self.clock()
        if self.infrastructure_at is None or now - self.infrastructure_at >= INFRASTRUCTURE_EVERY:
            try:
                self.infrastructure = protect.infrastructure(self.runner)
                self.infrastructure_at = now
            except (firewall.FirewallError, ValueError, OSError) as exc:
                self.record('infrastructure_unreadable', error=str(exc)[:300])

    def poll(self):
        self.refresh_infrastructure()
        self.check_inbound()
        self.check_gateway()
        self.check_accounts()
        self.check_devices()
        self.check_sysmon()
        self.check_memory()
        self.check_signatures()
        current = self.read()
        self.support = protect.support_peers(current)
        decisions = self.peers.poll(current) + self.subnet.poll(current)
        done = {}
        for decision in decisions:
            ip = decision['ip']
            if ip in done:
                continue
            reason = self.protected(ip)
            if reason:
                self.counts['skipped_protected'] += 1
                done[ip] = self.record('block_skipped', reason=reason, **decision)
                continue
            try:
                result = firewall.block_ip(ip, decision['rule'], self.runner)
                self.counts['blocked'] += 1
                done[ip] = self.record('blocked', **decision, firewall=result)
            except (firewall.FirewallError, ValueError) as exc:
                self.counts['block_failed'] += 1
                done[ip] = self.record('block_failed', error=str(exc)[:300], **decision)
        self.save_state()
        return list(done.values())

    def save_state(self):
        state = {'updated_at': self.clock(), 'startup': self.startup, 'counts': self.counts,
                 'gateway': self.gateway.counts if self.gateway else None,
                 'memory': self.memory.counts if self.memory else None,
                 'ram_signatures': self.signatures.health() if self.signatures else None,
                 'protected_infrastructure': sorted(self.infrastructure)}
        try:
            self.directory.mkdir(parents=True, exist_ok=True)
            temporary = self.directory / 'state.json.tmp'
            temporary.write_text(json.dumps(state, ensure_ascii=False, sort_keys=True), encoding='utf-8')
            os.replace(temporary, self.directory / 'state.json')
        except OSError:
            pass
        return state


def install_approvals(args):
    """--approve-location FOLDER and --approve-file PATH, given by the wizard after the administrator password."""
    locations, files = [], []
    pairs = iter(args)
    for flag in pairs:
        value = next(pairs, None)
        if flag == '--approve-location' and value:
            locations.append(value)
        elif flag == '--approve-file' and value:
            files.append(value)
        else:
            raise ValueError('bilinmeyen kurulum seçeneği: ' + str(flag))
    return {'locations': locations, 'files': files}


def default_devices(directory, key, runner, record):
    from .devices import Devices
    return Devices(directory, key, runner, record)


def default_accounts(directory, key, runner, record):
    from .accounts import Accounts
    return Accounts(directory, key, runner, record)


def default_gateway(directory, key, runner, record, clock):
    from .gateway import Gateway
    return Gateway(directory, key, runner, record, clock)


def default_sysmon_installer():
    from . import sysmon
    return sysmon.install(sysmon_dir())


def default_sysmon_reader():
    from .sysmon import EventReader
    return EventReader()


def windows_package_manager_running():
    """Windows Installer or Windows Update is running (the 'dnf/rpm runs' of Windows)."""
    import psutil
    from .sysmon import PACKAGE_MANAGERS
    for process in psutil.process_iter(['name']):
        if (process.info.get('name') or '').lower() in PACKAGE_MANAGERS:
            return True
    return False


def default_memory_scanner(record, directory=None, key=lambda: None, enforce=True):
    from satsuma import memory_decision
    from .memory import Scanner, Win32Reader, load_approvals, load_locations
    directory = Path(directory) if directory else state_dir()
    return Scanner(memory_decision.load_rules(), Win32Reader(), record,
                   satsuma_exe=sys.executable if getattr(sys, 'frozen', False) else None, enforce=enforce,
                   approvals=lambda: load_approvals(directory, key()),
                   locations=lambda: load_locations(directory, key()))


def default_signature_monitor(directory=None, enforce=True):
    from satsuma import memory_decision
    from . import clamav
    from .ramscan import SignatureMonitor
    directory = Path(directory) if directory else state_dir()
    runtime = clamav.Runtime(clamav.engine_dir(), clamav.data_dir(directory))
    return SignatureMonitor(runtime, memory_decision.load_rules(), enforce=enforce,
                            satsuma_exe=sys.executable if getattr(sys, 'frozen', False) else None)


def memory_report():
    """One scan that stops nothing: what the memory rules would stop on this machine now."""
    found = []
    scanner = default_memory_scanner(lambda kind, **fields: found.append(fields) or fields, enforce=False)
    scanner.scan()
    return {'ok': True, 'counts': scanner.counts, 'debug_privilege': scanner.reader.debug_privilege,
            'findings': found}


def is_admin():
    try:
        import ctypes
        return bool(ctypes.windll.shell32.IsUserAnAdmin())
    except (AttributeError, OSError):
        return False


def main(argv=None):
    args = list(sys.argv[1:] if argv is None else argv)
    # Turkish text must reach any console or pipe; a cp1252 console cannot encode it.
    # Türkçe metin her konsola ve boruya ulaşmalı; cp1252 konsolu onu kodlayamaz.
    for stream in (sys.stdout, sys.stderr):
        try:
            stream.reconfigure(encoding='utf-8', errors='replace')
        except (AttributeError, ValueError):
            pass
    if not is_admin():
        print('Yönetici olarak çalıştırın (Administrator).', file=sys.stderr)
        return 1
    if args[:1] in (['--install'], ['--uninstall'], ['--status']):
        from . import service
        if args[0] == '--install':
            if not getattr(sys, 'frozen', False):
                print('Kurulum derlenmiş satsuma-core-windows.exe ile yapılır.', file=sys.stderr)
                return 2
            try:
                approvals = install_approvals(args[1:])
            except ValueError as exc:
                print(str(exc), file=sys.stderr)
                return 2
            # Sysmon first, so the service reads its events from the first start.
            # Önce Sysmon; hizmet olaylarını ilk açılıştan itibaren okur.
            from . import clamav, sysmon
            monitor = sysmon.install(sysmon_dir())
            # ClamAV before the service too: its memory scan starts with a database (RAM v2).
            # ClamAV da hizmetten önce: bellek taraması veritabanıyla başlar (RAM v2).
            try:
                scanner = clamav.install(clamav.engine_dir(), clamav.data_dir(state_dir()))
            except Exception as exc:  # reported as a failed step, never hidden
                scanner = {'ok': False, 'status': 'ERROR', 'error': type(exc).__name__ + ': ' + str(exc)[:300]}
            result = service.install(sys.executable, **approvals)
            result['sysmon'] = monitor
            result['clamav'] = scanner
            result['ok'] = bool(result.get('ok')) and bool(monitor.get('ok')) and bool(scanner.get('ok'))
        elif args[0] == '--uninstall':
            result = service.uninstall()
            from . import accounts, clamav, devices, gateway, sysmon
            result['sysmon'] = sysmon.uninstall(sysmon_dir())
            result['clamav'] = clamav.uninstall(clamav.engine_dir(), clamav.data_dir(state_dir()))
            try:
                result['devices'] = devices.restore(state_dir())
            except Exception as exc:  # reported; the service is already removed
                result['devices'] = {'ok': False, 'error': str(exc)[:300]}
            try:
                result['accounts'] = accounts.Accounts(state_dir(), None).restore()
            except Exception as exc:  # reported; the service is already removed
                result['accounts'] = {'ok': False, 'error': str(exc)[:300]}
            try:
                result['gateway'] = gateway.unpin(state_dir())
            except Exception as exc:  # reported; the service is already removed
                result['gateway'] = {'ok': False, 'error': str(exc)[:300]}
        else:
            result = service.status()
        print(json.dumps(result, ensure_ascii=False))
        return 0 if result.get('ok') else 1
    if args[:1] == ['--memory-report']:
        print(json.dumps(memory_report(), ensure_ascii=False))
        return 0
    if not args or args[0] not in ('--run', '--once'):
        # Double-clicking the exe must never start the guard unattended outside the service
        # (2026-11-11 on the owner's machine it ran from inside the zip). Çift tıklama bekçiyi başlatmaz.
        print(USAGE)
        if not args and sys.stdin and sys.stdin.isatty():
            try:
                input('Kapatmak için Enter tuşuna basın.')
            except EOFError:
                pass
        return 2
    guard = Guard()
    guard.start()
    if '--once' in args:
        guard.poll()
        guard.stop()
        return 0
    run_loop(guard, lambda seconds: time.sleep(seconds) or False)
    return 0


USAGE = '''Satsuma Core (Windows)

Kurulum (PowerShell yönetici olarak, exe'nin bulunduğu klasörde):
  .\\satsuma-core-windows.exe --install [--approve-location KLASÖR ...]
Durum:     & 'C:\\Program Files\\Satsuma\\satsuma-core-windows.exe' --status
Kaldırma:  & 'C:\\Program Files\\Satsuma\\satsuma-core-windows.exe' --uninstall
Bellek raporu (hiçbir şeyi durdurmaz): --memory-report
'''


def run_loop(guard, wait):
    """Poll until ``wait(seconds)`` returns True (a stop request); a failing poll is recorded, never fatal.

    Window and Windows service run the same loop. Pencere ve Windows hizmeti aynı döngüyü çalıştırır.
    """
    while True:
        started = time.monotonic()
        try:
            guard.poll()
        except Exception as exc:  # the guard keeps running; the failure is recorded
            guard.record('guard_error', error=type(exc).__name__ + ': ' + str(exc)[:300])
        if wait(max(0.0, POLL_SECONDS - (time.monotonic() - started))):
            guard.record('stop_requested')
            guard.stop()
            return


if __name__ == '__main__':
    raise SystemExit(main())
