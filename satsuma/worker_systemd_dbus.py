"""Satsuma Core — systemd + D-Bus worker.

Single task: collect systemd units and D-Bus messages and hand them to the
pipeline; no interpretation. A D-Bus burst never discards the tick: the
messages that fit are processed and the dropped count makes health
DEGRADED.

TEK GÖREV: systemd units ve D-Bus mesajlarını topla, pipeline'a gönder.
ANLAMLANDIRMA YOK. Bir D-Bus patlaması turu atmaz: sığan mesajlar işlenir,
düşürülenlerin sayısı sağlık durumunu DEGRADED yapar.
"""
from .worker_delivery import delivered_tick
import re
import subprocess
import time
import os
import selectors


class WorkerSystemdDbus:
    name = "systemd_dbus"

    DBUS_INTERFACES = [
        'org.freedesktop.systemd1',
        'org.freedesktop.systemd1.Manager',
        'org.freedesktop.systemd1.Unit',
        'org.freedesktop.systemd1.Job',
        'org.freedesktop.systemd1.Service',
        'org.freedesktop.login1',
        'org.freedesktop.login1.Manager',
        'org.freedesktop.PolicyKit1',
        'org.freedesktop.NetworkManager',
        'org.freedesktop.NetworkManager.Device',
        'org.freedesktop.NetworkManager.Connection',
        'org.freedesktop.NetworkManager.Settings',
        'org.freedesktop.UDisks2',
        'org.freedesktop.UDisks2.Manager',
        'org.freedesktop.UDisks2.Filesystem',
        'org.freedesktop.UDisks2.Block',
        'org.freedesktop.UDisks2.Drive',
        'org.bluez',
        'org.bluez.Adapter1',
        'org.bluez.Device1',
        'org.freedesktop.UPower',
        'org.freedesktop.timedate1',
        'org.freedesktop.timesync1',
        'org.freedesktop.hostname1',
        'org.freedesktop.locale1',
        'org.freedesktop.login1.Session',
        'org.freedesktop.systemd1.Manager.StartTransientUnit',
        'org.freedesktop.DBus',
        'org.freedesktop.DBus.Properties',
        'org.freedesktop.DBus.ObjectManager',
        'org.freedesktop.DBus.Monitoring',
    ]

    def __init__(self, store, config=None):
        self.store = store
        self.config = config or {}
        self.monitor = None
        self.raw_key = 'worker.systemd_dbus.raw'
        self.history_key = 'worker.systemd_dbus.history'
        self.health_key = 'worker.systemd_dbus.health'
        self.baseline_key = 'worker.systemd_dbus.baseline'
        saved = self.store.get(self.baseline_key, None)
        if isinstance(saved, dict):
            self._last_units = {str(x): True for x in (saved.get('units') or [])}
            self._last_dbus_services = set(saved.get('dbus_services') or [])
            self._baseline_initialized = True
        else:
            self._last_units = {}
            self._last_dbus_services = set()
            self._baseline_initialized = False

    def _run(self, args, timeout=10):
        try:
            r = subprocess.run(args, capture_output=True, text=True,
                               timeout=timeout, check=False)
            return r.returncode, r.stdout or '', r.stderr or ''
        except Exception as e:
            return -1, '', str(e)

    def _collect_units(self):
        code, out, _ = self._run([
            'systemctl', 'list-units', '--type=service',
            '--no-pager', '--no-legend', '--plain'
        ])
        if code:
            raise RuntimeError('systemctl list-units failed: ' + out[:200])
        units = []
        for line in out.splitlines():
            parts = line.split()
            if parts:
                units.append({
                    'name': parts[0],
                    'load': parts[1] if len(parts) > 1 else '?',
                    'active': parts[2] if len(parts) > 2 else '?',
                })
        return units

    def _collect_timers(self):
        code, out, _ = self._run([
            'systemctl', 'list-timers', '--no-pager', '--no-legend', '--plain'
        ])
        if code:
            raise RuntimeError('systemctl list-timers failed')
        return [line.strip() for line in out.splitlines()]

    def _collect_dbus_services(self):
        code, out, _ = self._run(['busctl', 'list', '--no-pager', '--no-legend'])
        if code:
            raise RuntimeError('busctl list failed')
        services = []
        for line in out.splitlines():
            parts = line.split()
            if parts and not parts[0].startswith(':'):
                services.append(parts[0])
        return sorted(services)

    def _capture_dbus(self, duration=5):
        if self.monitor is None:
            from .dbus_stream import DbusStream
            self.monitor = DbusStream()
        try:
            out = self.monitor.capture(duration)
        except RuntimeError:
            if self.monitor.error or self.monitor.process.poll() is not None:
                self.monitor.close()
                self.monitor = None
            raise

        messages = []
        current = {}
        for line in (out or '').splitlines():
            if 'method call' in line or 'signal' in line:
                if current:
                    messages.append(current)
                current = {'raw': line[:500]}
                m = re.search(r'sender=([^\s]+)', line)
                if m:
                    current['sender'] = m.group(1)
                m = re.search(r'destination=([^\s]+)', line)
                if m:
                    current['destination'] = m.group(1)
                m = re.search(r'interface=([^\s;]+)', line)
                if m:
                    current['interface'] = m.group(1)
                m = re.search(r'member=([^\s;]+)', line)
                if m:
                    current['member'] = m.group(1)
                m = re.search(r'path=([^\s;]+)', line)
                if m:
                    current['path'] = m.group(1)
            elif line.strip().startswith('string') and current:
                current.setdefault('args', []).append(line.strip()[7:].strip('"')[:100])
        if current:
            messages.append(current)

        return messages

    def collect(self, dbus_duration=3):
        return {
            'timestamp': int(time.time()),
            'units': self._collect_units(),
            'timers': self._collect_timers(),
            'dbus_services': self._collect_dbus_services(),
            'dbus_messages': self._capture_dbus(dbus_duration),
            # Headers dropped by a full queue: coverage gap, never hidden.
            'dbus_dropped': self.monitor.take_dropped() if self.monitor is not None else 0,
        }

    def _raw_to_events(self, raw):
        """Ham veriyi host event'lerine çevir (sadece YENİ olanlar)."""
        events = []
        ts = raw.get('timestamp', int(time.time()))

        current_units = {
            f"{u.get('name')}:{u.get('active')}": True
            for u in raw.get('units', []) if u.get('name')
        }
        dbus_services = set(raw.get('dbus_services', []))

        # İlk açılışta mevcut unit/service listesini baseline kabul et. D-Bus mesajları
        # ise bu tick sırasında gerçekten gözlendiği için aşağıda yine işlenir.
        if not self._baseline_initialized:
            self._last_units = current_units
            self._last_dbus_services = dbus_services
            self._baseline_initialized = True

        # 1. Units — sadece YENİ veya değişen
        for unit in raw.get('units', []):
            name = unit.get('name')
            if not name:
                continue
            key = f"{name}:{unit.get('active')}"
            if key in self._last_units:
                continue
            events.append({
                'source': 'systemd_dbus',
                'kind': 'unit',
                'timestamp': ts,
                'action': 'unit_state_change',
                'category': 'host',
                'severity': 'info',
                'metadata': {
                    'extensions': {
                        'host.unit_name': name,
                        'host.unit_load': unit.get('load'),
                        'host.unit_active': unit.get('active'),
                    }
                }
            })
        self._last_units = current_units

        # 2. D-Bus servisleri — sadece YENİ
        for svc in dbus_services - self._last_dbus_services:
            events.append({
                'source': 'systemd_dbus',
                'kind': 'dbus_service',
                'timestamp': ts,
                'action': 'dbus_service_appeared',
                'category': 'host',
                'severity': 'info',
                'metadata': {'extensions': {'host.dbus_service': svc}}
            })
        self._last_dbus_services = dbus_services
        self.store.set(self.baseline_key, {
            'units': sorted(self._last_units),
            'dbus_services': sorted(self._last_dbus_services),
            'updated_at': int(time.time()),
        })

        # 3. D-Bus mesajları — StartTransientUnit vs.
        for msg in raw.get('dbus_messages', []):
            member = msg.get('member', '')
            interface = msg.get('interface', '')

            if 'StartTransientUnit' in member or 'StartTransientUnit' in interface:
                events.append({
                    'source': 'systemd_dbus',
                    'kind': 'dbus',
                    'timestamp': ts,
                    'action': 'StartTransientUnit',
                    'category': 'host',
                    'severity': 'high',
                    'metadata': {
                        'extensions': {
                            'host.dbus_sender': msg.get('sender'),
                            'host.dbus_destination': msg.get('destination'),
                            'host.dbus_member': member,
                            'host.dbus_interface': interface,
                            'host.dbus_path': msg.get('path'),
                        }
                    }
                })
            elif 'Unit' in member and 'New' in member:
                events.append({
                    'source': 'systemd_dbus',
                    'kind': 'dbus',
                    'timestamp': ts,
                    'action': 'new_unit',
                    'category': 'host',
                    'severity': 'medium',
                    'metadata': {
                        'extensions': {
                            'host.dbus_member': member,
                            'host.dbus_interface': interface,
                        }
                    }
                })

        return events

    @delivered_tick('_last_units', '_last_dbus_services', '_baseline_initialized')
    def tick(self, pipeline=None, dbus_duration=3):
        started = time.time()
        raw = self.collect(dbus_duration=dbus_duration)

        self.store.set(self.raw_key, raw)

        history = self.store.get(self.history_key, [])
        history.append({
            'timestamp': raw['timestamp'],
            'unit_count': len(raw['units']),
            'dbus_service_count': len(raw['dbus_services']),
            'dbus_message_count': len(raw['dbus_messages']),
        })
        history = history[-10:]
        self.store.set(self.history_key, history)

        events_count = 0
        if pipeline:
            for ev in self._raw_to_events(raw):
                try:
                    pipeline.ingest_host(ev)
                    events_count += 1
                except Exception as e:
                    self.store.add('errors', {
                        'component': 'worker_systemd_dbus',
                        'error': str(e)[:200],
                        'event_action': ev.get('action'),
                    })

        elapsed = time.time() - started
        self.store.set(self.health_key, {
            'updated_at': int(time.time()),
            'elapsed_ms': int(elapsed * 1000),
            'status': 'DEGRADED' if raw.get('dbus_dropped') else 'RUNNING',
            'degraded_reason': (f"D-Bus burst: {raw['dbus_dropped']} headers dropped; coverage gap"
                                if raw.get('dbus_dropped') else None),
            'dbus_dropped': raw.get('dbus_dropped', 0),
            'unit_count': len(raw['units']),
            'dbus_message_count': len(raw['dbus_messages']),
            'events_count': events_count,
        })

        return {
            'ok': True,
            'unit_count': len(raw['units']),
            'dbus_messages': len(raw['dbus_messages']),
            'events': events_count,
            'elapsed_ms': int(elapsed * 1000),
        }

    def _commit_delivery(self):
        if self.monitor is not None:self.monitor.commit()

    def close(self):
        if self.monitor is not None:self.monitor.close()
