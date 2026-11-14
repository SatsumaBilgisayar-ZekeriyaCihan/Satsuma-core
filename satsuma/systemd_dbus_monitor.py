"""Satsuma Core — systemd ve D-Bus izleme modülü.

Amaç:
- systemd unit'lerini takip et
- D-Bus mesajlarını dinle (kritik arayüzler)
- Anormal çağrıları yakala
- Süreç-bağlantı eşleştirmesi yap
"""
import json
import re
import subprocess
import time
from pathlib import Path
from datetime import datetime


class SystemdDbusMonitor:
    """systemd + D-Bus izleme modülü."""

    # Kritik D-Bus arayüzleri
    CRITICAL_INTERFACES = [
        'org.freedesktop.systemd1.Manager',
        'org.freedesktop.UDisks2.Filesystem',
        'org.freedesktop.UDisks2.Manager',
        'org.bluez',
        'org.freedesktop.login1.Manager',
        'org.freedesktop.NetworkManager',
    ]

    # Şüpheli D-Bus metotları
    SUSPICIOUS_METHODS = [
        'StartTransientUnit',
        'RegisterMachine',
        'Filesystem.Resize',
        'Filesystem.Check',
        'SetUnitProperties',
        'EnableUnitFiles',
        'MaskUnitFiles',
        'AttachProcesses',
        'SetEnvironment',
    ]

    def __init__(self, store, config=None):
        self.store = store
        self.config = config or {}
        self.units_key = 'systemd_dbus.units'
        self.alarm_key = 'systemd_dbus.alarm'
        self.since_timestamp = int(time.time())

    def _run(self, args, timeout=10):
        try:
            r = subprocess.run(args, capture_output=True, text=True,
                               timeout=timeout, check=False)
            return r.returncode, r.stdout or '', r.stderr or ''
        except Exception as e:
            return -1, '', str(e)

    # --- systemd ---

    def _collect_units(self):
        from .worker_systemd_dbus import WorkerSystemdDbus
        return WorkerSystemdDbus(self.store,self.config)._collect_units()

    def _collect_timers(self):
        from .worker_systemd_dbus import WorkerSystemdDbus
        return WorkerSystemdDbus(self.store,self.config)._collect_timers()

    # --- D-Bus ---

    def _collect_dbus_services(self):
        from .worker_systemd_dbus import WorkerSystemdDbus
        return WorkerSystemdDbus(self.store,self.config)._collect_dbus_services()

    def _monitor_dbus(self, duration=10):
        if not hasattr(self,'_compat_worker'):
            from .worker_systemd_dbus import WorkerSystemdDbus
            self._compat_worker=WorkerSystemdDbus(self.store,self.config)
        messages=self._compat_worker._capture_dbus(duration)
        for message in messages:
            member=message.get('member','')
            if member in self.SUSPICIOUS_METHODS:
                message.update(suspicious_method=member,severity='high')
        return messages

    def _resolve_sender(self, sender):
        """D-Bus sender (:1.XXX) → PID ve süreç adı."""
        code, out, _ = self._run(['busctl', 'status', sender, '--no-pager'])
        if code != 0:
            return None
        info = {'sender': sender}
        for line in out.splitlines():
            if 'PID=' in line:
                pid_match = re.search(r'PID=(\d+)', line)
                if pid_match:
                    info['pid'] = int(pid_match.group(1))
            if 'Comm=' in line:
                comm_match = re.search(r'Comm="([^"]+)"', line)
                if comm_match:
                    info['comm'] = comm_match.group(1)
            if 'Command=' in line:
                cmd_match = re.search(r'Command="([^"]+)"', line)
                if cmd_match:
                    info['command'] = cmd_match.group(1)
        return info

    # --- Karşılaştırma ---

    def _diff_units(self, old, new):
        old_names = {u['name'] for u in old}
        new_names = {u['name'] for u in new}
        return {
            'new_units': sorted(new_names - old_names),
            'removed_units': sorted(old_names - new_names),
        }

    # --- Alarm ---

    def _classify_alarm(self, diff, dbus_findings):
        alarms = []

        # Yeni unit
        for unit in diff['new_units']:
            # Şüpheli isim
            if re.search(r'root|hack|backdoor|hidden|malware|trojan|persist', unit, re.I):
                alarms.append({
                    'severity': 'critical',
                    'type': 'suspicious_unit',
                    'detail': f'Şüpheli systemd unit: {unit}',
                })
            else:
                alarms.append({
                    'severity': 'info',
                    'type': 'new_unit',
                    'detail': f'Yeni unit: {unit}',
                })

        # D-Bus şüpheli metot çağrıları
        for finding in dbus_findings:
            if 'suspicious_method' in finding:
                sender_info = self._resolve_sender(finding.get('sender', ''))
                alarms.append({
                    'severity': finding.get('severity', 'high'),
                    'type': 'dbus_suspicious_call',
                    'detail': f"Şüpheli D-Bus çağrısı: {finding['suspicious_method']}",
                    'sender': finding.get('sender'),
                    'sender_info': sender_info,
                    'args': finding.get('args', [])[:5],
                })

        return alarms

    # --- Ana döngü ---

    def tick(self):
        now = int(time.time())

        # systemd units
        new_units = self._collect_units()
        old_units = self.store.get(self.units_key, None)

        diff = {'new_units': [], 'removed_units': []}
        if old_units:
            diff = self._diff_units(old_units, new_units)

        # D-Bus kısa dinleme
        dbus_findings = self._monitor_dbus(duration=5)

        # Alarm sınıflandırma
        alarms = self._classify_alarm(diff, dbus_findings)

        # Audit'e yaz
        event = {
            'event': {
                'timestamp': now,
                'category': 'systemd_dbus_monitor',
                'action': 'tick',
                'outcome': 'alarm' if alarms else 'ok',
                'severity': 'critical' if any(a['severity'] == 'critical' for a in alarms) else (
                    'warn' if alarms else 'info'
                ),
            },
            'source': {
                'type': 'satsuma-core',
                'module': 'systemd_dbus_monitor',
            },
            'metadata': {
                'unit_diff': {
                    'new_units': diff['new_units'][:10],
                    'removed_units': diff['removed_units'][:10],
                },
                'dbus_findings': len(dbus_findings),
                'alarms': alarms,
            },
        }
        self.store.add('events', event)

        if alarms:
            self.store.set(self.alarm_key, {
                'timestamp': now,
                'alarms': alarms,
                'diff': diff,
            })

        self.store.set(self.units_key, new_units)

        if hasattr(self,'_compat_worker'):self._compat_worker._commit_delivery()
        return {'ok': True, 'alarms': len(alarms)}

    def reconcile(self):
        return self.tick()

    def close(self):
        if hasattr(self,'_compat_worker'):self._compat_worker.close()
