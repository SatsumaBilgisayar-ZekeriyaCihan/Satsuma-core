# -*- coding: utf-8 -*-
"""Read-only systemd service health snapshot for the dashboard.

Bu modül hiçbir servisi başlatmaz/durdurmaz; yalnızca mevcut systemd durumunu
sorgular ve okunabiliyorsa PID/uptime/restart bilgisi döndürür.
"""
from __future__ import annotations

import os
import subprocess
import time
from pathlib import Path

SERVICE_NAMES = ('satsuma-app-control.service', 'satsuma-image.service', 'satsuma-containment.service', 'satsuma-core-audit.service', 'satsuma-core-dns-refresh.service', 'satsuma-core-dns-refresh.timer', 'satsuma-core-dns.service', 'satsuma-core-finding.service', 'satsuma-deep-engine.service', 'satsuma-core-gateway.service', 'satsuma-core-otx.service', 'satsuma-core-security-scan.service', 'satsuma-core-security-scan.timer', 'satsuma-core-sentinel.service', 'satsuma-core-subnet.service', 'satsuma-core.service', 'satsuma-early-guard.service', 'satsuma-guardian.service', 'satsuma-integrity-check.service', 'satsuma-integrity-check.timer', 'satsuma-network-identity.service', 'satsuma-network-modes.service', 'satsuma-network.service', 'satsuma-operator.service', 'satsuma-opnsense-advisory.service', 'satsuma-reader.service', 'satsuma-suricata-ips.service', 'satsuma-suricata-otx-guard.service', 'satsuma-teams.service', 'satsuma-udev.service')


_SHOW_PROPERTIES = (
    'Id', 'ActiveState', 'SubState', 'UnitFileState', 'MainPID',
    'ExecMainStartTimestampMonotonic', 'NRestarts', 'Result',
    'ExecMainExitTimestampMonotonic',
)

_CACHE = {'at': 0.0, 'items': None}
_CACHE_TTL = 5.0


def _parse_properties(output: str) -> dict:
    out = {}
    for line in output.splitlines():
        if '=' not in line:
            continue
        key, value = line.split('=', 1)
        out[key.strip()] = value.strip()
    return out


def _status_from_props(unit: str, props: dict) -> dict:
    active_state = (props.get('ActiveState') or 'unknown').lower()
    unit_file = (props.get('UnitFileState') or '').lower()
    result_value = (props.get('Result') or '').lower()
    if active_state == 'active':
        status = 'ACTIVE'
    elif active_state in ('activating', 'reloading'):
        status = 'STARTING'
    elif active_state == 'failed':
        status = 'FAILED'
    elif active_state == 'inactive':
        status = 'INACTIVE'
    elif unit_file in ('disabled', 'masked') and active_state in ('inactive', 'unknown'):
        status = 'DISABLED'
    else:
        status = 'UNKNOWN'

    try:
        pid = int(props.get('MainPID') or 0) or None
    except ValueError:
        pid = None
    uptime = None
    if pid and active_state == 'active':
        try:
            start_us = int(props.get('ExecMainStartTimestampMonotonic') or 0)
            if start_us:
                # systemd monotonic clock is comparable to CLOCK_MONOTONIC.
                uptime = max(0, int(time.monotonic() - start_us / 1_000_000))
        except (ValueError, TypeError):
            uptime = None
    try:
        restarts = int(props.get('NRestarts') or 0)
    except ValueError:
        restarts = None
    last_failure = None
    if result_value and result_value != 'success':
        try:
            exit_us = int(props.get('ExecMainExitTimestampMonotonic') or 0)
            if exit_us:
                last_failure = max(0, int(time.monotonic() - exit_us / 1_000_000))
        except (ValueError, TypeError):
            last_failure = None
    return {
        'service': unit,
        'name': unit[:-8] if unit.endswith('.service') else unit,
        'status': status,
        'status_tr': {
            'ACTIVE': 'AKTİF',
            'INACTIVE': 'PASİF',
            'FAILED': 'BAŞARISIZ',
            'DISABLED': 'DEVRE DIŞI',
            'UNKNOWN': 'BİLİNMİYOR',
        }.get(status, status),
        'active': active_state == 'active',
        'active_state': active_state,
        'sub_state': props.get('SubState'),
        'unit_file_state': props.get('UnitFileState'),
        'pid': pid,
        'uptime_seconds': uptime,
        'last_failure_seconds_ago': last_failure,
        'result': props.get('Result') or None,
        'restart_count': restarts,
        'lifecycle': 'Zamanlayıcı' if unit.endswith('.timer') else 'İsteğe bağlı' if unit=='satsuma-opnsense-advisory.service' else 'Tamamlanınca kapanan görev' if unit in ('satsuma-core-dns-refresh.service','satsuma-core-security-scan.service','satsuma-integrity-check.service','satsuma-early-guard.service','satsuma-network.service','satsuma-network-modes.service','satsuma-image.service','satsuma-containment.service') else 'Sürekli servis',
        'source': 'systemd',
    }


def _cgroup_fallback(unit: str, now: float) -> dict:
    """Fallback when systemd DBus/systemctl is unavailable.

    Sadece cgroup v2 ve /proc kanıtı varsa ACTIVE/pid/uptime üretir; aksi
    halde UNKNOWN döner. Bu, "servis çalışmıyor" diye yanlış iddia etmez.
    """
    base = Path('/sys/fs/cgroup')
    candidates = [
        base / 'system.slice' / unit,
        base / 'system.slice' / (unit if unit.endswith('.service') else unit + '.service'),
    ]
    for cg in candidates:
        try:
            data = (cg / 'cgroup.procs').read_text().split()
        except OSError:
            continue
        pids = [int(x) for x in data if x.isdigit()]
        if not pids:
            continue
        pid = pids[0]
        uptime = None
        try:
            stat = Path(f'/proc/{pid}/stat').read_text().split()
            start_ticks = int(stat[21])
            hz = os.sysconf(os.sysconf_names['SC_CLK_TCK'])
            uptime = max(0, int(now - start_ticks / hz))
        except (OSError, ValueError, KeyError, IndexError):
            pass
        return {
            'service': unit,
            'name': unit[:-8] if unit.endswith('.service') else unit,
            'status': 'ACTIVE',
            'status_tr': 'AKTİF',
            'active': True,
            'active_state': 'active',
            'sub_state': 'unknown',
            'unit_file_state': 'unknown',
            'pid': pid,
            'uptime_seconds': uptime,
            'last_failure_seconds_ago': None,
            'result': None,
            'restart_count': None,
            'source': 'cgroup',
        }
    return {
        'service': unit,
        'name': unit[:-8] if unit.endswith('.service') else unit,
        'status': 'UNKNOWN',
        'status_tr': 'BİLİNMİYOR',
        'active': None,
        'active_state': 'unknown',
        'sub_state': None,
        'unit_file_state': None,
        'pid': None,
        'uptime_seconds': None,
        'last_failure_seconds_ago': None,
        'result': None,
        'restart_count': None,
        'source': 'systemd_unavailable',
    }


def service_status(names=None, use_cache=True):
    """Return a list of service health dictionaries (read-only)."""
    names = tuple(names or SERVICE_NAMES)
    now = time.monotonic()
    if use_cache and _CACHE['items'] is not None and now - _CACHE['at'] < _CACHE_TTL:
        return list(_CACHE['items'])

    items = []
    for unit in names:
        props = None
        if use_cache and _CACHE.get('props') and unit in _CACHE['props'] and now - _CACHE['at'] < _CACHE_TTL:
            props = _CACHE['props'][unit]
        if props is None:
            try:
                result = subprocess.run(
                    ['systemctl', 'show', '--no-pager', '--property=' + ','.join(_SHOW_PROPERTIES), '--', unit],
                    stdout=subprocess.PIPE,
                    stderr=subprocess.DEVNULL,
                    text=True,
                    timeout=3,
                    check=False,
                )
                if result.returncode == 0 and result.stdout:
                    props = _parse_properties(result.stdout)
            except (OSError, subprocess.SubprocessError):
                props = None
        if props:
            items.append(_status_from_props(unit, props))
        else:
            items.append(_cgroup_fallback(unit, time.time()))
    _CACHE['at'] = now
    _CACHE['items'] = items
    _CACHE['props'] = {}
    return list(items)
