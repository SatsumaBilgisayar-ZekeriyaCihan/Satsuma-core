"""Bounded, passive local network inventory. Observations do not grant trust."""
import ipaddress
import hashlib
import json
import time

from .network_identity import command


def discover(reader=command):
    sections = {}
    errors = {}
    queries = {'interfaces': ['address', 'show'],
               'routes_v4': ['-4', 'route', 'show', 'table', 'all'],
               'routes_v6': ['-6', 'route', 'show', 'table', 'all'],
               'neighbors': ['neigh', 'show']}
    for name, args in queries.items():
        try:
            rows = json.loads(reader(['/usr/sbin/ip', '-j', *args]))
            if not isinstance(rows, list) or len(rows) > 4096:
                raise ValueError('Inventory must be a bounded list')
            if any(not isinstance(row, dict) for row in rows):
                raise ValueError('Invalid inventory row')
            sections[name] = rows
        except Exception as exc:
            sections[name] = []
            errors[name] = str(exc)[:250]
    interfaces = []
    for row in sections['interfaces']:
        addresses = []
        for addr in row.get('addr_info', []):
            try:
                addresses.append(str(ipaddress.ip_interface(f"{addr['local']}/{addr['prefixlen']}")))
            except (KeyError, ValueError, TypeError):
                continue
        interfaces.append({'interface': row.get('ifname'), 'state': row.get('operstate'),
                           'mac': row.get('address'), 'addresses': addresses})
    neighbors = []
    for row in sections['neighbors']:
        try:
            address = str(ipaddress.ip_address(row['dst']))
        except (KeyError, ValueError, TypeError):
            continue
        neighbors.append({'ip': address, 'interface': row.get('dev'), 'mac': row.get('lladdr'),
                          'state': row.get('state'), 'trusted': False})
    routes = sections['routes_v4'] + sections['routes_v6']
    return {'status': 'DEGRADED' if errors else 'RUNNING', 'updated_at': time.time(),
            'interfaces': interfaces, 'routes': routes, 'neighbors': neighbors,
            'gateways': [row for row in routes if row.get('gateway')], 'errors': errors,
            'mode': 'passive', 'scope': 'Yerel arayüz, rota ve ARP/NDP önbelleği; tüm cihazlar keşfedilmiş sayılmaz'}


class WorkerNetworkDiscovery:
    name = 'network_discovery'

    def __init__(self, store, config=None):
        self.store = store
        self.config = config or {}

    def tick(self, pipeline=None):
        if self.config.get('network_discovery_enabled') is False:
            self.store.set('network_discovery', {'status':'DISABLED','updated_at':time.time()})
            return {'ok':True,'status':'DISABLED'}
        old = self.store.get('network_discovery', {}) or {}
        if 0 <= time.time() - old.get('updated_at', 0) < 30:
            return {'ok': old.get('status') == 'RUNNING', 'cached': True}
        result = discover()
        devices = self.store.get('network_devices', {}) or {}
        for neighbor in result['neighbors']:
            if not neighbor.get('mac'):
                continue  # An unresolved ARP entry is not an identified device.
            identity = '|'.join(str(neighbor.get(k, '')) for k in ('interface', 'ip', 'mac'))
            ident = hashlib.sha256(identity.encode()).hexdigest()[:32]
            if ident not in devices:
                # Local scanner executables cannot inspect a remote filesystem.
                # Enrollment is an explicit prerequisite, never a synthetic pass.
                devices[ident] = {**neighbor, 'device_id': ident, 'first_seen': result['updated_at'],
                    'scan_status': 'AGENT_REQUIRED', 'decision': 'pending',
                    'scanners': {name: 'REMOTE_AGENT_REQUIRED' for name in ('clamav', 'rkhunter', 'chkrootkit')},
                    'rule_matches': [], 'rule_evaluation': 'AWAITING_SCAN_EVIDENCE',
                    'message': 'Yeni cihaz gözlemlendi; uzak dosya/sistem taraması için yetkili ajan gerekli'}
                self.store.add('network_device_alerts', {**devices[ident], 'timestamp': result['updated_at'],
                    'severity': 'info', 'classification': 'indicator', 'action': 'device_discovered'})
            devices[ident]['last_seen'] = result['updated_at']
        self.store.set('network_devices', devices)
        self.store.set('network_discovery', result)
        self.store.set('worker.network_discovery.health', result)
        return {'ok': result['status'] == 'RUNNING', 'status': result['status'], 'errors': result['errors']}
