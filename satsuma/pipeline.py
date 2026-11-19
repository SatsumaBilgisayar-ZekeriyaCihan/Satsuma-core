"""Collector -> event flow (or persisted event) -> DNS/correlation -> risk -> review -> response.

Since 2.2.32 host and Suricata events stream to the rule engine
(satsuma.flow); raw events are never written to the database. The flow
guard watches the counters for loss.

Toplayıcı → olay akışı (ya da kalıcı olay) → DNS/korelasyon → risk → inceleme →
müdahale. 2.2.32'den beri ana makine ve Suricata olayları kural motoruna
akar (satsuma.flow); ham olay asla veritabanına yazılmaz. Akış bekçisi kayıp
sayaçlarını izler.
"""
import hashlib
import ipaddress
import json
import time
from datetime import datetime, timezone
from uuid import uuid4
from core.events.event import SatsumaEnvelope
from workers.normalizer.suricata.mapper import SuricataMapper
import logging
from collections import OrderedDict, deque
from .dns import DNSMonitorWorker
from .response import ResponseWorker, address
from .response_policy import authorize_destructive, denied_action_record
from .risk_reference import RiskEngine


class Pipeline:
    def __init__(self, store, config, replay=False, runner=None):
        self.store, self.config, self.replay = store, config, replay
        self.dns = DNSMonitorWorker(store, config)
        self.response = ResponseWorker(store, config, replay, **({'runner': runner} if runner else {}))
        self.mapper = SuricataMapper(logging.getLogger("satsuma.normalizer"))
        self.risk = RiskEngine()
        self.counts = OrderedDict()
        self.events = 0
        self.errors = 0
        self.last_event = None

    def ingest(self, raw):
        """Suricata EVE JSON → normalized."""
        if not isinstance(raw, dict):
            raise ValueError('EVE object required')
        if not isinstance(raw.get('event_type'), str):
            raise ValueError('event_type required')

        for key in ('src_ip', 'dest_ip'):
            if key in raw:
                address(raw[key])

        streaming = self._streaming()
        if streaming:
            from .flow import flow_id
            raw_id = flow_id()
        else:
            raw_id = self.store.add('events', raw)
        envelope = SatsumaEnvelope(
            str(raw_id),
            datetime.now(timezone.utc).isoformat(),
            "suricata", "local-sensor", "eve", raw
        )
        normalized = self.mapper.map(envelope)
        if normalized is None:
            raise ValueError('Event normalization failed')
        if streaming:
            self._stream({'raw_id': raw_id, 'event': normalized.model_dump(mode='json'), 'raw': raw})
        else:
            self.store.add('normalized', {
                'raw_id': raw_id,
                'event': normalized.model_dump(mode='json')
            })
        self.events += 1
        self.last_event = time.time()

        if 'dns' in raw and self.config.get('dns_monitor_enabled', True):
            try:
                dns_records = self.dns.process(raw, raw_id)
                for record in dns_records:
                    for rule in self.config.get('dns_actions', []):
                        if record['query'] == rule['domain']:
                            self.store.add('findings', {
                                'kind': 'dns_policy', 'raw_id': raw_id,
                                'domain': record['query'], 'action': rule['action']
                            })
                            if rule['action'] == 'block_ip':
                                policy_finding = {
                                    'classification': 'confirmed',
                                    'policy_allowed': True,
                                    'multi_source_verified': True,
                                    'source': ['dns_policy', 'operator_policy'],
                                    'type': 'dns_policy',
                                    'rule_id': 'dns_policy:' + rule['domain'],
                                }
                                auth = authorize_destructive(
                                    'network_isolate', policy_finding, self.config,
                                    context={'target_ip': rule['target_ip'], 'manual': True},
                                )
                                if auth.allowed:
                                    self.response.block(rule['target_ip'], 'Explicit DNS policy: ' + rule['domain'], raw_id, manual=True)
                                else:
                                    record = denied_action_record(auth, policy_finding)
                                    record['target_ip'] = rule['target_ip']
                                    record['raw_id'] = raw_id
                                    self.store.add('actions', record)
            except (ValueError, KeyError, TypeError) as exc:
                self.store.add('errors', {'component': 'dns', 'raw_id': raw_id, 'error': str(exc)[:200]})
                self.errors += 1

        if raw['event_type'] != 'alert':
            return

        alert = raw.get('alert')
        if not isinstance(alert, dict):
            raise ValueError('alert object required')
        severity = alert.get('severity', 0)
        if type(severity) is not int or severity not in (0, 1, 2, 3):
            raise ValueError('invalid severity')
        signature = alert.get('signature', '')
        if not isinstance(signature, str) or len(signature) > 4096:
            raise ValueError('invalid signature')

        if 'src_ip' not in raw or 'dest_ip' not in raw:
            self.store.add('alerts', {
                'timestamp': raw.get('timestamp'), 'raw_id': raw_id, 'signature': signature,
                'signature_id': alert.get('signature_id'), 'gid': alert.get('gid'), 'rev': alert.get('rev'),
                'severity': severity, 'category': alert.get('category'), 'suricata_action': alert.get('action'),
                'sources': [], 'destinations': [], 'risk_score': 0, 'risk_level': 'UNASSESSED',
                'risk_assessment': 'Ethernet cozumleme uyarisi; IP hedefi degerlendirilemiyor' if alert.get('signature_id') == 2200121 else 'IP hedefleri eksik; risk puani hesaplanmadi',
                'in_iface': raw.get('in_iface'), 'ethernet': raw.get('ethernet'),
                'packet_present': bool(raw.get('packet')), 'packet_info': raw.get('packet_info'),
                'investigation': 'Ham olayda EtherType, MAC ve paket verisini incele; bulunmayan alanlardan protokol veya saldiri sonucu cikarilmaz.',
                'target_review_required': True, 'replay': self.replay
            })
            return

        src = address(raw['src_ip'])
        dst = address(raw['dest_ip'])
        signature_id = alert.get('signature_id')
        key = hashlib.sha256(json.dumps([signature_id, signature, src, dst, raw.get('dest_port'), raw.get('proto')]).encode()).hexdigest()[:24]
        now = time.monotonic()
        queue = self.counts.setdefault(key, deque(maxlen=5002))
        while queue and now - queue[0] > self.config['frequency_window_seconds']:
            queue.popleft()
        queue.append(now)
        self.counts.move_to_end(key)
        while len(self.counts) > 4096:
            self.counts.popitem(last=False)

        incident = {
            'incident_id': key, 'timestamp': raw.get('timestamp'), 'raw_id': raw_id,
            'sources': [src], 'destinations': [dst], 'severity': severity, 'signature': signature,
            'signature_id': signature_id, 'gid': alert.get('gid'), 'rev': alert.get('rev'),
            'suricata_action': alert.get('action'), 'category': alert.get('category'),
            'rule_metadata': alert.get('metadata', {}), 'flow_id': raw.get('flow_id'), 'tx_id': raw.get('tx_id'),
            'src_port': raw.get('src_port'), 'dest_port': raw.get('dest_port'), 'count': len(queue),
            'count_window_seconds': self.config['frequency_window_seconds'], 'replay': self.replay
        }
        result = self.risk.analyze(incident)
        incident['risk_score'] = result['risk_score']
        incident['risk_level'] = result['risk_level']
        incident['classification'] = result.get('classification', 'indicator')
        incident['confidence'] = result.get('confidence', 'low')
        incident['analysis'] = result['analysis']
        if 'dns' in raw:
            incident['dns'] = raw['dns']
        source = ipaddress.ip_address(src)
        destination = ipaddress.ip_address(dst)
        local_source = source.is_private or source.is_loopback or source.is_link_local
        ambiguous = local_source and (destination.is_private or destination.is_loopback or destination.is_link_local)
        incident['target_review_required'] = ambiguous
        self.store.add('alerts', incident)

        # Tek Suricata alarmı otomatik olarak saldırı doğrulaması değildir.
        # Otomatik blok yalnızca yüksek güvenli CRITICAL/likely ve tekrar eden
        # global hedefli sinyalde denenir. Diğer HIGH/CRITICAL olaylar incelemeye gider.
        if incident['risk_level'] in ('HIGH', 'CRITICAL'):
            target = dst if local_source else src
            target_addr = ipaddress.ip_address(target)
            auto_eligible = (
                incident.get('classification') in ('likely', 'confirmed')
                and incident.get('count', 0) >= 2
                and target_addr.is_global
                and not ambiguous
            )
            if auto_eligible:
                from .auto_network import respond
                respond(self.response, incident, target, signature, raw_id)
            else:
                self.store.add('actions', {
                    'timestamp': time.time(), 'status': 'target_review_required', 'raw_id': raw_id,
                    'target': target if target_addr.is_global else None,
                    'reason': 'Suricata signal requires correlation/review before response',
                    'classification': incident.get('classification'),
                    'risk_level': incident.get('risk_level'),
                    'traffic_drop_verified': False,
                })

    def _build_host_normalized(self, raw):
        """Host event -> normalized SatsumaEvent format.

        Eski worker'lar ile yeni kural/Team katmani arasinda tek contract kurar.
        Worker top-level alan kullansa bile kurallar bunlari metadata.extensions
        altinda ``host.*`` olarak gorebilir. Boylece collector'a ozel sema
        farklari kural motoruna sizmaz.
        """
        ts = raw.get('timestamp')
        if isinstance(ts, (int, float)):
            ts = datetime.fromtimestamp(ts, timezone.utc).astimezone().isoformat()
        elif not isinstance(ts, str):
            ts = datetime.now(timezone.utc).astimezone().isoformat()

        raw_meta = raw.get('metadata') if isinstance(raw.get('metadata'), dict) else {}
        extensions = dict(raw_meta.get('extensions') or {})

        # Legacy/top-level worker alanlarini ortak host.* namespace'ine tasi.
        aliases = {
            'kind': 'host.kind',
            'pid': 'host.pid',
            'ppid': 'host.ppid',
            'uid': 'host.uid',
            'gid': 'host.gid',
            'auid': 'host.auid',
            'cmd': 'host.cmd',
            'exe': 'host.exe',
            'starttime': 'host.starttime',
            'start_seconds': 'host.start_seconds',
            'comm': 'host.comm',
            'parent_cmd': 'host.parent_cmd',
            'path': 'host.path',
            'file_path': 'host.file_path',
            'operation': 'host.operation',
            'syscall': 'host.syscall',
            'syscall_name': 'host.syscall_name',
            'subtype': 'host.subtype',
            'result': 'host.result',
            'unit': 'host.unit',
            'identifier': 'host.identifier',
            'message': 'host.message',
            'target': 'host.target',
            'file': 'host.file',
            'virus': 'host.virus',
            'rule': 'host.rule',
            'hash': 'host.hash',
            'namespace': 'host.namespace',
            'query': 'host.query',
            'rrtype': 'host.rrtype',
            'answers': 'host.answers',
            'types': 'host.types',
            'src_ip': 'host.src_ip',
            'dest_ip': 'host.dest_ip',
            'src_port': 'host.src_port',
            'dest_port': 'host.dest_port',
            'proto': 'host.proto',
            'origin': 'host.origin',
        }
        for source_key, ext_key in aliases.items():
            value = raw.get(source_key)
            if value is not None and ext_key not in extensions:
                extensions[ext_key] = value

        network = None
        if raw.get('src_ip') and raw.get('dest_ip'):
            network = {
                'src_ip': raw.get('src_ip'),
                'dst_ip': raw.get('dest_ip'),
                'src_port': raw.get('src_port'),
                'dst_port': raw.get('dest_port'),
                'proto': str(raw.get('proto', '')).lower() or None,
            }

        action = raw.get('action') or raw.get('kind') or 'host_event'
        category = raw.get('category') or ('identity' if raw.get('source') in ('audit', 'journal') else 'host')

        return {
            'event': {
                'id': str(uuid4()),
                'timestamp': ts,
                'ingested_at': datetime.now(timezone.utc).isoformat(),
                'schema_version': '1.0',
                'category': category,
                'action': str(action),
                'severity': raw.get('severity', 'info'),
            },
            'source': {
                'type': raw.get('source', 'host'),
                'collector_id': raw.get('source', 'host'),
                'host': 'local-sensor',
            },
            'raw': {
                'format': 'host_event',
                'data': raw,
            },
            'network': network,
            'payload': None,
            'metadata': {
                'tags': [raw.get('source', 'host')],
                'labels': {},
                'extensions': extensions,
            },
        }

    def ingest_audit(self, raw):
        """Audit event icin acik adaptor; worker ile pipeline contract'ini sabitler."""
        if not isinstance(raw, dict):
            raise ValueError('Audit event object required')
        raw = dict(raw)
        raw.setdefault('action', raw.get('kind', 'audit_event'))
        raw.setdefault('source', 'audit')
        return self.ingest_host(raw)

    def ingest_journal(self, raw):
        """Journal legacy worker adaptor."""
        if not isinstance(raw, dict):
            raise ValueError('Journal event object required')
        raw = dict(raw)
        raw.setdefault('action', raw.get('kind', 'journal_event'))
        raw.setdefault('source', 'journal')
        return self.ingest_host(raw)

    def _streaming(self):
        config = getattr(self, 'config', None)
        if not isinstance(config, dict):
            return False  # a partly built pipeline (tests, tools) keeps the database path
        return bool(config.get('flow_stream_enabled', True)) and not getattr(self, 'replay', False)

    def _stream(self, body):
        sink = getattr(self, 'flow_sink', None)
        if sink is not None:
            sink(body)
            return True
        if getattr(self, '_flow_sender', None) is None:
            from .flow import FlowSender
            self._flow_sender = FlowSender()
        if self._flow_sender.send(body):
            return True
        self.flow_dropped = getattr(self, 'flow_dropped', 0) + 1
        return False

    def flow_health(self):
        sender = getattr(self, '_flow_sender', None)
        if sender is None:
            return {'sent': 0, 'failed': 0, 'dropped': getattr(self, 'flow_dropped', 0), 'retried': 0,
                    'waiting': 0, 'updated_at': time.time()}
        # Called with every health update: events waiting for a busy receiver go out here too.
        sender.flush()
        # 2.2.52: one loss is one count (it was counted as both failed and dropped).
        return {**sender.health(), 'failed': 0, 'dropped': sender.dropped, 'updated_at': time.time()}

    def ingest_host(self, raw):
        """Host olaylari -> normalized. ``action`` yoksa ``kind`` kullanilir."""
        if not isinstance(raw, dict):
            raise ValueError('Host event object required')
        raw = dict(raw)
        action = raw.get('action') or raw.get('kind')
        if not isinstance(action, str) or not action:
            raise ValueError('action/kind required')
        raw['action'] = action

        # Satsuma's own commands are kept apart (user request 2026-11-04):
        # marked, counted separately, never given to the rules.
        # Satsuma'nın kendi komutları ayrı tutulur: işaretlenir, ayrı sayılır,
        # kurallara verilmez.
        if getattr(self, '_self', None) is None:
            from .self_events import SelfClassifier
            self._self = SelfClassifier()
        own = self._self.is_own(raw)
        if own:
            from .self_events import ORIGIN
            raw['origin'] = ORIGIN

        # Event flow (2.2.32, user decision 2026-11-04): host events go to the
        # rule engine, never the database. A sink in the engine's own process takes
        # them directly; other services send a datagram.
        if self._streaming():
            from .flow import flow_id
            event_id = flow_id()
            body = {'raw_id': event_id, 'event': self._build_host_normalized(raw), 'raw': raw}
            if own:
                body['own'] = True
            # No raw event is ever written (user decision 2026-11-04); a lost
            # datagram is counted and the flow guard acts on it.
            if self._stream(body):
                self.events += 1
                self.last_event = time.time()
            return event_id

        raw_id = self.store.add('events', raw)
        normalized = self._build_host_normalized(raw)
        self.store.add('normalized', {
            'raw_id': raw_id,
            'event': normalized
        })
        self.events += 1
        self.last_event = time.time()
        return raw_id

    def health(self):
        return {
            'events': self.events, 'dns_records': self.dns.count,
            'dns_requests': self.dns.requests, 'dns_responses': self.dns.responses,
            'dns_unique_domains': len(self.dns.domains),
            'dns_anomalies': self.dns.anomalies, 'dns_nxdomain': self.dns.nxdomain,
            'dns_query_name_missing': self.dns.query_name_missing,
            'dns_missing_query': self.dns.missing_names,
            'errors': self.errors, 'last_event': self.last_event,
            'response_enabled': self.config['response_enabled'],
            'replay': self.replay, 'process_attribution': 'not_available', 'flow': self.flow_health(),
            'self_events': self._self.health() if getattr(self, '_self', None) else {'own_events': 0, 'other_events': 0},
            'dns_capture_scope': 'Observed EVE only; loopback completeness requires host verification',
            'updated_at': time.time()
        }
