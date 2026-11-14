"""Offline, bounded evidence replay. Deliberately does not import response/app."""
import argparse
import base64
import bisect
import hashlib
import io
import json
import logging
import math
import sqlite3
from datetime import datetime, timezone
from pathlib import Path
from urllib.parse import quote

from core.events.event import SatsumaEnvelope
from core.schema.models import SatsumaEvent
from workers.normalizer.suricata.mapper import SuricataMapper

MAX_LINE = 4 * 1024 * 1024
MAX_EVENTS = 20000
MAX_BYTES = 128 * 1024 * 1024


def encode(obj):
    return json.dumps(obj, sort_keys=True, ensure_ascii=True, allow_nan=False, separators=(',', ':'))


def digest(data):
    return hashlib.sha256(data).hexdigest()


def tail_bytes(path, lines):
    if not 1 <= lines <= MAX_EVENTS:
        raise ValueError('eve_tail_lines must be between 1 and 20000')
    data=b'';newlines=0
    with Path(path).open('rb') as stream:
        stream.seek(0,2);position=stream.tell()
        while position and newlines <= lines:
            size=min(65536,position);position-=size;stream.seek(position)
            chunk=stream.read(size);data=chunk+data;newlines+=chunk.count(b'\n')
            if len(data)>MAX_BYTES+MAX_LINE:
                raise ValueError('Selected EVE tail exceeds replay byte limit')
    return b''.join(data.splitlines(keepends=True)[-lines:])


def event_time(value):
    if isinstance(value, bool):
        raise ValueError('Invalid timestamp')
    if isinstance(value, (int, float)):
        stamp = float(value)
    elif isinstance(value, str):
        dt = datetime.fromisoformat(value.replace('Z', '+00:00'))
        if dt.tzinfo is None:
            raise ValueError('Timestamp must include timezone')
        stamp = dt.timestamp()
    else:
        raise ValueError('Missing timestamp')
    if not math.isfinite(stamp):
        raise ValueError('Non-finite timestamp')
    return datetime.fromtimestamp(stamp, timezone.utc).isoformat(), stamp


def normalize(source, obj, host, ref, received):
    if not isinstance(obj, dict):
        raise ValueError('Record must be a JSON object')
    if source == 'suricata':
        timestamp, _ = event_time(obj.get('timestamp'))
        if not isinstance(obj.get('event_type'), str) or not obj['event_type']:
            raise ValueError('Missing event_type')
        envelope = SatsumaEnvelope(ref, received, source, host, 'eve', obj)
        model = SuricataMapper(logging.getLogger(__name__)).map(envelope)
        if model is None:
            raise ValueError('Existing SuricataMapper rejected event')
        value = model.model_dump(mode='json')
        value['event'].update(id=ref, timestamp=timestamp, ingested_at=received)
    else:
        kind, body = obj.get('kind'), obj.get('body')
        if not isinstance(kind, str) or not kind or not isinstance(body, dict):
            raise ValueError('Host record requires kind and body object')
        timestamp, _ = event_time(body.get('timestamp'))
        value = {'event': {'id': ref, 'timestamp': timestamp, 'ingested_at': received,
                           'schema_version': '1.0', 'category': 'host', 'action': kind},
                 'source': {'type': 'linux', 'host': host, 'collector_id': 'host_store_replay', 'raw_ref': ref},
                 'raw': {'format': 'json', 'data': obj},
                 'metadata': {'tags': ['offline-replay'], 'labels': {},
                              'extensions': {'satsuma.host_record_id': obj.get('id'),
                                             'satsuma.process_attribution': 'not_established'}}}
    return SatsumaEvent.model_validate(value).model_dump(mode='json')


class Ledger:
    def __init__(self, path):
        self.db = sqlite3.connect(path)
        self.db.execute('CREATE TABLE IF NOT EXISTS evidence(seq INTEGER PRIMARY KEY, body TEXT NOT NULL, previous TEXT NOT NULL, sha256 TEXT NOT NULL)')

    def add(self, record):
        self.db.execute('BEGIN IMMEDIATE')
        try:
            last = self.db.execute('SELECT sha256 FROM evidence ORDER BY seq DESC LIMIT 1').fetchone()
            previous = last[0] if last else 'GENESIS'
            body = encode(record)
            value = digest((previous + '\n' + body).encode())
            self.db.execute('INSERT INTO evidence(body,previous,sha256) VALUES(?,?,?)', (body, previous, value))
            self.db.commit()
        except Exception:
            self.db.rollback()
            raise

    def verify(self):
        previous = 'GENESIS'
        for body, prior, value in self.db.execute('SELECT body,previous,sha256 FROM evidence ORDER BY seq'):
            if prior != previous or digest((prior + '\n' + body).encode()) != value:
                return False
            record = json.loads(body)
            if digest(base64.b64decode(record['raw_base64'], validate=True)) != record['raw_sha256']:
                return False
            previous = value
        return True

    def close(self):
        self.db.close()


def correlate(events, window=60, limit=100):
    # Host IDs are explicitly assigned by the operator for these input files.
    by_host = {}
    for e in events:
        if e['source']['collector_id'] == 'host_store_replay':
            by_host.setdefault(e['source']['host'], []).append((event_time(e['event']['timestamp'])[1], e))
    for rows in by_host.values():
        rows.sort(key=lambda x: (x[0], x[1]['event']['id']))
    times = {h: [row[0] for row in rows] for h, rows in by_host.items()}
    for anchor in events:
        if anchor['source']['type'] != 'suricata':
            continue
        at = event_time(anchor['event']['timestamp'])[1]
        host = anchor['source']['host']; rows = by_host.get(host, []); stamps = times.get(host, [])
        start = bisect.bisect_left(stamps, at-window); end = bisect.bisect_right(stamps, at+window)
        selected = rows[start:min(end, start+limit)]
        yield {'incident_id': 'replay-' + anchor['event']['id'], 'status': 'REVIEW',
               'anchor_event_id': anchor['event']['id'], 'window_seconds': window,
               'candidates': [{'event_id': e['event']['id'], 'delta_seconds': t-at,
                               'basis': 'same_declared_host_and_time_only', 'confirmed_link': False}
                              for t, e in selected],
               'candidate_count': end-start, 'candidates_truncated': end-start > limit,
               'malware_confirmed': False, 'actions': [],
               'limitations': ['No process ownership, boot identity or clock skew verification',
                              'Temporal proximity is not causation; missing events do not imply a clean host']}


def replay(inputs, output, host, max_events=MAX_EVENTS, eve_tail_lines=None):
    if not host.strip():
        raise ValueError('Host identity is required')
    if not 1 <= max_events <= MAX_EVENTS:
        raise ValueError('max_events must be between 1 and 20000')
    if eve_tail_lines is not None and not 1 <= eve_tail_lines <= MAX_EVENTS:
        raise ValueError('eve_tail_lines must be between 1 and 20000')
    output = Path(output).resolve()
    for root in (Path('/etc'), Path('/usr'), Path('/opt'), Path('/var'), Path('/proc'), Path('/sys'), Path('/dev')):
        if output == root or root in output.parents:
            raise ValueError('Replay output must not be a system directory')
    # Fail rather than overwrite an existing evidence destination.
    output.mkdir(mode=0o700, parents=True, exist_ok=False)
    ledger = Ledger(output/'evidence.sqlite')
    events=[]; errors=[]; total=0; count=0; received=datetime.now(timezone.utc).isoformat()
    manifest=[]

    def consume(source, path, line_no, raw):
        nonlocal total, count
        total += len(raw); count += 1
        if len(raw) > MAX_LINE or total > MAX_BYTES or count > max_events:
            raise ValueError('Replay input limit exceeded; output is incomplete')
        raw_hash=digest(raw)
        ref=digest(encode([source,host,str(path),line_no,raw_hash]).encode())
        record={'source':source,'input_path':str(path),'line':line_no,
                'raw_sha256':raw_hash,'raw_base64':base64.b64encode(raw).decode(),
                'event_id':ref,'received_at':received}
        try:
            obj=json.loads(raw, parse_constant=lambda x: (_ for _ in ()).throw(ValueError('Non-finite JSON')))
            normalized=normalize('host' if source == 'host-db' else source,obj,host,ref,received)
            record['normalized']=normalized; events.append(normalized)
        except (ValueError,TypeError,OverflowError,RecursionError) as exc:
            record['error']=type(exc).__name__+': '+str(exc)[:500]
            errors.append({'event_id':ref,'line':line_no,'input_path':str(path),'error':record['error']})
        ledger.add(record)

    try:
        for source, name in inputs:
            if source not in ('suricata', 'host', 'host-db'):
                raise ValueError('Unknown input adapter')
            path=Path(name).resolve(); file_hash=hashlib.sha256(); line_no=0
            if source == 'host-db':
                snapshot=output/'host-snapshot.sqlite'
                uri='file:'+quote(str(path),safe='/')+'?mode=ro'
                live=sqlite3.connect(uri,uri=True,timeout=5)
                snap=sqlite3.connect(snapshot)
                try:
                    live.backup(snap);snap.commit()
                finally:
                    snap.close();live.close()
                with snapshot.open('rb') as stream:
                    for chunk in iter(lambda:stream.read(1024*1024),b''):file_hash.update(chunk)
                db=sqlite3.connect('file:'+quote(str(snapshot),safe='/')+'?mode=ro',uri=True)
                try:
                    for ident,kind,body in db.execute('SELECT id,kind,body FROM records ORDER BY id'):
                        line_no+=1
                        try:decoded=json.loads(body)
                        except (ValueError,TypeError):decoded=body
                        raw=(encode({'id':ident,'kind':kind,'body':decoded})+'\n').encode()
                        consume(source,path,line_no,raw)
                except sqlite3.Error as exc:
                    raise ValueError('Host database does not contain a readable records table') from exc
                finally:db.close()
                manifest.append({'path':str(path),'adapter':source,'snapshot':str(snapshot),
                                 'snapshot_sha256':file_hash.hexdigest(),'records':line_no})
                continue
            selected=tail_bytes(path,eve_tail_lines) if source == 'suricata' and eve_tail_lines is not None else None
            stream=io.BytesIO(selected) if selected is not None else path.open('rb')
            with stream:
                while True:
                    raw=stream.readline(MAX_LINE+1)
                    if not raw: break
                    line_no+=1;file_hash.update(raw);consume(source,path,line_no,raw)
            item={'path':str(path),'adapter':source,'sha256':file_hash.hexdigest(),'lines':line_no}
            if selected is not None:item['selection']={'tail_lines_requested':eve_tail_lines,'bytes':len(selected)}
            manifest.append(item)
        with (output/'incidents.jsonl').open('w') as f:
            for incident in correlate(events): f.write(encode(incident)+'\n')
        report={'status':'complete_with_errors' if errors else 'complete','input_lines':count,
                'normalized_events':len(events),'errors':errors,'inputs':manifest,
                'evidence_chain_valid':ledger.verify(),'actions_executed':0,
                'scope':'offline replay; not a malware verdict',
                'chain_limit':'No external trust anchor; suffix deletion/full recomputation not detected'}
        (output/'report.json').write_text(json.dumps(report,ensure_ascii=False,indent=2)+'\n')
        return report
    except Exception as exc:
        (output/'INCOMPLETE.json').write_text(json.dumps({'status':'incomplete','error':str(exc),'input_lines':count})+'\n')
        raise
    finally:
        ledger.close()


def main():
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument('--eve',required=True)
    hosts=p.add_mutually_exclusive_group();hosts.add_argument('--host-records');hosts.add_argument('--host-db')
    p.add_argument('--host-id',required=True);p.add_argument('--output',required=True)
    p.add_argument('--eve-tail-lines',type=int,help='Read only the last N complete EVE records')
    args=p.parse_args(); inputs=[('suricata',args.eve)]
    if args.host_records: inputs.append(('host',args.host_records))
    if args.host_db: inputs.append(('host-db',args.host_db))
    print(json.dumps(replay(inputs,args.output,args.host_id,eve_tail_lines=args.eve_tail_lines),ensure_ascii=False,indent=2))


if __name__=='__main__': main()
