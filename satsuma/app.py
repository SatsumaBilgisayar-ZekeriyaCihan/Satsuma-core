import argparse
import fcntl
import json
import os
import signal
import sqlite3
import sys
import time
from pathlib import Path
from .config import load, load_with_policy, validate, DEFAULT
from .dns import domain
from .pipeline import Pipeline
from .reader import Reader
from .store import Store
from .response import address
from .nft_policy import NftPolicyManager
from .response_policy import authorize_destructive, denied_action_record


def legacy_running():
    from .legacy_process import legacy_running as scan
    return scan()


def network_health():
    from .ips import read_ready
    status = read_ready()
    return {'nfqueue_100_listener': status['ready'], 'ips': status, 'traffic_drop_verified': False}


def commands(store,pipeline):
    for ident,kind,body in store.db.execute("SELECT id,kind,body FROM commands WHERE status='pending' ORDER BY id LIMIT 10").fetchall():
        # Mark execution start durably; an interrupted command is never silently repeated.
        store.db.execute("UPDATE commands SET status='running' WHERE id=?",(ident,));store.db.commit()
        try:
            obj=json.loads(body)
            status='done'
            if kind=='watch':
                name=domain(obj['domain']);watch=pipeline.config['watch_domains']
                if name not in watch:
                    if len(watch)>=4096:raise ValueError('watch capacity reached')
                    watch.append(name)
                store.set('watch_domains',watch)
                store.add('actions',{'timestamp':time.time(),'status':'watch_added','domain':name})
            elif kind=='block':
                target = address(obj['ip'])
                operator_finding = {
                    'classification': 'confirmed',
                    'policy_allowed': True,
                    'multi_source_verified': True,
                    'source': ['operator_command', 'dashboard_policy'],
                    'type': 'operator_command',
                    'rule_id': 'operator-block',
                }
                auth = authorize_destructive(
                    'network_isolate', operator_finding, pipeline.config,
                    context={'target_ip': target, 'manual': True},
                )
                if auth.allowed:
                    result=pipeline.response.block(target,'Operator confirmed dashboard action',manual=True)
                    status='done' if result['status'] in ('already_in_set','set_membership_confirmed','blocked') else 'failed'
                else:
                    store.add('actions', denied_action_record(auth, operator_finding))
                    status='failed'
            else:raise ValueError('unknown command')
        except Exception as exc:
            store.add('errors',{'component':'command','error':str(exc)[:300],'command_id':ident});status='failed'
        store.db.execute('UPDATE commands SET status=? WHERE id=?',(status,ident));store.db.commit()


def runtime_health(store, config, network):
    reasons=[]
    for name, age in (('sys_proc',10),('memory',40)):
        health=store.get('worker.'+name+'.health',{}) or {}
        if health.get('status')!='RUNNING' or not 0<=time.time()-health.get('updated_at',0)<=age:
            reasons.append(name+': missing, degraded or stale')
    if config.get('suricata_collector_enabled',True) and (store.get('eve_source',{}) or {}).get('status')!='RUNNING':
        reasons.append('Suricata EVE collection unavailable')
    if not network.get('nfqueue_100_listener'):
        reasons.append('Verified IPS listener unavailable')
    if (store.get('nft_policy',{}) or {}).get('status')!='ok':
        reasons.append('Firewall reconciliation unavailable or degraded')
    if (store.get('integrity_runtime',{}) or {}).get('status')!='HEALTHY':
        reasons.append('Application integrity warning; monitoring continues')
    return {**network,'status':'degraded' if reasons else 'running','degraded_reasons':reasons}


def run():
    from .memory_access import protect_self
    protect_self()
    from satsuma.runtime_user import require_service_user; require_service_user()
    old=legacy_running()
    if old:raise RuntimeError('Old home-based Core is running (PID '+','.join(old)+'). Stop that Core before starting this version.')
    config,policy_meta,policy=load_with_policy();store=Store()
    from .integrity_monitor import assess_runtime
    store.set('integrity_runtime', assess_runtime())
    config['early_guard_required'] = True
    lock_fd=os.open('/var/lib/satsuma-core/runtime.lock',os.O_WRONLY|os.O_CREAT|os.O_NOFOLLOW,0o600)
    fcntl.flock(lock_fd,fcntl.LOCK_EX|fcntl.LOCK_NB)
    config['watch_domains']=list(dict.fromkeys(config['watch_domains']+store.get('watch_domains',[])))[:4096]
    store.set('policy_saved',policy_meta)
    store.set('policy_effective',policy)
    nft_policy=NftPolicyManager(store,config).reconcile()
    pipeline=Pipeline(store,config);reader=None;running=True

    # ANINDA /proc okuma icin sys_proc worker
    from .worker_sys_proc import WorkerSysProc
    sys_proc_worker = WorkerSysProc(store, config)
    from .worker_memory import WorkerMemory
    memory_worker = WorkerMemory(store, config)
    applied={**policy_meta,'status':'applied','applied_at':time.time(),
             'workers':{
                 'suricata_collector':'enabled' if config.get('suricata_collector_enabled',True) else 'disabled',
                 'dns_monitor':'enabled' if config.get('dns_monitor_enabled',True) else 'disabled',
                 'response':'enabled' if config['response_enabled'] else 'disabled',
                 'audit':'enabled' if config['audit_enabled'] else 'disabled',
                 'finding':'enabled' if config['finding_enabled'] else 'disabled',
                 'evidence':'enabled' if config['evidence_enabled'] else 'disabled',
                 'gateway':'separate_service_not_asserted_running'},'nft_policy':nft_policy}
    store.set('policy_applied',applied)
    def stop(*_):
        nonlocal running
        running=False
    signal.signal(signal.SIGTERM,stop);signal.signal(signal.SIGINT,stop)
    try:
        last=0
        next_reader_attempt=0
        while running:
            if config.get('suricata_collector_enabled',True) and time.monotonic() >= next_reader_attempt:
                try:
                    if reader is None:
                        from .source_guard import resolve_writer_uid
                        writer_uid=resolve_writer_uid(config['eve_writer_uid'])
                        reader=Reader(config['eve_path'],store,pipeline,writer_uid)
                    reader.poll()
                    store.set('eve_source', {'status':'RUNNING', 'path':config['eve_path'], 'writer_uid':writer_uid,
                                            'updated_at':time.time(), 'identity_source':'verified_suricata_process'})
                except Exception as exc:
                    store.set('eve_source', {'status':'DEGRADED', 'error':str(exc)[:500], 'updated_at':time.time()})
                    store.add('errors', {'component':'eve_reader', 'error':str(exc)[:500], 'timestamp':time.time()})
                    if reader:
                        reader.close()
                    reader=None
                    next_reader_attempt=time.monotonic()+5
            commands(store,pipeline)

            # ANINDA /proc OKU (her 150ms)
            try:
                sys_proc_worker.tick(pipeline=pipeline)
            except Exception as e:
                store.add('errors', {'component': 'sys_proc_worker', 'error': str(e)[:200]})
            try:
                memory_worker.tick(pipeline=pipeline)
            except Exception as e:
                store.add('errors', {'component': 'memory_worker', 'error': str(e)[:200]})

            if time.monotonic()-last>1:
                gateway_health=store.get('gateway_health',{'status':'starting'})
                readiness = runtime_health(store, config, network_health())
                store.set('health',{**pipeline.health(),**readiness,'updated_at':time.time(),
                          'eve_path':config['eve_path'],'reader':reader.health() if reader else {},'version':__import__('satsuma').__version__,'policy':applied})
                store.set('health',{**store.get('health',{}),'gateway':gateway_health})
                last=time.monotonic()
            time.sleep(.15)
    except Exception as exc:
        store.set('health',{**pipeline.health(),'status':'degraded','error':str(exc)[:500]})
        raise
    finally:
        if reader:reader.close()
        store.close();os.close(lock_fd)


def init_policy():
    from .policy import POLICY_PATH,from_legacy,load as load_policy,write_atomic
    if POLICY_PATH.exists() or POLICY_PATH.is_symlink():
        policy,_,meta=load_policy(POLICY_PATH);print(json.dumps(meta,indent=2));return
    config=load()
    policy=write_atomic(from_legacy(config),POLICY_PATH)
    print(json.dumps({'status':'created','path':str(POLICY_PATH),'revision':policy['revision']},indent=2))


def check_policy():
    from .policy import POLICY_PATH,load as load_policy
    policy,effective,meta=load_policy(POLICY_PATH)
    print(json.dumps({'policy':policy,'effective_config':effective,'validation':meta},indent=2))


def main():
    parser=argparse.ArgumentParser(description='Satsuma Core 2.0.0-candidate.3 — Suricata / DNS security console')
    from . import __version__
    parser.add_argument('--version', action='version', version=f'Satsuma Core {__version__}')
    group=parser.add_mutually_exclusive_group(required=True)
    group.add_argument('--run',action='store_true')
    group.add_argument('--otx-worker',action='store_true')
    group.add_argument('--subnet-worker',action='store_true')
    group.add_argument('--audit-worker',action='store_true')
    group.add_argument('--audit-rules',action='store_true')
    group.add_argument('--boot-inventory',action='store_true')
    group.add_argument('--usbguard-setup',action='store_true')
    group.add_argument('--usbguard-restore',action='store_true')
    group.add_argument('--signed-verify',action='store_true')
    group.add_argument('--hash-blacklist',action='store_true')
    group.add_argument('--finding-worker',action='store_true')
    group.add_argument('--dashboard',action='store_true')
    group.add_argument('--replay',metavar='JSONL')
    group.add_argument('--check-config',action='store_true')
    group.add_argument('--check-policy',action='store_true')
    group.add_argument('--init-policy',action='store_true')
    parser.add_argument('--output',help='Replay only: isolated test output directory')
    group.add_argument('--gateway-worker',action='store_true')
    group.add_argument('--sentinel-worker',action='store_true')
    group.add_argument('--security-scan',action='store_true')
    group.add_argument('--temporary-scan',action='store_true')
    args=parser.parse_args()
    if args.otx_worker:
        from .otx import run as run_otx
        run_otx()
    elif args.subnet_worker:
        from .subnet_protection import run as run_subnet
        run_subnet()
    elif args.sentinel_worker:
        from .sentinel import run as run_sentinel
        run_sentinel()
    elif args.security_scan:
        from .security_scan import run as run_security_scan
        run_security_scan()
    elif args.temporary_scan:
        from .temporary_scan import main as temporary_scan
        temporary_scan()
    elif args.gateway_worker:
        from .gateway_worker import run as run_gateway
        run_gateway()
    elif args.hash_blacklist:
        from .hash_blacklist import main as hash_blacklist
        raise SystemExit(hash_blacklist())
    elif args.signed_verify:
        from .signed_verify import main as signed_verify
        raise SystemExit(signed_verify())
    elif args.usbguard_restore:
        from .usb_guard import restore_main as usbguard_restore
        raise SystemExit(usbguard_restore())
    elif args.usbguard_setup:
        from .usb_guard import main as usbguard_setup
        raise SystemExit(usbguard_setup())
    elif args.boot_inventory:
        from .boot_inventory import main as boot_inventory
        raise SystemExit(boot_inventory())
    elif args.audit_rules:
        from .audit_rules import main as load_audit_rules
        raise SystemExit(load_audit_rules())
    elif args.audit_worker:
        from workers.audit.worker import run as run_audit
        run_audit()
    elif args.finding_worker:
        from workers.finding.worker import run as run_finding
        run_finding()
    elif args.run:run()
    elif args.dashboard:
        # Tek kanonik dashboard: reader socket uzerinden okuyan PyQt arayuzu.
        # Eski curses dashboard (satsuma.dashboard) uyumluluk modulu olarak
        # kalir; production entrypoint degildir.
        from .dashboard_qt.app import run as run_qt_dashboard
        run_qt_dashboard()
    elif args.check_config:
        print(json.dumps(load(),indent=2))
    elif args.check_policy:check_policy()
    elif args.init_policy:init_policy()
    else:
        if not args.output:parser.error('--replay requires --output')
        target=Path(args.output).resolve()
        if target==Path('/var/lib/satsuma-core') or Path('/var/lib/satsuma-core') in target.parents:
            parser.error('Replay must not use production storage')
        if target.exists() and any(target.iterdir()):parser.error('Replay output must be empty')
        store=Store(target,test=True);pipeline=Pipeline(store,validate({}),replay=True)
        try:
            with open(args.replay,'rb') as stream:
                for line in stream:
                    if len(line)>4*1024*1024:raise ValueError('Oversized replay record')
                    try:pipeline.ingest(json.loads(line))
                    except (ValueError,TypeError,KeyError) as exc:
                        pipeline.errors+=1;store.add('errors',{'component':'replay','error':str(exc)[:200]})
            report=pipeline.health();report['status']='replay_complete';store.set('health',report)
            print(json.dumps(report,indent=2))
        finally:store.close()
