"""Satsuma Core — safe Response Worker.

The response layer is the last line of defence. Even if a caller errs:
response_enabled is enforced; loopback, multicast and unspecified targets
are never blocked automatically, nor are private or link-local ones;
process trees are killed by PID relation only, never pkill -f; critical
system paths are never quarantined automatically; and no archive is ever
unpacked over the root filesystem (audit G6); and /etc/hosts is never
written. Before each signal the identity, and for a memory-based stop the
debugger state and the code difference, are checked again.

Satsuma Core — güvenli Response Worker.

Response katmanı son savunma hattıdır. Çağıran modül hata yapsa bile burada:
- response_enabled zorunlu uygulanır,
- loopback/multicast/unspecified hedefler asla otomatik bloklanmaz,
- private/link-local hedefler otomatik bloklanmaz,
- süreç ağacı yalnızca PID ilişkisi ile öldürülür; pkill -f kullanılmaz,
- kritik sistem yolları otomatik karantinaya taşınmaz,
- hiçbir arşiv sistemin köküne açılmaz (denetim G6),
- /etc/hosts dosyasına hiçbir zaman yazılmaz,
- her sinyalden önce kimlik, bellek kaynaklı durdurmada ayrıca debugger
  durumu ve kod farkı yeniden denetlenir.
"""
from __future__ import annotations

import ipaddress
import os
import shutil
import signal
import select
import subprocess
import sqlite3
import time
from datetime import datetime
from pathlib import Path

from .process_identity import (
    canonical_exe_path,
    capture_process_identity,
    revalidate_captured_identity,
    verify_process_identity,
)

QUARANTINE_DIR = Path('/var/lib/satsuma-core/quarantine')
PROTECTED_QUARANTINE_ROOTS = tuple(Path(p) for p in (
    '/bin', '/sbin', '/usr/bin', '/usr/sbin', '/lib', '/lib64', '/usr/lib', '/etc', '/boot'
))


def _ensure_quarantine():
    try:
        QUARANTINE_DIR.mkdir(parents=True, exist_ok=True)
        os.chmod(QUARANTINE_DIR, 0o700)
    except (PermissionError, OSError):
        pass


def address(ip):
    return str(ipaddress.ip_address(ip))


class ResponseWorker:
    def __init__(self, store, config, replay=False, runner=None):
        self.store = store
        self.config = config
        self.replay = replay
        self.runner = runner
        self.nft_family = config.get('nft_family', 'inet')
        self.nft_table = config.get('nft_table', 'satsuma_core')
        self.nft_set = config.get('nft_set', 'blocked_ips')
        self.nft_set_v6 = config.get('nft_set_v6', 'blocked_ips_v6')
        self.blocked = set()
        self.killed = set()
        self.quarantined = set()

    # ------------------------------------------------------------------
    # Fail-safe
    # ------------------------------------------------------------------
    def _guard(self, action, target=None):
        # Trust is mandatory for active mutations; observation has its own path.
        # Etkin değişiklikler güven kararı gerektirir; gözlem yolu ayrıdır.
        if self.replay:
            return {'status': 'replay_skip', 'action': action, 'target': target}
        if not bool(self.config.get('response_enabled', False)):
            try:
                self.store.add('actions', {
                    'timestamp': time.time(),
                    'status': 'response_disabled',
                    'requested_action': action,
                    'target': target,
                })
            except Exception:
                pass
            return {'status': 'response_disabled', 'action': action, 'target': target}
        if action != 'emergency_backup':
            from .intervention_guard import evaluate
            decision = evaluate(self.store)
            if not decision['allowed']:
                return {'status':'integrity_locked','action':action,'target':target,
                        'reasons':decision['reasons'],'trust':decision,'signal_sent':False}
        return None

    # ------------------------------------------------------------------
    # Persistent nft state (root-owned core.db state table)
    # ------------------------------------------------------------------
    def _persistent_blocks(self) -> dict:
        getter = getattr(self.store, "get", None)
        blocks = getter("persistent_blocks", {}) if callable(getter) else {}
        return dict(blocks) if isinstance(blocks, dict) else {}

    def _persist_block(self, ip: str, set_name: str, reason: str, raw_id=None,
                       manual: bool = False, duration: int = 0) -> bool:
        setter = getattr(self.store, "set", None)
        if not callable(setter):
            return False
        try:
            if getattr(self.store,"db",None) is not None:
                self.store.db.execute("BEGIN IMMEDIATE")
            blocks = self._persistent_blocks()
            blocks[ip] = {
                "ip": ip,
                "nft_family": self.nft_family,
                "nft_table": self.nft_table,
                "nft_set": set_name,
                "added_at": time.time(),
                "reason": reason,
                "raw_id": raw_id,
                "manual": bool(manual),
                "duration": int(duration or 0),
                "state": "active",
            }
            setter("persistent_blocks", blocks)
            add = getattr(self.store, "add", None)
            if callable(add):
                add("actions", {
                    "timestamp": time.time(),
                    "status": "nft_state_persisted",
                    "ip": ip,
                    "nft_set": set_name,
                    "reason": reason,
                    "source": "block_ip",
                })
            return True
        except Exception:
            if getattr(self.store,"db",None) is not None:self.store.db.rollback()
            try:
                add = getattr(self.store, "add", None)
                if callable(add):
                    add("errors", {
                        "timestamp": time.time(),
                        "component": "response.persistent_state",
                        "ip": ip,
                        "nft_set": set_name,
                        "error": "persistent state write failed",
                    })
            except Exception:
                pass
            return False

    @staticmethod
    def _protected_ip(addr: ipaddress._BaseAddress, manual: bool):
        if addr.is_loopback or addr.is_multicast or addr.is_unspecified:
            return 'protected_target'
        if not manual:
            from .full_protection import protected_reason
            return protected_reason(addr)
        return None

    # ------------------------------------------------------------------
    # 1. IP BLOKLAMA
    # ------------------------------------------------------------------
    def _privd(self, op, **params):
        """privd's answer (2.2.15), or None when this process acts itself.

        Tests (runner given) and replays never leave this process.
        """
        if self.runner is not None or self.replay:
            return None
        action = {'block_ip':'block_ip', 'unblock_ip':'unblock_ip', 'terminate':'kill_process',
                  'terminate_tree':'kill_process'}.get(op)
        if action:
            denied = self._guard(action, params.get('pid', params.get('ip')))
            if denied:
                return denied
        from .privd import delegate
        return delegate(op, **params)

    def block_ip(self, ip, reason, raw_id=None, manual=False, duration=0):
        answer = self._privd('block_ip', ip=str(ip), reason=str(reason)[:500], manual=bool(manual),
                             raw_id=raw_id, duration=int(duration or 0))
        if answer is not None:
            return answer
        from .network_control import block
        try:return block(self,ip,reason,raw_id,manual,duration)
        except (ValueError,OSError,RuntimeError,sqlite3.Error,subprocess.TimeoutExpired) as exc:return {'status':'failed','error':str(exc)}

    def block(self, ip, reason, raw_id=None, manual=False):
        return self.block_ip(ip, reason, raw_id, manual)

    def unblock_ip(self, ip, reason, manual=False):
        answer = self._privd('unblock_ip', ip=str(ip), reason=str(reason)[:500], manual=bool(manual))
        if answer is not None:
            return answer
        from .network_control import unblock
        try:return unblock(self,ip,reason,manual)
        except (ValueError,OSError,RuntimeError,sqlite3.Error,subprocess.TimeoutExpired) as exc:return {'ok':False,'status':'failed','error':str(exc)}

    # ------------------------------------------------------------------
    # 2. SÜREÇ ÖLDÜRME
    # ------------------------------------------------------------------
    @staticmethod
    def _safe_pid(pid):
        try:
            value = int(pid)
        except (TypeError, ValueError):
            return None
        if value <= 1 or value == os.getpid():
            return None
        return value

    @staticmethod
    def _children_of(pid):
        children_file = Path(f'/proc/{pid}/task/{pid}/children')
        try:
            return [int(x) for x in children_file.read_text().split() if x.isdigit()]
        except (OSError, ValueError):
            return []

    def _descendants(self, pid, limit=256):
        result = []
        queue = [pid]
        seen = {pid}
        while queue and len(result) < limit:
            parent = queue.pop(0)
            for child in self._children_of(parent):
                if child in seen or child <= 1 or child == os.getpid():
                    continue
                seen.add(child)
                result.append(child)
                queue.append(child)
        return result

    def _deny_process_identity(self, status, pid, reason, details=None):
        record = {
            'timestamp': time.time(),
            'status': status,
            'pid': pid,
            'reason': reason,
            'executed': False,
        }
        if details:
            record['identity'] = details
        try:
            self.store.add('actions', record)
        except Exception:
            pass
        return {
            'status': status,
            'pid': pid,
            'reason': reason,
            'identity': details or {},
        }

    def _identity_failure(self, pid, result):
        return self._deny_process_identity(
            'identity_verification_failed',
            pid,
            result.get('reason', 'identity_verification_failed'),
            result,
        )

    def kill_process(self, pid, reason, sig=signal.SIGTERM, evidence=None, context=None):
        """Terminate one process only after full target identity verification.

        ``evidence`` must carry the detection-time PID, starttime and
        executable path.  Missing or mismatching evidence is fail-closed and
        no signal is sent.  Callers cannot bypass this gate by using the
        public method directly.
        """
        evidence_denied = self._rule_evidence_guard('process_kill', evidence, context)
        if evidence_denied:
            return evidence_denied
        pid = self._safe_pid(pid)
        if pid is None:
            return {'status': 'invalid_or_protected_pid', 'pid': pid}
        # 2.2.62: privd sends the signal (it re-verifies the identity in its own process).
        answer = self._privd('terminate', pid=int(pid), reason=str(reason)[:500],
                             evidence=evidence if isinstance(evidence, dict) else None,
                             context=context if isinstance(context, dict) else None)
        if answer is not None:
            return answer
        denied = self._guard('kill_process', pid)
        if denied:
            return denied
        identity = verify_process_identity(pid, evidence=evidence)
        if not identity.get('ok'):
            return self._identity_failure(pid, identity)
        try:
            evidence_denied = self._rule_evidence_guard('process_kill', evidence, context)
            if evidence_denied:
                return evidence_denied
            os.kill(pid, sig)
            self.killed.add(pid)
            self.store.add('actions', {
                'timestamp': time.time(),
                'status': 'process_killed',
                'pid': pid,
                'signal': int(sig),
                'reason': reason,
                'identity_verified': True,
                'exe': identity.get('live_exe'),
                'starttime': identity.get('live_starttime'),
            })
            return {'status': 'killed', 'pid': pid}
        except (ProcessLookupError, PermissionError, ValueError, OSError) as exc:
            return {'status': 'failed', 'pid': pid, 'error': str(exc)}

    def _rule_evidence_guard(self, action, evidence, context):
        from .rule_response import requirement_for, evidence_report
        from .ai_rule_package import is_ai_finding
        context = context if isinstance(context, dict) else {}
        finding = context.get('finding') or {'rule_id': context.get('rule_id'), 'event': evidence}
        # The RAM ClamAV engine was retired. Never let legacy findings or
        # pre-retirement action payloads reach the privileged signal backend.
        # This check must precede the _privd delegation as well as fallbacks.
        if action in ('process_kill', 'kill_process', 'terminate'):
            retired = {'SATSUMA-RAM-106', 'SATSUMA-RAM-107'}
            rule_id = str(finding.get('rule_id') or context.get('rule_id') or '')
            raw_action = evidence.get('action') if isinstance(evidence, dict) else None
            if (rule_id in retired or raw_action in ('ram_signature_match_v2', 'ram_review_v2')
                    or context.get('ram_v2_required')):
                return {'status': 'policy_denied', 'signal_sent': False,
                        'reasons': ['ram_clamav_retired']}
        if context.get('finding') and finding.get('event') != evidence:
            from .rule_response import _identity
            if _identity(finding.get('event') or {}, action, context) != _identity(evidence or {}, action, context):
                return {'status':'policy_denied','signal_sent':False,'reasons':['finding_and_action_target_mismatch']}
        if is_ai_finding(finding):
            from .ai_enforcement import confirm
            confirmed = confirm(finding, self.store, context) if action in ('kill_process', 'process_kill', 'terminate') else {'passed': False, 'missing': ['ai_proposal_requires_separate_operator_action']}
            if not confirmed['passed']:
                return {'status': 'policy_denied', 'signal_sent': False, 'reasons': confirmed['missing']}
            return None
        try:
            requirement = requirement_for(finding, self.config, self.store)
            if requirement and requirement['minimum_sources'] > 1:
                report = evidence_report(self.store, finding, action, requirement, context)
                if not report['passed']:
                    return {'status': 'policy_denied', 'signal_sent': False, 'reasons': report['missing']}
        except (ValueError, TypeError, KeyError):
            return {'status': 'policy_denied', 'signal_sent': False, 'reasons': ['invalid_rule_evidence_policy']}
        return None

    def terminate_process(self, pid, reason, evidence=None, context=None):
        """Stop one verified Linux process, with PID-safe bounded escalation.

        ``context`` carries why the stop was decided (rule, finding, whether
        a memory code difference is the basis). Before SIGTERM and again
        before SIGKILL the guards, the identity and, for a memory-based stop,
        the debugger state and the code difference are checked again. /proc
        reads are not pinned by the pidfd, so the identity is rechecked after
        the code read. This narrows the race between check and signal; it
        does not close it.
        """
        evidence_denied = self._rule_evidence_guard('process_kill', evidence, context)
        if evidence_denied:
            return evidence_denied
        try:
            answer = self._privd('terminate', pid=int(pid), reason=str(reason)[:500],
                                 evidence=evidence if isinstance(evidence, dict) else None,
                                 context=context if isinstance(context, dict) else None)
        except (TypeError, ValueError):
            answer = None
        if answer is not None:
            return answer
        from copy import deepcopy
        from .process_identity import read_tracer_pid
        from .memory_validation import validate_executable
        evidence = deepcopy(evidence) if isinstance(evidence, dict) else evidence
        context = deepcopy(context) if isinstance(context, dict) else {}
        ram_required = bool(context.get('ram_v2_required')) or (isinstance(evidence, dict)
                        and evidence.get('action') in ('ram_signature_match_v2', 'ram_review_v2'))
        memory_required = bool(context.get('memory_validation_required'))
        if isinstance(evidence, dict):
            memory_required = memory_required or (evidence.get('source') == 'memory'
                                                  and evidence.get('action') == 'executable_code_mismatch')
        evidence_denied = self._rule_evidence_guard('process_kill', evidence, context)
        if evidence_denied:
            return evidence_denied
        pid = self._safe_pid(pid)
        if pid is None:
            return {'status': 'invalid_or_protected_pid', 'signal_sent': False}
        denied = self._guard('kill_process', pid)
        if denied:
            return {**denied, 'signal_sent': False}
        identity = verify_process_identity(pid, evidence=evidence)
        if not identity.get('ok'):
            return {**self._identity_failure(pid, identity), 'signal_sent': False}
        fd = None
        sent = False
        escalated = False
        rechecks = {}

        def finish(status, **extra):
            check = list(rechecks.values())[-1] if rechecks else {}
            result = {'action': 'process.terminate', 'status': status, 'pid': pid,
                      'signal_sent': sent, 'exit_verified': extra.pop('exit_verified', False),
                      'escalated': escalated, 'reason': reason,
                      'rule_id': context.get('rule_id'), 'finding_id': context.get('finding_id'),
                      'memory_validation_required': memory_required,
                      'memory_validation_complete': check.get('complete'), **extra}
            self.store.add('actions', {**result, 'timestamp': time.time()})
            return result

        def pre_signal(stage, check_exited):
            evidence_denied = self._rule_evidence_guard('process_kill', evidence, context)
            if evidence_denied:
                return finish('policy_denied', stage=stage, reasons=evidence_denied['reasons'])
            denied = self._guard('kill_process', pid)
            if denied:
                return finish(denied['status'], stage=stage, guard=denied)
            if check_exited and poller.poll(0):
                # SIGTERM already worked; nothing stronger is needed.
                return finish('terminated', stage=stage, exit_verified=True)
            identity = verify_process_identity(pid, evidence=evidence)
            if not identity.get('ok'):
                return finish('identity_recheck_failed', stage=stage, identity=identity)
            if ram_required:
                # Never re-read process RAM through a retired ClamAV path.
                return finish('ram_clamav_retired', stage=stage)
            if not memory_required:
                return None
            tracer = read_tracer_pid(pid)
            if tracer is None:
                return finish('debugger_state_unknown', stage=stage)
            if tracer != 0:
                return finish('debugger_attached_review_required', stage=stage, tracer_pid=tracer)
            recheck = validate_executable('/proc/' + str(pid))
            rechecks[stage] = {k: v for k, v in recheck.items() if k != 'regions'}
            if recheck.get('status') != 'CODE_MISMATCH':
                return finish('code_recheck_failed', stage=stage, recheck=rechecks[stage])
            # The code read went through /proc, not the pidfd: a reused PID
            # or an exec must not authorize the signal.
            identity = verify_process_identity(pid, evidence=evidence)
            if not identity.get('ok'):
                return finish('identity_recheck_failed', stage=stage, identity=identity)
            tracer = read_tracer_pid(pid)
            if tracer is None:
                return finish('debugger_state_unknown', stage=stage)
            if tracer != 0:
                return finish('debugger_attached_review_required', stage=stage, tracer_pid=tracer)
            return None

        try:
            # A pidfd refers to one process instance even if its PID is reused.
            fd = os.pidfd_open(pid)
            poller = select.poll()
            poller.register(fd, select.POLLIN)
            denied = pre_signal('before_sigterm', check_exited=False)
            if denied:
                return denied
            signal.pidfd_send_signal(fd, signal.SIGTERM)
            sent = True
            if not poller.poll(1000):
                # The SIGTERM handler may restore code, exec or attach a
                # tracer: check everything again before the stronger signal.
                denied = pre_signal('before_sigkill', check_exited=True)
                if denied:
                    return denied
                signal.pidfd_send_signal(fd, signal.SIGKILL)
                escalated = True
            exited = bool(poller.poll(1000))
            return finish('terminated' if exited else 'termination_pending', exit_verified=exited)
        except (AttributeError, OSError, ValueError) as exc:
            return {'status': 'termination_failed', 'pid': pid,
                    'signal_sent': sent, 'exit_verified': False, 'error': str(exc)}
        finally:
            if fd is not None:
                os.close(fd)

    def kill_process_tree(self, pid, reason, evidence=None, context=None):
        """Terminate a verified root process and its live descendants.

        The root PID must pass the same evidence identity gate as
        :meth:`kill_process`.  Descendants are captured from live ``/proc``
        state and are revalidated by starttime and canonical exe immediately
        before each signal, so PID reuse cannot redirect the kill.
        """
        evidence_denied = self._rule_evidence_guard('process_kill', evidence, context)
        if evidence_denied:
            return evidence_denied
        try:
            answer = self._privd('terminate_tree', pid=int(pid), reason=str(reason)[:500],
                                 evidence=evidence if isinstance(evidence, dict) else None,
                                 context=context if isinstance(context, dict) else None)
        except (TypeError, ValueError):
            answer = None
        if answer is not None:
            return answer
        pid = self._safe_pid(pid)
        if pid is None:
            return {'status': 'invalid_or_protected_pid', 'pid': pid}
        denied = self._guard('kill_process_tree', pid)
        if denied:
            return denied
        identity = verify_process_identity(pid, evidence=evidence)
        if not identity.get('ok'):
            return self._identity_failure(pid, identity)

        descendants = self._descendants(pid)
        candidates = list(reversed(descendants)) + [pid]
        captured = []
        failed = []
        for target in candidates:
            item = capture_process_identity(target)
            if item is None:
                failed.append({'pid': target, 'error': 'identity_capture_failed'})
                continue
            captured.append(item)
        captured_by_pid = {item['pid']: item for item in captured}

        killed = []
        # Children first, then the verified root.
        for item in captured:
            target = item['pid']
            if not revalidate_captured_identity(item):
                failed.append({'pid': target, 'error': 'identity_changed_before_signal'})
                continue
            try:
                evidence_denied = self._rule_evidence_guard('process_kill', evidence, context)
                if evidence_denied:
                    return evidence_denied
                os.kill(target, signal.SIGTERM)
                killed.append(target)
            except ProcessLookupError:
                continue
            except (PermissionError, OSError) as exc:
                failed.append({'pid': target, 'error': str(exc)})

        # Short grace period, then KILL only processes whose captured identity
        # still matches.  This prevents a reused PID from being signalled.
        time.sleep(0.15)
        for target in list(killed):
            original = captured_by_pid.get(target)
            if original is None or not revalidate_captured_identity(original):
                continue
            if Path(f'/proc/{target}').exists():
                try:
                    evidence_denied = self._rule_evidence_guard('process_kill', evidence, context)
                    if evidence_denied:
                        return evidence_denied
                    os.kill(target, signal.SIGKILL)
                except (ProcessLookupError, PermissionError, OSError):
                    pass

        self.killed.update(killed)
        self.store.add('actions', {
            'timestamp': time.time(),
            'status': 'process_tree_killed',
            'pid': pid,
            'pids': killed,
            'failed': failed,
            'reason': reason,
            'identity_verified': True,
            'exe': identity.get('live_exe'),
            'starttime': identity.get('live_starttime'),
        })
        return {'status': 'killed_tree', 'pid': pid, 'pids': killed, 'failed': failed}

    # ------------------------------------------------------------------
    # 3. DOSYA KARANTİNA
    # ------------------------------------------------------------------
    def quarantine_file(self, path, reason):
        denied = self._guard('quarantine_file', path)
        if denied:
            return denied
        _ensure_quarantine()
        try:
            src = Path(path).resolve(strict=True)
        except (OSError, RuntimeError):
            return {'status': 'not_found', 'path': str(path)}
        if not src.is_file():
            return {'status': 'not_regular_file', 'path': str(src)}
        if any(src == root or root in src.parents for root in PROTECTED_QUARANTINE_ROOTS):
            return {'status': 'protected_path', 'path': str(src)}

        ts = datetime.now().strftime('%Y%m%d-%H%M%S')
        dst = QUARANTINE_DIR / f"{ts}-{src.name}"
        try:
            shutil.move(str(src), str(dst))
            os.chmod(dst, 0o600)
            self.quarantined.add(str(dst))
            self.store.add('actions', {
                'timestamp': time.time(), 'status': 'file_quarantined',
                'source': str(src), 'destination': str(dst), 'reason': reason,
            })
            return {'status': 'quarantined', 'source': str(src), 'destination': str(dst)}
        except (OSError, PermissionError) as exc:
            return {'status': 'failed', 'path': str(src), 'error': str(exc)}

    # ------------------------------------------------------------------
    # 4. KULLANICI KİLİTLEME
    # ------------------------------------------------------------------
    def lock_user(self, uid_or_name, reason):
        if str(uid_or_name) in {'0', 'root'}:
            return {'status': 'protected_user', 'user': str(uid_or_name)}
        denied = self._guard('lock_user', str(uid_or_name))
        if denied:
            return denied
        try:
            r = subprocess.run(['usermod', '-L', str(uid_or_name)], capture_output=True, text=True, timeout=5)
            if r.returncode == 0:
                self.store.add('actions', {
                    'timestamp': time.time(), 'status': 'user_locked',
                    'user': str(uid_or_name), 'reason': reason,
                })
                return {'status': 'locked', 'user': str(uid_or_name)}
            return {'status': 'failed', 'user': str(uid_or_name), 'error': r.stderr}
        except Exception as exc:
            return {'status': 'failed', 'user': str(uid_or_name), 'error': str(exc)}

    # 5. (removed) Config restore unpacked an unchecked archive from
    #    /root/satsuma-backup-* over / as root; nothing called it (audit G6).
    #    (kaldırıldı) Yapılandırma geri yükleme denetlenmemiş bir arşivi root
    #    olarak köke açıyordu; hiçbir yerden çağrılmıyordu (denetim G6).

    # ------------------------------------------------------------------
    # 6. DOSYA SİSTEMİ DONDURMA
    # ------------------------------------------------------------------
    def freeze_filesystem(self, path, reason):
        denied = self._guard('freeze_filesystem', path)
        if denied:
            return denied
        try:
            r = subprocess.run(['mount', '-o', 'remount,ro', path], capture_output=True, text=True, timeout=5)
            if r.returncode == 0:
                self.store.add('actions', {
                    'timestamp': time.time(), 'status': 'filesystem_frozen',
                    'path': path, 'reason': reason,
                })
                return {'status': 'frozen', 'path': path}
            return {'status': 'failed', 'path': path, 'error': r.stderr}
        except Exception as exc:
            return {'status': 'failed', 'path': path, 'error': str(exc)}

    # ------------------------------------------------------------------
    # 7. ACİL YEDEK
    # ------------------------------------------------------------------
    def emergency_backup(self, reason):
        denied = self._guard('emergency_backup')
        if denied:
            return denied
        ts = datetime.now().strftime('%Y%m%d-%H%M%S')
        dst = Path(f'/root/emergency-backup-{ts}')
        try:
            dst.mkdir(parents=True, exist_ok=True)
            subprocess.run(['sqlite3', '/var/lib/satsuma-core/core.db', f".backup '{dst}/core.db.backup'"], timeout=300)
            subprocess.run(['tar', '-czf', f'{dst}/config.tar.gz', '/etc/satsuma-core'], timeout=60)
            self.store.add('actions', {
                'timestamp': time.time(), 'status': 'emergency_backup',
                'path': str(dst), 'reason': reason,
            })
            return {'status': 'backed_up', 'path': str(dst)}
        except Exception as exc:
            return {'status': 'failed', 'error': str(exc)}

    # 8. (removed) DNS sinkhole appended an unvalidated domain to /etc/hosts
    #    as root; a newline in it could add any name -> address line, a MITM
    #    door. Nothing called it. DNS blocking goes through dnsmasq.
    #    (kaldırıldı) Doğrulanmamış alan adını root olarak /etc/hosts'a
    #    yazıyordu; içindeki bir satır sonu herhangi bir ad -> adres satırı
    #    ekleyebilirdi (MITM kapısı). Hiçbir yerden çağrılmıyordu.

    # ------------------------------------------------------------------
    # 9. ADMIN BİLDİRİM — sistem durumu değiştirmez, response_enabled'dan bağımsız.
    # ------------------------------------------------------------------
    def notify_admin(self, title, message, urgency='normal'):
        try:
            subprocess.run(['notify-send', '-u', urgency, '-t', '10000', title, message], timeout=5, capture_output=True)
            self.store.add('actions', {
                'timestamp': time.time(), 'status': 'notified',
                'title': title, 'message': message[:200], 'urgency': urgency,
            })
            return {'status': 'notified'}
        except Exception as exc:
            return {'status': 'failed', 'error': str(exc)}

    def auto_kill(self, pid, reason, evidence=None, context=None):
        # Auto-kill is intentionally disabled unless the caller can supply the
        # same full identity evidence required by kill_process_tree.
        return self.kill_process_tree(pid, f"auto: {reason}", evidence=evidence, context=context)
