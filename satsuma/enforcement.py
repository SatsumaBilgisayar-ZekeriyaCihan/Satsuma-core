"""Automatic blocking: stop the process behind a rule match.

Since 2.2.9 (full protection) this covers every suspicious, likely and
confirmed rule at any severity, critical indicators and attack-tool
indicators; see ENFORCED and ATTACK_INDICATORS. Since 2.2.13 a passwordless
"sudo -n" / "sudo -S" is stopped too while sudo autoblock is on
(satsuma.sudo_nopasswd).

The user asked for the rules to be active, not only reported (2026-10-25).
With the policy on, a fresh finding from a rule whose classification and
severity are in ENFORCED stops the exact process in the event (identity
checked again before the signal by ResponseWorker). One sensor is enough;
the earlier two-sensor/two-rule confirmation is not required under this
explicit user policy. Since 2.2.38 no program is exempt by its name or its
unit (owner, 2026-11-13: code a remote-support peer sends through TeamViewer
or AnyDesk must be stopped, and malware must not hide inside a protected
name). Only two things are never signalled: PID 1, which the kernel does not
let anyone kill (a critical alarm is raised instead), and a command the
owner started from the dashboard with the admin password. The policy is on by default and
can be switched off in the dashboard (that asks for the password again).
Integrity locks and the operator pause still apply.

Otomatik engelleme: bir kural eşleşmesinin arkasındaki işlemi durdurur.

2.2.9 (tam koruma) ile her önem düzeyindeki şüpheli, muhtemel ve kesin
kuralları, kritik göstergeleri ve saldırı aracı göstergelerini kapsar;
bkz. ENFORCED ve ATTACK_INDICATORS. 2.2.13'ten beri sudo oto-blok açıkken
parolasız "sudo -n" / "sudo -S" de durdurulur (satsuma.sudo_nopasswd).

Kullanıcı kuralların yalnızca bildirmesini değil, etkin olmasını istedi
(2026-10-25). İlke açıkken, sınıflaması ve önemi ENFORCED içinde olan bir
kuraldan gelen taze bulgu, olaydaki işlemin kendisini durdurur (kimlik,
sinyalden önce ResponseWorker tarafından yeniden denetlenir). Tek sensör
yeterlidir; bu açık kullanıcı ilkesinde önceki iki sensör/iki kural
doğrulaması aranmaz. 2.2.38'den beri hiçbir program adına ya da birimine
göre muaf değildir (sahibi, 2026-11-13: uzak destekte karşı tarafın
TeamViewer ya da AnyDesk üzerinden gönderdiği kod durdurulmalı; zararlı
korunan bir adın içine saklanamamalı). Yalnızca iki şeye sinyal gönderilmez:
çekirdeğin kimsenin öldürmesine izin vermediği PID 1 (yerine kritik alarm
verilir) ve sahibinin panelden yönetici parolasıyla başlattığı komut. İlke
varsayılan olarak açıktır ve panelden kapatılabilir (kapatmak parolayı
yeniden ister). Bütünlük kilitleri ve operatör duraklatması geçerli kalır.
"""
import os
import time
from pathlib import Path

# Eligibility below is not authorization. Explicit per-rule evidence requirements
# in rule_response are mandatory in response_policy and final process guards;
# enabling this general policy cannot waive them.
POLICY_KEY = 'enforcement_policy'
# Full protection (2.2.9): every suspicious/likely/confirmed rule, at any
# severity, plus critical indicators and the indicators that name an attack
# tool rather than ordinary activity (reverse shells, Metasploit, netcat and
# socat tunnels). Other indicators (clipboard, browser history, ps, git…)
# describe what normal programs do all day and stay reports.
SEVERITIES = ('low', 'medium', 'high', 'critical')
ENFORCED = ({(c, s) for c in ('suspicious', 'likely', 'confirmed') for s in SEVERITIES}
            | {('indicator', 'critical')})
ATTACK_INDICATORS = frozenset((
    'SATSUMA-EXEC-002', 'SATSUMA-EXEC-003', 'SATSUMA-EXEC-004', 'SATSUMA-EXEC-005',
    'SATSUMA-EXEC-006', 'SATSUMA-EXEC-011', 'SATSUMA-EXEC-015',
    'SATSUMA-EXFIL-006', 'SATSUMA-EXFIL-011',
    # Writable and executable memory without a file: where injected shellcode
    # lives. Owner's decision 2026-11-11: stopped, not only reported; the same
    # exemptions apply (Satsuma, remote support, desktop, package manager).
    # Dosyasız yazılabilir+çalıştırılabilir bellek: enjekte edilen kodun yeri.
    # Sahibinin kararı 2026-11-11: yalnızca bildirilmez, durdurulur.
    'SATSUMA-RAM-001',
    # 2.2.38 (owner, 2026-11-13): every RAM detection stops the process, none is
    # only recorded: code run from memfd (002, 003), a program whose file was
    # deleted (004, package updates excluded by the worker), a traced process
    # (009, only root may trace under ptrace_scope 2). Retired RAM-ClamAV
    # signature rules 106/107 are not active attack indicators.
    # 2.2.38 (sahibi, 2026-11-13): hiçbir RAM tespiti yalnızca kaydedilmez; süreç durdurulur.
    'SATSUMA-RAM-002', 'SATSUMA-RAM-003', 'SATSUMA-RAM-004', 'SATSUMA-RAM-009'))
# 2.2.38: the list of programs exempt by name is gone (owner, 2026-11-13).
# 2.2.38: ada göre muaf programlar listesi kaldırıldı (sahibi, 2026-11-13).
INIT_PID = 1
# 2.2.38 (owner, 2026-11-16): SATSUMA-RAM-001 is loosened. Browsers, Java, Node,
# Python and .NET build writable+executable buffers (JIT) all day, so stopping
# on the indicator alone stopped everything. A program whose file is a root-owned
# regular file in a folder nobody else can write (trusted_path) is recorded, not
# stopped; anything else (a dropped binary, memfd, a deleted file, /tmp, a home
# folder) is still stopped. Same rule as Windows (program_not_in_expected_location).
# 2.2.38 (sahibi, 2026-11-16): RAM-001 gevşetildi. Tarayıcı, Java, Node, Python
# ve .NET gün boyu yazılabilir+çalıştırılabilir tampon (JIT) kurar; yalnızca
# göstergeye bakmak her şeyi durduruyordu. Program dosyası root sahipli, kimsenin
# yazamadığı klasördeki normal dosyaysa kaydedilir, durdurulmaz; geri kalanı
# (bırakılmış ikili, memfd, silinmiş dosya, /tmp, ev klasörü) yine durdurulur.
RWX_RULE = 'SATSUMA-RAM-001'


def policy(store):
    """Stored policy; on unless the user switched it off."""
    stored = store.get(POLICY_KEY, None) if store is not None else None
    if not isinstance(stored, dict) or type(stored.get('enabled')) is not bool:
        return {'enabled': True, 'source': 'default'}
    return stored


def sudo_autoblock(finding, sudo_enabled=True):
    """Passwordless sudo at run time (satsuma.sudo_nopasswd), when the switch is on."""
    from .sudo_nopasswd import RUNTIME_RULES
    return bool(sudo_enabled) and str(finding.get('rule_id', '')) in RUNTIME_RULES


def automatic_allowed(finding, sudo_enabled=True):
    """Classes any automatic response may act on: not plain activity indicators."""
    if str(finding.get('rule_id', '')) in ATTACK_INDICATORS or sudo_autoblock(finding, sudo_enabled):
        return True
    classification = str(finding.get('classification', '')).lower()
    if classification in ('suspicious', 'likely', 'confirmed'):
        return True
    return classification == 'indicator' and str(finding.get('severity', '')).lower() == 'critical'


def eligible(finding, sudo_enabled=True):
    if str(finding.get('rule_id', '')) in ATTACK_INDICATORS or sudo_autoblock(finding, sudo_enabled):
        return True
    return (str(finding.get('classification', '')).lower(), str(finding.get('severity', '')).lower()) in ENFORCED


def exempt(pid, executable, finding=None, proc_root='/proc'):
    """Reason the process cannot be stopped, or None.

    No name and no unit protects a process: a rule match inside TeamViewer,
    AnyDesk, the desktop or Satsuma itself means something got in, and it is
    stopped. PID 1 cannot be killed by anyone; the caller raises a critical
    alarm for it. A command the owner started from the dashboard (admin
    password, satsuma-operator) is the owner's own action.

    Hiçbir ad ya da birim bir süreci korumaz: TeamViewer, AnyDesk, masaüstü ya
    da Satsuma'nın içinde kural eşleşmesi bir şeyin girdiği anlamına gelir ve
    durdurulur. PID 1'i kimse öldüremez; çağıran onun için kritik alarm verir.
    Sahibinin panelden parolayla başlattığı komut sahibinin kendi işidir.
    """
    from .trusted_process import system_service
    try:
        if int(pid) == INIT_PID:
            return 'init_cannot_be_stopped'
    except (TypeError, ValueError):
        return None
    try:cgroups=Path(proc_root,str(pid),'cgroup').read_text()
    except (OSError,ValueError):cgroups=''
    unit=system_service(cgroups)
    if (finding or {}).get('origin') == 'satsuma_operator' and unit=='satsuma-operator.service':
        return 'satsuma_dashboard_action'
    return None


def rwx_kept(finding, executable, pid=None):
    """Reason a RAM-001 match is only recorded, or None when the process is stopped.

    RAM-001 yalnızca kaydedilir mi: program güvenilir yoldaysa neden, değilse None.
    """
    if str((finding or {}).get('rule_id', '')) != RWX_RULE or not executable:
        return None
    path = str(executable)
    if 'memfd:' in path:
        return None
    # 2.2.38: a " (deleted)" program counts only when a root-owned file nobody
    # else can write is back at the same path (a package update replaced it
    # while it ran, e.g. Firefox during dnf update), the same rule as
    # worker_memory's replaced_executable. A program removed to hide (nothing
    # at the path, or a file in /tmp) is still stopped. The caller passes the
    # path already without the suffix (process_identity.canonical_exe_path).
    # Güncellemeyle yerine root dosyası gelmiş program kaydedilir; gizlenmek
    # için silinen program yine durdurulur.
    from .trusted_process import trusted_path, trusted_running_program
    if trusted_path(path.removesuffix(' (deleted)')):
        return 'trusted_program_jit_memory'
    # 2.2.41: a sandboxed program (Flatpak) reports a path of its own namespace;
    # the running file itself is judged (trusted_process.trusted_running_program).
    if pid is not None and trusted_running_program(pid):
        return 'trusted_program_jit_memory'
    return None


def apply(store, config):
    """Config that lets the automatic process path act while the policy is on."""
    if not policy(store).get('enabled'):
        return dict(config)
    allowed = list(config.get('destructive_allowed_actions') or [])
    if 'process_kill' not in allowed:
        allowed.append('process_kill')
    return {**config, 'response_enabled': True, 'destructive_response_enabled': True,
            'destructive_allowed_actions': allowed, 'auto_action_process_enabled': True,
            'user_enforcement': True}


def set_policy(store, enabled, uid=None):
    record = {'enabled': bool(enabled), 'source': 'operator', 'operator_uid': uid, 'updated_at': time.time()}
    store.set(POLICY_KEY, record)
    return record


def describe(store):
    p = policy(store)
    return {**p, 'enforced_rules': 'her önem düzeyinde şüpheli, muhtemel ve kesin saldırı kuralları; kritik göstergeler; ters shell, Metasploit, netcat/socat tünelleri',
            'never_stopped': 'Satsuma, TeamViewer, AnyDesk, masaüstü ve paket yöneticisi'}
