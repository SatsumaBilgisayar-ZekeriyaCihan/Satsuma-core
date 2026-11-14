"""Inventory and vet everything that runs in early boot, not only Satsuma.

The installed system comes from an untrusted supply chain, and the init
system is what will run Satsuma, so Satsuma checks it. Read-only. Collected:

- early units: DefaultDependencies=no or pulled in by sysinit.target, with
  their unit file and drop-ins;
- systemd generators (they run before any unit);
- the initramfs of the running kernel: dracut modules, hooks and the files
  it carries;
- the kernel command line;
- files that act during boot: modules-load.d, modprobe.d (``install`` lines
  run commands), udev rules (RUN/PROGRAM), binfmt.d, tmpfiles.d, sysctl.d,
  dracut.conf.d and /etc/ld.so.preload.

Every file is checked with lstat (never followed): package owner, rpm -V
result, owner, mode and link target. An executable or unit nobody packaged,
a changed packaged file, a link leaving the system trees, or a group- or
world-writable file is a finding. The package database itself may be
tampered with; that is checked separately against signed packages, and this
report says ``trust: local_rpmdb``.

Erken açılışta çalışan her şeyin envanteri ve denetimi; yalnızca Satsuma değil.

Kurulu sistem güvenilmeyen bir tedarik zincirinden geliyor ve Satsuma'yı
çalıştıracak olan init sistemi; bu yüzden Satsuma onu denetler. Salt okunur.
Toplananlar: erken birimler (DefaultDependencies=no ya da sysinit.target'ın
çektikleri) ve ek ayarları; systemd generator'ları (her birimden önce
çalışırlar); çalışan çekirdeğin initramfs'i: dracut modülleri, kancaları ve
taşıdığı dosyalar; çekirdek komut satırı; açılışta etkili dosyalar:
modules-load.d, modprobe.d (``install`` satırları komut çalıştırır), udev
kuralları (RUN/PROGRAM), binfmt.d, tmpfiles.d, sysctl.d, dracut.conf.d ve
/etc/ld.so.preload.

Her dosya lstat ile denetlenir (bağlantı izlenmez): paket sahibi, rpm -V
sonucu, sahip, izinler ve bağlantı hedefi. Paketlenmemiş bir çalıştırılabilir
dosya ya da birim, değişmiş bir paket dosyası, sistem ağaçlarının dışına
çıkan bir bağlantı ya da grup veya herkes tarafından yazılabilen bir dosya
bulgu sayılır. Paket veritabanının kendisi de değiştirilmiş olabilir; bu
imzalı paketlere karşı ayrıca denetlenir, bu rapor ``trust: local_rpmdb``
der.
"""
import json
import os
import re
import stat
import subprocess
import time
from pathlib import Path

STATUS_FILE = Path('/var/lib/satsuma-core/boot-inventory.json')
GENERATOR_DIRS = ['/usr/lib/systemd/system-generators', '/usr/local/lib/systemd/system-generators',
                  '/etc/systemd/system-generators', '/run/systemd/system-generators',
                  '/usr/lib/systemd/user-generators', '/etc/systemd/user-generators']
BOOT_CONFIG_DIRS = ['/etc/modules-load.d', '/usr/lib/modules-load.d', '/etc/modprobe.d', '/usr/lib/modprobe.d',
                    '/etc/udev/rules.d', '/usr/lib/udev/rules.d', '/etc/binfmt.d', '/usr/lib/binfmt.d',
                    '/etc/tmpfiles.d', '/usr/lib/tmpfiles.d', '/etc/sysctl.d', '/usr/lib/sysctl.d',
                    '/etc/dracut.conf.d', '/usr/lib/dracut/dracut.conf.d']
SINGLE_FILES = ['/etc/ld.so.preload', '/etc/dracut.conf', '/etc/modprobe.conf', '/etc/sysctl.conf']
SYSTEM_TREES = ('/usr/', '/etc/', '/run/systemd/', '/proc/', '/dev/')
# Kernel parameters that switch a protection off or hand control elsewhere.
RISKY_CMDLINE = {
    'init': 'replaces the init program', 'rdinit': 'replaces the initramfs init',
    'rd.break': 'drops to a shell in the initramfs', 'rd.shell': 'allows a shell in the initramfs',
    'systemd.unit': 'boots into another target', 'systemd.debug_shell': 'opens a root shell on tty9',
    'single': 'single-user mode', 'emergency': 'emergency shell',
    'selinux': 'SELinux setting', 'enforcing': 'SELinux enforcement', 'audit': 'kernel audit',
    'module.sig_enforce': 'module signature enforcement', 'lockdown': 'kernel lockdown',
    'ima_appraise': 'IMA appraisal', 'mitigations': 'CPU vulnerability mitigations',
    'nokaslr': 'disables address randomisation', 'iommu': 'IOMMU', 'intel_iommu': 'IOMMU',
    'amd_iommu': 'IOMMU', 'usbcore.authorized_default': 'USB authorisation default',
    'systemd.mask': 'masks units at boot', 'systemd.wants': 'adds units at boot',
    'systemd.run': 'runs a command at boot', 'rd.systemd.unit': 'initramfs target',
}
SAFE_VALUES = {'selinux': {'1'}, 'enforcing': {'1'}, 'audit': {'1'}, 'module.sig_enforce': {'1'},
               'lockdown': {'integrity', 'confidentiality'}, 'mitigations': {'auto', 'auto,nosmt'},
               'iommu': {'force', 'pt'}, 'intel_iommu': {'on'}, 'amd_iommu': {'on'},
               'usbcore.authorized_default': {'0', '2'}}


def run(args, runner=subprocess.run, timeout=120):
    return runner(args, capture_output=True, text=True, timeout=timeout)


def cmdline_findings(text):
    findings = []
    for token in text.split():
        key, _, value = token.partition('=')
        if key in RISKY_CMDLINE and value not in SAFE_VALUES.get(key, set()):
            findings.append({'kind': 'kernel_cmdline', 'item': token, 'severity': 'high',
                             'reason': RISKY_CMDLINE[key]})
    return findings


def file_facts(path, lstat=os.lstat, readlink=os.readlink):
    try:
        info = lstat(path)
    except FileNotFoundError:
        return None
    facts = {'path': path, 'uid': info.st_uid, 'mode': stat.S_IMODE(info.st_mode)}
    if stat.S_ISLNK(info.st_mode):
        try:
            target = readlink(path)
        except OSError:
            target = ''
        absolute = os.path.normpath(os.path.join(os.path.dirname(path), target))
        facts.update(link=target, link_resolved=absolute)
    return facts


def file_problems(facts):
    problems = []
    if facts.get('link') is not None:
        # /dev/null links are how units are masked; other targets must stay in system trees.
        if not facts['link_resolved'].startswith(SYSTEM_TREES):
            problems.append('link_leaves_system_trees')
    else:
        if facts['uid'] != 0:
            problems.append('not_owned_by_root')
        if facts['mode'] & 0o022:
            problems.append('group_or_world_writable')
    return problems


def list_dir(path):
    try:
        return sorted(os.path.join(path, name) for name in os.listdir(path))
    except OSError:
        return []


def owners(paths, runner=subprocess.run):
    """Map each path to its package, or None when no package owns it."""
    # One query per file: a file shared by two packages prints two lines.
    result = {}
    for path in paths:
        query = run(['/usr/bin/rpm', '-qf', '--qf', '%{NAME}\n', path], runner)
        names = query.stdout.split() if query.returncode == 0 else []
        result[path] = names[0] if names else None
    return result


VERIFY_LINE = re.compile(r'^(?P<flags>\S{9})\s+(?:(?P<attr>[cdglr])\s+)?(?P<path>/.*)$')


def verify_packages(packages, runner=subprocess.run):
    """Changed files per rpm -V; config files (attr c) are reported apart."""
    changed = {}
    for name in sorted(packages):
        out = run(['/usr/bin/rpm', '-V', '--nodeps', '--noscripts', name], runner, timeout=300).stdout
        for line in out.splitlines():
            match = VERIFY_LINE.match(line)
            if match and match['flags'] != '.........':
                changed[match['path']] = {'flags': match['flags'], 'config': match['attr'] == 'c'}
            elif line.startswith('missing'):
                changed[line.split()[-1]] = {'flags': 'missing', 'config': ' c ' in line}
    return changed


def early_units(runner=subprocess.run):
    """Units with DefaultDependencies=no or reachable from sysinit.target."""
    deps = run(['/usr/bin/systemctl', 'list-dependencies', '--plain', '--no-pager', 'sysinit.target'], runner).stdout
    wanted = {line.strip().lstrip('●○ ').strip() for line in deps.splitlines() if line.strip()}
    shown = run(['/usr/bin/systemctl', 'show', '--no-pager', '-p', 'Id', '-p', 'FragmentPath', '-p', 'DropInPaths',
                 '-p', 'DefaultDependencies', '*'], runner).stdout
    units, current = [], {}
    for line in shown.splitlines() + ['']:
        if not line.strip():
            if current.get('Id') and (current.get('DefaultDependencies') == 'no' or current['Id'] in wanted):
                units.append({'unit': current['Id'], 'fragment': current.get('FragmentPath', ''),
                              'dropins': current.get('DropInPaths', '').split()})
            current = {}
            continue
        key, _, value = line.partition('=')
        current[key] = value
    return units


def initramfs(runner=subprocess.run, kernel=None):
    kernel = kernel or os.uname().release
    image = f'/boot/initramfs-{kernel}.img'
    modules = run(['/usr/bin/lsinitrd', '-m', image], runner, timeout=300).stdout
    files = run(['/usr/bin/lsinitrd', image], runner, timeout=300).stdout
    names = [line.strip() for line in modules.splitlines() if line and not line.startswith(('=', 'Image', 'Version', 'Arguments', 'dracut modules')) and ' ' not in line.strip()]
    hooks = sorted({line.split()[-1] for line in files.splitlines()
                    if '/hooks/' in line or '/cmdline.d/' in line or line.rstrip().endswith('.service')})
    return {'image': image, 'dracut_modules': names, 'hooks_and_units': hooks}


def collect(runner=subprocess.run, cmdline=None, lstat=os.lstat, readlink=os.readlink):
    findings, inventory = [], {}
    cmdline = Path('/proc/cmdline').read_text() if cmdline is None else cmdline
    inventory['kernel_cmdline'] = cmdline.strip()
    findings += cmdline_findings(cmdline)

    units = early_units(runner)
    inventory['early_units'] = units
    generators = [p for d in GENERATOR_DIRS for p in list_dir(d)]
    inventory['generators'] = generators
    boot_files = [p for d in BOOT_CONFIG_DIRS for p in list_dir(d)] + SINGLE_FILES
    try:
        inventory['initramfs'] = initramfs(runner)
    except (OSError, subprocess.SubprocessError) as exc:
        inventory['initramfs'] = {'error': str(exc)[:300]}
        findings.append({'kind': 'initramfs', 'item': 'unreadable', 'severity': 'review', 'reason': str(exc)[:200]})

    unit_files = [u['fragment'] for u in units if u['fragment']] + [d for u in units for d in u['dropins']]
    paths = sorted({p for p in unit_files + generators + boot_files if p})
    facts = {p: f for p in paths if (f := file_facts(p, lstat, readlink))}
    package_of = owners(list(facts), runner) if facts else {}
    changed = verify_packages({pkg for pkg in package_of.values() if pkg}, runner)
    for path, fact in facts.items():
        role = ('generator' if path in generators else 'unit' if path in unit_files else 'boot_config')
        problems = file_problems(fact)
        package = package_of.get(path)
        if package is None and fact.get('link') is None:
            # Generators and units run code; boot configs can still be the admin's own.
            problems.append('not_packaged')
        if path in changed:
            problems.append('config_changed' if changed[path]['config'] else 'package_file_changed')
        if path == '/etc/ld.so.preload':
            problems.append('ld_so_preload_present')
        for problem in problems:
            severe = problem not in ('config_changed',) and not (problem == 'not_packaged' and role == 'boot_config')
            findings.append({'kind': role, 'item': path, 'package': package, 'severity': 'high' if severe else 'review',
                             'reason': problem, **({'link': fact['link']} if 'link' in fact else {})})
    for finding in modprobe_commands(facts):
        # An unchanged packaged line is the distribution's own; still listed.
        if package_of.get(finding['item']) and finding['item'] not in changed:
            finding['severity'] = 'review'
        findings.append(finding)
    return {'updated_at': time.time(), 'trust': 'local_rpmdb', 'inventory': inventory,
            'findings': findings, 'status': 'FINDINGS' if any(f['severity'] == 'high' for f in findings) else 'CLEAN'}


def modprobe_commands(facts):
    """``install``/``remove`` lines in modprobe.d run an arbitrary command when a module loads."""
    findings = []
    for path in facts:
        if '/modprobe.d/' not in path or facts[path].get('link') is not None:
            continue
        try:
            text = Path(path).read_text(errors='replace')
        except OSError:
            continue
        for line in text.splitlines():
            words = line.split('#', 1)[0].split()
            if words[:1] in (['install'], ['remove']) and len(words) > 2 and words[2] not in ('/bin/true', '/bin/false', '/usr/bin/true', '/usr/bin/false'):
                findings.append({'kind': 'boot_config', 'item': path, 'severity': 'high',
                                 'reason': 'modprobe_runs_command', 'line': line.strip()[:300]})
    return findings


def save(report, path=STATUS_FILE):
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_name('.' + path.name + '.tmp')
    tmp.write_text(json.dumps(report, sort_keys=True))
    os.replace(tmp, path)


def main():
    report = collect()
    save(report)
    print(json.dumps({'status': report['status'], 'findings': len(report['findings'])}))
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
