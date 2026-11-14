"""Own and apply only Satsuma Core audit watch rules."""
import hashlib,json,os,shutil,subprocess,time
from pathlib import Path

RULE_FILE=Path('/etc/audit/rules.d/satsuma-core.rules')
KEY_PREFIX='satsuma_core_'

def render(policy,exists=os.path.exists):
 lines=['## Managed by Satsuma Core policy. Do not edit by hand.']
 missing=[]
 for target in policy['audit']['targets']:
  if not target['enabled']:continue
  if not exists(target['path']):missing.append(target['path']);continue
  digest=hashlib.sha256(target['path'].encode()).hexdigest()[:16]
  # Paths validated by policy; whitespace is rejected here because audit rule files cannot safely quote every parser variant.
  if any(x.isspace() for x in target['path']):raise ValueError('Audit target path cannot contain whitespace: '+target['path'])
  lines.append(f"-w {target['path']} -p {target['permissions']} -k {KEY_PREFIX}{digest}")
 return '\n'.join(lines)+'\n',missing

def current(path=RULE_FILE):
 try:return path.read_text()
 except FileNotFoundError:return ''

def plan(policy,path=RULE_FILE,exists=os.path.exists):
 wanted,missing=render(policy,exists)
 present=current(path)
 return {'changed':present!=wanted,'rule_file':str(path),'missing_targets':missing,'before':present,'after':wanted,'revision':policy['revision']}

def apply(policy,path=RULE_FILE,runner=subprocess.run,exists=os.path.exists):
 from satsuma.runtime_user import require_service_user; require_service_user()
 result=plan(policy,path,exists)
 if result['missing_targets']:raise FileNotFoundError('Audit targets absent: '+', '.join(result['missing_targets']))
 status=runner(['auditctl','-s'],capture_output=True,text=True,timeout=30)
 if status.returncode:raise RuntimeError('auditctl status failed: '+status.stderr[-1000:])
 if any(line.split()[:2]==['enabled','2'] for line in status.stdout.splitlines()):raise RuntimeError('Audit is immutable (enabled 2); policy saved but cannot be applied before reboot/config change')
 if not result['changed']:
  listing=runner(['auditctl','-l'],capture_output=True,text=True,timeout=30)
  expected=[line for line in result['after'].splitlines() if line.startswith('-w ')]
  verified=listing.returncode==0 and all(line.split(' -k ')[0] in listing.stdout for line in expected)
  return {**result,'status':'ALREADY_APPLIED' if verified else 'FILE_PRESENT_NOT_EFFECTIVE','verified':verified}
 path.parent.mkdir(parents=True,exist_ok=True)
 backup=None
 if path.exists():
  backup=path.with_name(path.name+'.backup-'+time.strftime('%Y%m%d-%H%M%S'));shutil.copy2(path,backup)
 tmp=path.with_name(path.name+f'.tmp-{os.getpid()}')
 try:
  fd=os.open(tmp,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600)
  with os.fdopen(fd,'w') as stream:stream.write(result['after']);stream.flush();os.fsync(stream.fileno())
  os.replace(tmp,path);os.chmod(path,0o600)
  check=runner(['augenrules','--check'],capture_output=True,text=True,timeout=30)
  if check.returncode:raise RuntimeError('augenrules check failed: '+(check.stderr or check.stdout)[-1000:])
  loaded=runner(['augenrules','--load'],capture_output=True,text=True,timeout=30)
  if loaded.returncode:raise RuntimeError('augenrules load failed: '+(loaded.stderr or loaded.stdout)[-1000:])
  listing=runner(['auditctl','-l'],capture_output=True,text=True,timeout=30)
  if listing.returncode:raise RuntimeError('auditctl verification failed: '+listing.stderr[-1000:])
  expected=[line for line in result['after'].splitlines() if line.startswith('-w ')]
  verified=all(line.split(' -k ')[0] in listing.stdout for line in expected)
  if not verified:raise RuntimeError('Audit rules loaded but effective rule verification failed')
  return {**result,'status':'APPLIED','verified':True,'backup':str(backup) if backup else None}
 except Exception:
  if backup:shutil.copy2(backup,path)
  elif path.exists():path.unlink()
  runner(['augenrules','--load'],capture_output=True,text=True,timeout=30)
  raise
 finally:
  if tmp.exists():tmp.unlink()
