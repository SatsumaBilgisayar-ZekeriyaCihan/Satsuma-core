"""Pinned package trust independent of the host RPM key database.

No trust-on-first-use, URL key import or fallback after verification failure.
"""
import hashlib
import hmac
import json
import os
from pathlib import Path
import re
import stat
import subprocess
import tempfile
import time
from urllib.parse import urlsplit

POLICY=Path('/etc/satsuma-core/package-trust/policy.json')
KEYS=Path('/etc/satsuma-core/package-trust/keys')
ROOT=Path('/var/lib/satsuma-core/package-trust')
SAFE_ENV={'PATH':'/usr/sbin:/usr/bin:/sbin:/bin','LC_ALL':'C','HOME':'/nonexistent','GNUPGHOME':'/nonexistent'}


class TrustDenied(RuntimeError):
    pass


def secure_read(path, limit=4*1024*1024):
    from .protected_storage import open_directory
    path=Path(path)
    directory=open_directory(path.parent)
    try:
        fd=os.open(path.name,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK,dir_fd=directory)
        try:
            info=os.fstat(fd)
            if not stat.S_ISREG(info.st_mode) or info.st_uid!=0 or info.st_mode & 0o022 or info.st_nlink!=1 or info.st_size>limit:
                raise TrustDenied('Unprotected trust input: '+str(path))
            with os.fdopen(os.dup(fd),'rb') as stream:data=stream.read(limit+1)
            if len(data)>limit:raise TrustDenied('Oversized trust input')
            return data
        finally:os.close(fd)
    finally:os.close(directory)


def validate_policy(policy):
    if not isinstance(policy,dict) or set(policy)!={'schema','repositories'} or type(policy['schema']) is not int or policy['schema']!=1 or not isinstance(policy['repositories'],dict):
        raise TrustDenied('Invalid package trust policy')
    for name,repo in policy['repositories'].items():
        if not re.fullmatch(r'[A-Za-z0-9_@.-]{1,128}',name) or name=='@System':
            raise TrustDenied('Invalid repository ID')
        if not isinstance(repo,dict) or set(repo)!={'sources','keys'} or not repo['keys'] or not isinstance(repo['keys'],list) or not isinstance(repo['sources'],list):
            raise TrustDenied('Repository requires explicit sources and pinned keys')
        for source in repo['sources']:
            parsed=urlsplit(source)
            if parsed.scheme!='https' or not parsed.hostname or parsed.username or parsed.password or parsed.fragment:
                raise TrustDenied('Only explicitly approved HTTPS repository sources are allowed')
        for fingerprint in repo['keys']:
            if not isinstance(fingerprint,str) or not re.fullmatch(r'(?:[0-9A-F]{40}|[0-9A-F]{64})',fingerprint):
                raise TrustDenied('Full uppercase OpenPGP fingerprint required')
    return policy


def parse_json(data):
    def unique(pairs):
        result={}
        for key,value in pairs:
            if key in result:raise TrustDenied('Duplicate JSON key')
            result[key]=value
        return result
    return json.loads(data,object_pairs_hook=unique)


def load_policy(path=POLICY):
    from installer.integrity import KEY,read_key
    raw=secure_read(path)
    signature=secure_read(Path(str(path)+'.sig'),limit=32)
    expected=hmac.new(read_key(KEY),raw,hashlib.sha256).digest()
    if not hmac.compare_digest(signature,expected):raise TrustDenied('Package trust policy signature mismatch')
    return validate_policy(parse_json(raw))


def initialize_policy(path=POLICY):
    from installer.integrity import KEY,read_key,sign
    signature=Path(str(path)+'.sig')
    if signature.exists() or signature.is_symlink():
        load_policy(path)
        return
    policy=validate_policy(parse_json(secure_read(path)))
    if policy['repositories']:raise TrustDenied('An unsigned existing trust policy must not be adopted')
    sign(Path(path),read_key(KEY))



def fingerprints(output):
    """Return primary fingerprints only, not untrusted short key IDs."""
    result=[];primary=False
    for line in output.splitlines():
        columns=line.split(':')
        if columns[0] in ('sec','ssb'):raise TrustDenied('Private key material is not allowed')
        if columns[0]=='pub':
            if columns[1] in ('r','e','d') or (columns[6] not in ('','0') and int(columns[6])<=time.time()):
                raise TrustDenied('Revoked, expired or disabled trust key')
            primary=True
        elif columns[0] in ('sub','ssb'):primary=False
        elif columns[0]=='fpr' and primary:
            result.append(columns[9].upper());primary=False
    return result


class PackageGate:
    def __init__(self,policy,keys=KEYS,work=ROOT,runner=subprocess.run,
                 rpm='/usr/bin/rpm',rpmkeys='/usr/bin/rpmkeys',gpg='/usr/bin/gpg',env=None,rpmdb='/usr/bin/rpmdb'):
        self.policy=validate_policy(policy);self.keys=Path(keys);self.work=Path(work)
        self.runner=runner;self.rpmdb=rpmdb;self.rpm=rpm;self.rpmkeys=rpmkeys;self.gpg=gpg;self.env=dict(env or SAFE_ENV)

    def call(self,args,**kwargs):
        result=self.runner(args,capture_output=True,text=True,timeout=120,env=self.env,**kwargs)
        if result.returncode:
            raise TrustDenied('Verifier rejected input: '+(result.stderr+result.stdout)[-1500:])
        return result.stdout

    def key_material(self,repo):
        materials=[]
        for expected in self.policy['repositories'][repo]['keys']:
            data=secure_read(self.keys/(expected+'.asc'))
            with tempfile.TemporaryDirectory(dir=self.work,prefix='inspect-') as directory:
                key=Path(directory)/'key.asc';key.write_bytes(data)
                output=self.call([self.gpg,'--no-options','--batch','--no-tty','--homedir',directory,
                                  '--with-colons','--import-options','show-only','--import',str(key)])
            if fingerprints(output)!=[expected]:
                raise TrustDenied('Pinned key fingerprint mismatch')
            materials.append((expected,data))
        return materials

    def repository(self,repo):
        name=repo.get('id')
        trusted=self.policy['repositories'].get(name)
        if trusted is None:raise TrustDenied('Unapproved repository: '+str(name))
        actual=repo.get('sources')
        if not isinstance(actual,list) or not actual or any(source not in trusted['sources'] for source in actual):
            raise TrustDenied('Repository source changed: '+str(name))
        return self.key_material(name)

    def seed_metadata_keys(self,repo):
        materials=self.repository(repo)
        from .protected_storage import open_directory
        cache=Path(repo['cachedir'])
        # Verify the exact cache path without following pre-existing links.
        directory=open_directory(cache/'pubring');os.close(directory)
        home=cache/'pubring'
        for current,dirs,files in os.walk(home,followlinks=False):
            for name in dirs+files:
                path=Path(current)/name;info=path.lstat()
                if path.is_symlink() or info.st_uid!=0 or info.st_mode & 0o022 or (not path.is_dir() and (not stat.S_ISREG(info.st_mode) or info.st_nlink!=1)):
                    raise TrustDenied('Unsafe existing metadata keyring')
        output=self.call([self.gpg,'--no-options','--batch','--homedir',str(home),'--with-colons','--list-keys'])
        allowed={fingerprint for fingerprint,_ in materials}
        if not set(fingerprints(output)) <= allowed:
            raise TrustDenied('Metadata keyring contains an unapproved key')
        for fingerprint,data in materials:
            with tempfile.TemporaryDirectory(dir=self.work,prefix='metadata-') as directory:
                key=Path(directory)/'key.asc';key.write_bytes(data)
                self.call([self.gpg,'--no-options','--batch','--homedir',str(home),'--import',str(key)])

    def plan(self,packages):
        if not isinstance(packages,list) or len(packages)>10000:raise TrustDenied('Invalid transaction plan')
        for package in packages:
            repo=package.get('repo')
            if repo not in self.policy['repositories']:raise TrustDenied('Unapproved package repository')
            if package.get('action','').lower()=='downgrade':raise TrustDenied('Unapproved downgrade')
            algorithm=package.get('algorithm','').lower()
            sizes={'sha256':64,'sha384':96,'sha512':128}
            digest=package.get('checksum','')
            if algorithm not in sizes or not isinstance(digest,str) or not re.fullmatch('[0-9a-fA-F]{'+str(sizes.get(algorithm,0))+'}',digest):
                raise TrustDenied('Missing strong repository package checksum')
            if type(package.get('size')) is not int or package['size']<=0:
                raise TrustDenied('Invalid repository package size')
            if not isinstance(package.get('nevra'),str) or not package['nevra']:
                raise TrustDenied('Missing package identity')
        return packages

    def verify_downloaded(self,packages):
        from .protected_storage import open_directory
        self.plan(packages)
        results=[]
        with tempfile.TemporaryDirectory(dir=self.work,prefix='rpmdb-') as directory:
            databases={}
            for package in packages:
                repo=package['repo']
                if repo not in databases:
                    database=Path(directory)/str(len(databases));database.mkdir(mode=0o700)
                    self.call([self.rpmdb,'--dbpath',str(database),'--initdb'])
                    for index,(_,data) in enumerate(self.key_material(repo)):
                        key=Path(directory)/(str(len(databases))+'-'+str(index)+'.asc');key.write_bytes(data)
                        # Only the isolated DB is modified; DNF never gets to import a URL key.
                        self.call([self.rpmkeys,'--dbpath',str(database),'--import',str(key)])
                    databases[repo]=database
                path=Path(package['path']);parent=open_directory(path.parent)
                try:
                    fd=os.open(path.name,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK,dir_fd=parent)
                finally:os.close(parent)
                try:
                    info=os.fstat(fd)
                    if not stat.S_ISREG(info.st_mode) or info.st_uid!=0 or info.st_mode & 0o022 or info.st_nlink!=1 or info.st_size!=package['size']:
                        raise TrustDenied('Unsafe or replaced downloaded package')
                    digest=hashlib.new(package['algorithm'].lower())
                    while chunk:=os.read(fd,1024*1024):digest.update(chunk)
                    if digest.hexdigest()!=package['checksum'].lower():raise TrustDenied('Downloaded package checksum mismatch')
                    os.lseek(fd,0,os.SEEK_SET)
                    target='/proc/self/fd/'+str(fd)
                    output=self.call([self.rpmkeys,'--dbpath',str(databases[repo]),'--checksig','--verbose',target],pass_fds=(fd,))
                    if not re.search(r'\bsignature\b[^\n]*:\s*OK\s*$',output,re.I|re.M):
                        raise TrustDenied('An actual approved RPM signature is required; digests alone are insufficient')
                    os.lseek(fd,0,os.SEEK_SET)
                    identity=self.call([self.rpm,'--dbpath',str(databases[repo]),'-qp','--qf',
                        '%{NAME}-%{EPOCHNUM}:%{VERSION}-%{RELEASE}.%{ARCH}',target],pass_fds=(fd,)).strip()
                    if identity!=package['nevra']:raise TrustDenied('RPM header does not match resolved package identity')
                    after=os.fstat(fd)
                    if (info.st_size,info.st_mtime_ns,info.st_ctime_ns)!=(after.st_size,after.st_mtime_ns,after.st_ctime_ns):
                        raise TrustDenied('Package changed during verification')
                    results.append({'nevra':identity,'repository':repo,'sha256_or_stronger':digest.hexdigest(),'signature':'approved'})
                finally:os.close(fd)
        return results


def approve_key(repo,source,key_file,fingerprint,policy_path=POLICY,keys=KEYS,work=ROOT,runner=subprocess.run):
    """Explicit root enrollment with an out-of-band FULL fingerprint.

    Does not infer trust from a file owner, installed RPM keys or a key URL.
    """
    if os.geteuid()!=0:raise TrustDenied('Root required for trust enrollment')
    if not re.fullmatch(r'(?:[0-9A-F]{40}|[0-9A-F]{64})',fingerprint):
        raise TrustDenied('Full uppercase fingerprint required')
    from .protected_storage import open_directory
    for directory in (Path(keys),Path(work),Path(policy_path).parent):
        fd=open_directory(directory);os.close(fd)
    fd=os.open(key_file,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK)
    try:
        info=os.fstat(fd)
        if not stat.S_ISREG(info.st_mode) or info.st_size>4*1024*1024:raise TrustDenied('Invalid public key input')
        data=os.read(fd,4*1024*1024+1)
        if len(data)>4*1024*1024:raise TrustDenied('Oversized public key')
    finally:os.close(fd)
    if Path(policy_path).exists():policy=load_policy(policy_path)
    else:policy={'schema':1,'repositories':{}}
    previous=policy['repositories'].get(repo,{'sources':[],'keys':[]})
    policy['repositories'][repo]={'sources':sorted(set(previous['sources']+source)),
                                  'keys':sorted(set(previous['keys']+[fingerprint]))}
    validate_policy(policy)
    with tempfile.TemporaryDirectory(dir=work,prefix='enroll-') as directory:
        staged=Path(directory)/'public.asc';staged.write_bytes(data)
        result=runner(['/usr/bin/gpg','--no-options','--batch','--homedir',directory,'--with-colons',
                       '--import-options','show-only','--import',str(staged)],capture_output=True,text=True,
                       timeout=30,env=SAFE_ENV)
        if result.returncode or fingerprints(result.stdout)!=[fingerprint]:
            raise TrustDenied('Public key does not match the explicitly approved fingerprint')
        # The native DNF check is still required. Only Satsuma's explicit enrollment
        # can install this approved key in the system RPM DB, never a repo callback.
        imported=runner(['/usr/bin/rpmkeys','--import',str(staged)],capture_output=True,text=True,timeout=30,env=SAFE_ENV)
        if imported.returncode:raise TrustDenied('Approved key enrollment into RPM failed')
    def atomic(path,content):
        fd,temporary=tempfile.mkstemp(prefix='.trust-',dir=path.parent)
        try:
            with os.fdopen(fd,'wb') as stream:stream.write(content);stream.flush();os.fsync(stream.fileno())
            os.chmod(temporary,0o644);os.replace(temporary,path)
        finally:
            if os.path.exists(temporary):os.unlink(temporary)
    atomic(Path(keys)/(fingerprint+'.asc'),data)
    atomic(Path(policy_path),json.dumps(policy,sort_keys=True,indent=2).encode()+b'\n')
    from installer.integrity import KEY,read_key,sign
    sign(Path(policy_path),read_key(KEY))
    return {'repository':repo,'fingerprint':fingerprint,'status':'explicitly_enrolled'}
