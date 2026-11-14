"""Bind protection exceptions to root-controlled paths and system cgroups.

Koruma istisnalarını root denetimli dosya yollarına ve sistem cgroup'larına bağla.
"""
from pathlib import Path
import stat

SATSUMA_LAUNCHERS={'satsuma-core','satsuma-run','satsuma-admin','satsuma-reader',
                  'satsuma-dashboard','satsuma-research','satsuma-deepseek-test'}


def system_service(value):
    """Return only a direct system.slice unit, never a similarly named user unit.

    Yalnız doğrudan system.slice birimini döndür; aynı adlı kullanıcı birimini değil.
    """
    for line in str(value or '').splitlines():
        path=line.split(':',2)[-1] if ':' in line else line
        parts=path.strip().split('/')
        if len(parts)>=3 and parts[:2]==['','system.slice']:
            unit=parts[2]
            if unit.endswith('.service') and '..' not in parts:
                return unit
    return ''


def trusted_path(value):
    """Root-only regular executable path with no writable parent directory.

    Üst dizinleri de yazmaya kapalı, root sahipli normal çalıştırılabilir dosya yolu.
    """
    try:
        path=Path(str(value).removesuffix(' (deleted)'))
        if not path.is_absolute():return False
        path=path.resolve(strict=True)
        for entry in (path,*path.parents):
            info=entry.stat()
            if info.st_uid!=0 or info.st_mode&0o022:return False
        return stat.S_ISREG(path.stat().st_mode)
    except (OSError,ValueError,RuntimeError):
        return False


def satsuma_entry(executable,cmdline):
    """Recognize a trusted entrypoint, not arbitrary words in its arguments.

    Argümanlardaki sözcükleri değil güvenilir giriş noktasını tanı.
    """
    if not trusted_path(executable):return False
    name=Path(executable).name
    if name in SATSUMA_LAUNCHERS:return True
    if not name.startswith('python'):return False
    # Real callers pass NUL-separated /proc arguments as a list. A joined
    # string cannot distinguish whitespace inside one argument.
    if not isinstance(cmdline,(list,tuple)):return False
    args=list(cmdline)
    index=1
    while index<len(args):
        token=args[index]
        if token in ('-c','-m') or token.startswith(('-c','-m')):return False
        if token in ('-X','-W'):
            index+=2;continue
        if token.startswith('-'):
            index+=1;continue
        path=Path(token)
        return path.is_absolute() and str(path).startswith('/opt/satsuma-core/') and trusted_path(path)
    return False
