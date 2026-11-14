"""Shared decision for the compile tool block, the same for Linux and Windows (owner's decision 2026-11-11).

The owner does not compile on these machines; a compiler, assembler, linker or
packer that starts is stopped and a finding is recorded. While the package
manager runs (Linux: dnf, rpm, PackageKit; Windows: Windows Installer and
Windows Update) the tool may run, because package installation uses them; the
finding is still recorded. Linux stops the tool before it runs (fanotify,
satsuma.exec_guard); Windows stops it as soon as Sysmon reports it.

Tools (owner's list): as, ld, ld.bfd, ld.gold, gold, gcc, cc, c++, clang,
make, cmake, meson, ninja, rustc, cargo, go, nasm, yasm, tcc, pyinstaller,
nuitka; on Windows also csc and vbc. Versioned and target-prefixed names of
the same tools are included (gcc-14, x86_64-redhat-linux-gcc, clang-18), and
the C++ drivers of the same compilers (g++, clang++).

Derleme aracı engeli için ortak karar; Linux ve Windows'ta aynı (sahibinin
kararı 2026-11-11). Sahibi bu makinelerde derleme yapmaz; başlayan
derleyici, çevirici, bağlayıcı ya da paketleyici durdurulur ve bulgu
kaydedilir. Paket yöneticisi çalışırken (Linux: dnf, rpm, PackageKit;
Windows: Windows Installer ve Windows Update) paket kurulumu bunları
kullandığı için araç çalışabilir; bulgu yine kaydedilir. Linux aracı
çalışmadan önce durdurur (fanotify); Windows Sysmon bildirir bildirmez
durdurur. Aynı araçların sürümlü ve hedef önekli adları ile aynı
derleyicilerin C++ sürücüleri (g++, clang++) dahildir.
"""
import re

RULE_ID = 'SATSUMA-BUILD-001'
TOOLS = ('as', 'ld', 'ld.bfd', 'ld.gold', 'gold', 'gcc', 'cc', 'c++', 'g++', 'clang', 'clang++', 'make',
         'cmake', 'meson', 'ninja', 'rustc', 'cargo', 'go', 'nasm', 'yasm', 'tcc', 'pyinstaller', 'nuitka',
         'nuitka3')
WINDOWS_TOOLS = ('csc', 'vbc')
_TRIPLE = r'(?:[a-z0-9_]+-){2,4}'            # x86_64-redhat-linux-, aarch64-linux-gnu-
_VERSION = r'(?:-?\d+(?:\.\d+)*)?'          # gcc-14, clang-18, python3.12-style suffixes


def _pattern(names):
    alternatives = '|'.join(re.escape(name) for name in sorted(names, key=len, reverse=True))
    return re.compile(r'^(?:%s)?(%s)%s$' % (_TRIPLE, alternatives, _VERSION))


LINUX_PATTERN = _pattern(TOOLS)
WINDOWS_PATTERN = _pattern(TOOLS + WINDOWS_TOOLS)


def tool_name(path, windows=False):
    """The build tool a program path names, or None."""
    name = re.split(r'[\\/]', str(path or ''))[-1]
    if windows:
        name = name.lower()
        if name.endswith('.exe'):
            name = name[:-4]
    else:
        name = name.removesuffix(' (deleted)')
    match = (WINDOWS_PATTERN if windows else LINUX_PATTERN).match(name)
    return match.group(1) if match else None


def decide(path, package_manager_running, windows=False):
    """None when the program is not a build tool; otherwise the rule and whether it is stopped."""
    tool = tool_name(path, windows)
    if tool is None:
        return None
    result = {'rule_id': RULE_ID, 'tool': tool, 'path': str(path), 'stop': not package_manager_running}
    if package_manager_running:
        result['kept'] = 'package_manager_running'
    return result
