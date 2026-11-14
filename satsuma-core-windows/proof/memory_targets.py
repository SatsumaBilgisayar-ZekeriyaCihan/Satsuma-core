"""Harmless test programs for the memory proof on GitHub's Windows server; never shipped in the exe.

Each mode prepares one memory state the service must find, writes its process
id and waits. rwx_thread starts one thread in RWX memory that only runs
"pause; jump back" (it waits and does nothing else); nothing else is executed
from the prepared memory: rwx_private and
rwx_shared only allocate writable and executable memory (filled with zeros),
temp_dll loads a copy of Windows' own version.dll from the Temp folder with
its signature entry removed (unsigned, so it is stopped), signed_temp loads a
copy of the signed vcruntime140.dll from Temp and must survive (owner's
decision 2026-11-11), plain does nothing and must survive. ram_signature
holds a harmless marker (text, never executed) in memory placed as low in its
address space as Windows allows, so the ClamAV memory scan (RAM v2) reaches
it in its first turn; the marker matches only a test signature the proof
step writes on the build server, never shipped.

GitHub'ın Windows sunucusundaki bellek kanıtı için zararsız deneme
programları; exe'ye konmaz. Her kip hizmetin bulması gereken bir bellek
durumu hazırlar, süreç numarasını yazar ve bekler. rwx_thread, RWX bellekte
yalnızca "bekle; geri dön" çalıştıran bir iş parçacığı başlatır (bekler,
başka hiçbir şey yapmaz); hazırlanan bellekten başka hiçbir şey
çalıştırılmaz: rwx_private ve rwx_shared yalnızca sıfırla dolu
yazılabilir+çalıştırılabilir bellek ayırır, temp_dll Windows'un kendi
version.dll dosyasının imza kaydı silinmiş Temp kopyasını yükler (imzasız,
durdurulur), signed_temp imzalı vcruntime140.dll'in Temp'teki
kopyasını yükler ve hayatta kalmalıdır (sahibinin kararı 2026-11-11), plain
hiçbir şey yapmaz ve hayatta kalmalıdır. ram_signature zararsız bir işareti
(metin, asla çalıştırılmaz) adres alanında Windows'un izin verdiği en alt
konumda tutar; ClamAV bellek taraması (RAM v2) onu ilk turunda bulur. İşaret
yalnızca kanıt adımının derleme sunucusuna yazdığı deneme imzasına uyar;
ürünle gönderilmez.
"""
import ctypes
import os
import shutil
import sys
import tempfile
import time
from ctypes import wintypes

kernel32 = ctypes.WinDLL('kernel32', use_last_error=True)
kernel32.VirtualAlloc.restype = ctypes.c_void_p
kernel32.VirtualAlloc.argtypes = (ctypes.c_void_p, ctypes.c_size_t, wintypes.DWORD, wintypes.DWORD)
kernel32.CreateFileMappingW.restype = wintypes.HANDLE
kernel32.CreateFileMappingW.argtypes = (wintypes.HANDLE, ctypes.c_void_p, wintypes.DWORD, wintypes.DWORD,
                                        wintypes.DWORD, wintypes.LPCWSTR)
kernel32.MapViewOfFile.restype = ctypes.c_void_p
kernel32.MapViewOfFile.argtypes = (wintypes.HANDLE, wintypes.DWORD, wintypes.DWORD, wintypes.DWORD, ctypes.c_size_t)


def strip_signature(path):
    """Remove the embedded signature entry so the copy is truly unsigned; the code is unchanged.

    Gömülü imza kaydını siler, kopya gerçekten imzasız olur; kod değişmez.
    """
    import struct
    with open(path, 'r+b') as stream:
        data = bytearray(stream.read())
        header = struct.unpack_from('<I', data, 0x3C)[0]
        optional = header + 24
        magic = struct.unpack_from('<H', data, optional)[0]
        directories = optional + (112 if magic == 0x20B else 96)
        struct.pack_into('<II', data, directories + 4 * 8, 0, 0)        # IMAGE_DIRECTORY_ENTRY_SECURITY
        stream.seek(0)
        stream.write(data)


def prepare(mode):
    if mode == 'rwx_private':
        address = kernel32.VirtualAlloc(None, 65536, 0x3000, 0x40)   # MEM_COMMIT|MEM_RESERVE, PAGE_EXECUTE_READWRITE
        if not address:
            raise OSError(ctypes.get_last_error(), 'VirtualAlloc')
    elif mode == 'rwx_thread':
        # A thread started in RWX memory running "pause; jump back": harmless, it only waits.
        # RWX bellekte başlatılan, yalnızca "bekle; geri dön" çalıştıran zararsız iş parçacığı.
        address = kernel32.VirtualAlloc(None, 65536, 0x3000, 0x40)
        if not address:
            raise OSError(ctypes.get_last_error(), 'VirtualAlloc')
        ctypes.memmove(address, b'\xf3\x90\xeb\xfc', 4)
        kernel32.CreateThread.restype = wintypes.HANDLE
        kernel32.CreateThread.argtypes = (ctypes.c_void_p, ctypes.c_size_t, ctypes.c_void_p, ctypes.c_void_p,
                                          wintypes.DWORD, ctypes.c_void_p)
        if not kernel32.CreateThread(None, 0, address, None, 0, None):
            raise OSError(ctypes.get_last_error(), 'CreateThread')
    elif mode == 'rwx_shared':
        section = kernel32.CreateFileMappingW(wintypes.HANDLE(-1), None, 0x40, 0, 65536, None)
        if not section:
            raise OSError(ctypes.get_last_error(), 'CreateFileMappingW')
        if not kernel32.MapViewOfFile(section, 0x0002 | 0x0020, 0, 0, 65536):   # FILE_MAP_WRITE|FILE_MAP_EXECUTE
            raise OSError(ctypes.get_last_error(), 'MapViewOfFile')
    elif mode == 'temp_dll':
        folder = tempfile.mkdtemp(prefix='satsuma-proof-')
        copy = os.path.join(folder, 'proofver.dll')
        shutil.copyfile(os.path.join(os.environ['SystemRoot'], 'System32', 'version.dll'), copy)
        strip_signature(copy)
        ctypes.WinDLL(copy)
    elif mode == 'signed_temp':
        folder = tempfile.mkdtemp(prefix='satsuma-proof-')
        copy = os.path.join(folder, 'proofsigned.dll')
        shutil.copyfile(os.path.join(sys.base_prefix, 'vcruntime140.dll'), copy)
        ctypes.WinDLL(copy)
    elif mode == 'ram_signature':
        # Built reversed at run time: this file and other programs never hold the marker itself.
        # Çalışırken ters çevrilerek kurulur: bu dosya ve başka programlar işaretin kendisini tutmaz.
        marker = bytes(reversed(b'6804d2b5e1a9c3f7-FOORP-2V-MAR-AMUSTAS'))
        for slot in range(1, 4096):
            address = kernel32.VirtualAlloc(ctypes.c_void_p(slot * 0x10000), 65536, 0x3000, 0x04)  # PAGE_READWRITE
            if address:
                break
        else:
            raise OSError(ctypes.get_last_error(), 'VirtualAlloc low')
        ctypes.memmove(address, marker, len(marker))
        print('marker at 0x%x' % address, flush=True)
    elif mode != 'plain':
        raise SystemExit('unknown mode ' + mode)


if __name__ == '__main__':
    mode, pid_file = sys.argv[1], sys.argv[2]
    prepare(mode)
    with open(pid_file, 'w', encoding='ascii') as stream:
        stream.write(str(os.getpid()))
    time.sleep(600)
