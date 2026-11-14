"""Bounded DNS wire checks on local and configured system resolver paths.

Yerel ve yapılandırılmış sistem DNS yollarında sınırlı gerçek sorgu denetimi.
A cached answer proves the checked path, never fresh upstream connectivity.
Önbellek yanıtı yalnız denetlenen yolu kanıtlar; yeni üst sunucu erişimini değil.
"""
import ipaddress
from pathlib import Path
import secrets
import socket
import struct
import time

NAME = 'example.com'


class DaemonAnswered(RuntimeError):
    """The resolver replied, but the reply is an error or has no usable address.

    Çözümleyici yanıt verdi, ama yanıt bir hata ya da kullanılabilir adres içermiyor.
    """

QUESTION = b'\x07example\x03com\0' + struct.pack('!HH', 1, 1)


def _name(packet, offset):
    labels=[];seen=set();end=None
    for _ in range(128):
        if offset >= len(packet) or offset in seen:raise RuntimeError('Invalid DNS name')
        seen.add(offset);length=packet[offset];offset+=1
        if length & 0xc0 == 0xc0:
            if offset >= len(packet):raise RuntimeError('Incomplete DNS pointer')
            if end is None:end=offset+1
            offset=((length & 0x3f)<<8)|packet[offset]
        elif length & 0xc0:raise RuntimeError('Invalid DNS label')
        elif length==0:return b'.'.join(labels).lower(), end or offset
        else:
            if offset+length>len(packet):raise RuntimeError('Incomplete DNS label')
            labels.append(packet[offset:offset+length]);offset+=length
    raise RuntimeError('DNS name exceeds limit')


def validate_reply(packet, ident):
    if len(packet)<12:raise RuntimeError('Incomplete DNS reply')
    reply_id,flags,questions,answers,_,_=struct.unpack('!6H',packet[:12])
    if reply_id!=ident or questions!=1:
        raise RuntimeError('DNS reply ID, flags or response code invalid')
    if flags & 0xfa0f != 0x8000:
        raise DaemonAnswered('DNS reply ID, flags or response code invalid')
    name,offset=_name(packet,12)
    if name!=NAME.encode() or packet[offset:offset+4]!=struct.pack('!HH',1,1):
        raise RuntimeError('DNS reply question mismatch')
    offset+=4;addresses=[];aliases={name}
    for _ in range(min(answers,256)):
        owner,offset=_name(packet,offset)
        if offset+10>len(packet):raise RuntimeError('Incomplete DNS record')
        kind,cls,ttl,size=struct.unpack('!HHIH',packet[offset:offset+10]);offset+=10
        if offset+size>len(packet):raise RuntimeError('Incomplete DNS data')
        if owner in aliases and kind==5 and cls==1:
            alias,end=_name(packet,offset)
            if end!=offset+size:raise RuntimeError('Invalid DNS alias')
            aliases.add(alias)
        elif owner in aliases and kind==1 and cls==1 and size==4:
            address=ipaddress.ip_address(packet[offset:offset+size])
            if address.is_global:addresses.append(str(address))
        offset+=size
    if not addresses:raise DaemonAnswered('DNS A lookup has no usable answer; blocked or unavailable')
    return addresses


def query(host, port, *, transport='udp', timeout=2):
    ident=secrets.randbelow(65536)
    packet=struct.pack('!6H',ident,0x100,1,0,0,0)+QUESTION
    address=ipaddress.ip_address(host)
    family=socket.AF_INET6 if address.version==6 else socket.AF_INET
    deadline=time.monotonic()+timeout
    with socket.socket(family,socket.SOCK_STREAM if transport=='tcp' else socket.SOCK_DGRAM) as connection:
        connection.settimeout(max(.001,deadline-time.monotonic()));connection.connect((str(address),port))
        def receive(size):
            chunks=b''
            while len(chunks)<size:
                connection.settimeout(max(.001,deadline-time.monotonic()))
                data=connection.recv(size-len(chunks))
                if not data:raise RuntimeError('Incomplete DNS TCP frame')
                chunks+=data
            return chunks
        connection.settimeout(max(.001,deadline-time.monotonic()))
        connection.sendall(struct.pack('!H',len(packet))+packet if transport=='tcp' else packet)
        if transport=='tcp':reply=receive(struct.unpack('!H',receive(2))[0])
        else:reply=connection.recv(65535)
    return validate_reply(reply,ident)


def system_resolvers(path=Path('/etc/resolv.conf')):
    result=[]
    for line in path.read_text()[:65536].splitlines():
        fields=line.split('#',1)[0].split(';',1)[0].split()
        if len(fields)!=2 or fields[0]!='nameserver':continue
        try:address=ipaddress.ip_address(fields[1])
        except ValueError:continue
        if not address.is_unspecified and not address.is_multicast and str(address) not in result:
            result.append(str(address))
    if not result:raise RuntimeError('No configured system DNS resolver')
    return result[:3]


def probe_system(timeout=6, resolv_path=Path('/etc/resolv.conf')):
    """Exercise port 53 including NAT/queues; never connect directly to 53053."""
    deadline=time.monotonic()+timeout;errors=[]
    for resolver in system_resolvers(resolv_path):
        try:
            for transport in ('udp','tcp'):
                remaining=deadline-time.monotonic()
                if remaining<=0:raise TimeoutError('System DNS deadline exceeded')
                query(resolver,53,transport=transport,timeout=min(2,remaining))
            return {'system_ready':True,'resolver':resolver,'transports':['udp','tcp'],
                    'query':NAME+' A','system_checked_at':time.time(),
                    'scope':'configured resolver port 53, including active NAT and security queues; not NSS or fresh upstream proof'}
        except (OSError,RuntimeError) as exc:errors.append(resolver+': '+str(exc))
    raise RuntimeError('System DNS readiness failed: '+'; '.join(errors))
