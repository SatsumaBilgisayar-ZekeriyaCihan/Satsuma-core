"""Small libnetfilter_queue adapter. Does not unbind another firewall's queues.

A packet the callback cannot decide gets no ACCEPT and is counted; an
errno-less handler failure no longer ends the process unless it repeats
UNEXPLAINED_LIMIT times in a row. Failures with a real errno stay fatal.

Küçük libnetfilter_queue bağdaştırıcısı. Başka bir güvenlik duvarının
kuyruklarını ayırmaz.

Geri çağrının karar veremediği pakete ACCEPT verilmez ve sayılır; errno'suz
bir işleyici hatası, art arda UNEXPLAINED_LIMIT kez tekrarlanmadıkça artık
süreci bitirmez. Gerçek errno taşıyan hatalar ölümcül kalır.
"""
import ctypes as C
import ctypes.util
import errno
import os
import select
import socket
import time

# Consecutive errno-less handler failures tolerated before the queue is
# treated as broken; arbitrary but far above a single bad packet.
UNEXPLAINED_LIMIT=256
CALLBACK=C.CFUNCTYPE(C.c_int,C.c_void_p,C.c_void_p,C.c_void_p,C.c_void_p)


class QueueFailure(RuntimeError):
    def __init__(self,phase,number,result,code):
        self.phase,self.queue_number,self.result,self.errno=phase,number,result,code
        detail=os.strerror(code) if code else 'library supplied no errno'
        super().__init__(f'NFQUEUE {phase} failure: queue={number}, result={result}, errno={code} ({detail})')


class Queue:
    def __init__(self,number,decide,prepare=None,finish=None):
        name=ctypes.util.find_library('netfilter_queue')
        if not name:raise RuntimeError('libnetfilter_queue is missing')
        self.lib=C.CDLL(name,use_errno=True);self.handle=None;self.queue=None
        declarations={
            'nfq_open':([],C.c_void_p),'nfq_close':([C.c_void_p],C.c_int),
            'nfq_create_queue':([C.c_void_p,C.c_uint16,CALLBACK,C.c_void_p],C.c_void_p),
            'nfq_destroy_queue':([C.c_void_p],C.c_int),
            'nfq_set_mode':([C.c_void_p,C.c_uint8,C.c_uint32],C.c_int),
            'nfq_set_queue_maxlen':([C.c_void_p,C.c_uint32],C.c_int),
            'nfq_fd':([C.c_void_p],C.c_int),
            'nfq_handle_packet':([C.c_void_p,C.c_char_p,C.c_int],C.c_int),
            'nfq_get_msg_packet_hdr':([C.c_void_p],C.c_void_p),
            'nfq_get_payload':([C.c_void_p,C.POINTER(C.c_void_p)],C.c_int),
            'nfq_set_verdict':([C.c_void_p,C.c_uint32,C.c_uint32,C.c_uint32,C.c_void_p],C.c_int)}
        for symbol,(args,result) in declarations.items():
            fn=getattr(self.lib,symbol);fn.argtypes=args;fn.restype=result
        self.number=number;self.decide=decide;self.callback=CALLBACK(self._packet)
        self.prepare,self.finish=prepare,finish
        self.receive_overruns=0
        self.observability={}

    def _unexplained_failures(self):
        self._count('unexplained_handler_failures')
        streak=self.observability.get('consecutive_unexplained_failures',0)+1
        self.observability['consecutive_unexplained_failures']=streak
        return streak

    def _count(self,name):
        if not hasattr(self,'observability'):self.observability={}
        self.observability[name]=self.observability.get(name,0)+1

    def _packet(self,qh,msg,data,unused):
        header=self.lib.nfq_get_msg_packet_hdr(data)
        if not header:
            self._count('missing_headers');return -1
        packet_id=int.from_bytes(C.string_at(header,4),'big')
        verdict=0
        try:
            pointer=C.c_void_p();size=self.lib.nfq_get_payload(data,C.byref(pointer))
            if size>0 and size<=65535:verdict=1 if self.decide(C.string_at(pointer,size)) else 0
            else:self._count('invalid_payloads')
        except Exception:
            self._count('callback_errors');verdict=0
        self._count('packets_seen')
        for attempt in range(3):
            C.set_errno(0)
            result=self.lib.nfq_set_verdict(qh,packet_id,verdict,0,None)
            code=C.get_errno()
            if result>=0 or code not in (errno.EINTR,errno.EAGAIN,errno.ENOBUFS):break
            if attempt<2:
                self._count('verdict_retries')
                # Resend the SAME ID and decision only. Bound waiting so a
                # permanently broken netlink socket cannot pin this callback.
                if code!=errno.EINTR and hasattr(self,'fd'):
                    select.select([],[self.fd],[],0.005)
        if result<0:
            self._count('verdict_failures')
            self.observability['last_verdict_errno']=code
            # A packet already removed from the kernel queue cannot be given
            # a verdict. Do not kill the consumer for that stale ID. Do not
            # submit a replacement ACCEPT or report a successful verdict.
            if code in (errno.ENOENT,errno.ESRCH):
                self._count('stale_verdicts');return 0
        return result

    def __enter__(self):
        try:
            self.handle=self.lib.nfq_open()
            if not self.handle:raise RuntimeError('Cannot open NFQUEUE')
            self.queue=self.lib.nfq_create_queue(self.handle,self.number,self.callback,None)
            if not self.queue:raise RuntimeError('Cannot bind Satsuma queue')
            if self.lib.nfq_set_mode(self.queue,2,65535)<0 or self.lib.nfq_set_queue_maxlen(self.queue,1024)<0:
                raise RuntimeError('Cannot configure Satsuma queue')
            self.fd=self.lib.nfq_fd(self.handle)
            return self
        except Exception:
            self.__exit__(None,None,None);raise

    def poll(self,timeout):
        if select.select([self.fd],[],[],timeout)[0]:
            # Drain only packets already waiting; never delay a packet to fill
            # a batch. The socket-owner snapshot is acquired AFTER this drain
            # and discarded before the next one (no timed verdict cache).
            batch=[]
            for _ in range(32):
                try:
                    raw=os.read(self.fd,131072)
                except OSError as exc:
                    if exc.errno in (errno.EINTR,errno.EAGAIN):
                        self._count('read_retries');break
                    if exc.errno!=errno.ENOBUFS:raise
                    # Netlink reports lost messages once, then permits reads
                    # again. Keep the queue bound and deny-by-default rules in
                    # place; process any messages already drained this round.
                    self.receive_overruns+=1
                    break
                if not raw:raise QueueFailure('read-eof',getattr(self,'number',-1),0,0)
                batch.append(raw)
                if not select.select([self.fd],[],[],0)[0]:break
            if not batch:return
            started=time.monotonic()
            if not hasattr(self,'observability'):self.observability={}
            try:
                if self.prepare:self.prepare()
                for raw in batch:
                    C.set_errno(0)
                    result=self.lib.nfq_handle_packet(self.handle,raw,len(raw))
                    if result<0:
                        code=C.get_errno()
                        self._count('handler_failures')
                        self.observability['last_handler_errno']=code
                        # errno 0: our own callback refused one packet (no
                        # header or a verdict the kernel did not take). That
                        # packet gets no ACCEPT; keep serving the others.
                        # Field log: one such packet restarted app-control.
                        if code==0 and self._unexplained_failures()<=UNEXPLAINED_LIMIT:
                            continue
                        raise QueueFailure('handle-packet',getattr(self,'number',-1),result,code)
                    self.observability['consecutive_unexplained_failures']=0
            finally:
                if self.finish:self.finish()
                if not hasattr(self,'observability'):self.observability={}
                elapsed=time.monotonic()-started
                self.observability['batch_processing_seconds_total']=self.observability.get('batch_processing_seconds_total',0)+elapsed
                self.observability['batch_processing_seconds_max']=max(self.observability.get('batch_processing_seconds_max',0),elapsed)
                self._count('batches_processed')

    def metrics(self):
        base={'receive_overruns':self.receive_overruns,**getattr(self,'observability',{})}
        try:
            with open('/proc/net/netfilter/nfnetlink_queue') as stream:
                for line in stream:
                    fields=line.split()
                    if len(fields)>=8 and int(fields[0])==self.number:
                        return {'queued':int(fields[2]),'kernel_drops':int(fields[5]),
                                'userspace_drops':int(fields[6]),
                                **base}
        except (OSError,ValueError):pass
        return {'status':'UNAVAILABLE',**base}

    def __exit__(self,*args):
        if self.queue:self.lib.nfq_destroy_queue(self.queue);self.queue=None
        if self.handle:self.lib.nfq_close(self.handle);self.handle=None

