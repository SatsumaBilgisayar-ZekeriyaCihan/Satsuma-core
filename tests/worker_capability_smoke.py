"""Probe required service capabilities against one disposable cross-UID child.

Runs only inside the isolated CI container. No ptrace or process memory is read.
"""
import os
from pathlib import Path
import signal
import subprocess
import sys

child=subprocess.Popen(['/usr/bin/sleep','30'],user=65534,group=65534,extra_groups=[])
try:
    # Wait for exec to replace the pre-exec parent image.
    import time
    deadline=time.monotonic()+3
    while time.monotonic()<deadline:
        if os.readlink('/proc/'+str(child.pid)+'/exe').endswith('/sleep'):break
        time.sleep(.01)
    caps='dac_read_search,sys_ptrace,kill,net_admin'
    args=['/usr/bin/setpriv','--bounding-set=-all,'+','.join('+'+x for x in caps.split(',')),
          '--no-new-privs',sys.executable,'-c',
          'import sys,os,signal;from satsuma.worker_memory import inspect_process;from satsuma.process_identity import capture_process_identity;pid=int(sys.argv[1]);inspect_process("/proc/"+str(pid));identity=capture_process_identity(pid);assert identity and identity["uid"]==65534;os.kill(pid,signal.SIGTERM)',
          str(child.pid)]
    result=subprocess.run(args,capture_output=True,text=True,timeout=10,
                          env={**os.environ,'PYTHONPATH':str(Path(__file__).parents[1])})
    assert result.returncode==0,result.stderr
    assert child.wait(timeout=5)==-signal.SIGTERM
    print('CROSS_UID_METADATA_AND_AUTHORIZED_SIGNAL_CAPABILITIES_PASS; NO_PTRACE_OR_MEMORY_DUMP')
finally:
    if child.poll() is None:child.kill();child.wait(timeout=5)
