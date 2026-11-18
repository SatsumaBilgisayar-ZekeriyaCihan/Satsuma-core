"""Long maintenance tasks return immediately; no shell or arbitrary command API."""
import json
import os
import shutil
import stat
import subprocess
import sys
import tempfile
import time
import uuid
from pathlib import Path


class MaintenanceJobs:
    def __init__(self, store, popen=subprocess.Popen):
        self.store,self.popen=store,popen
        self.process=None
        self.log=None
        self.operation=None
        self.finished=False
        self.result=None
        self.command_id=None

    def status(self):
        if not self.process:return self.result or {'status':'IDLE'}
        code=self.process.poll()
        if code is None:return {'status':'RUNNING','operation':self.operation,'command_id':self.command_id}
        if not self.finished:
            self.log.seek(0,2);size=self.log.tell();self.log.seek(max(0,size-10000))
            output=self.log.read().decode(errors='replace');self.log.close()
            state='COMPLETED' if code==0 else 'FAILED'
            self.result={'status':state,'operation':self.operation,'command_id':self.command_id,
                         'returncode':code,'output':output}
            self.finished=True
            self.store.add('actions',{'action':self.operation,'command_id':self.command_id,
                                     'status':state,'timestamp':time.time(),'returncode':code})
        return self.result

    def start(self, operation):
        if self.status().get('status')=='RUNNING':
            raise RuntimeError('Bir bakım işi zaten çalışıyor; durumunu izleyin')
        if operation=='boot_check':
            # Same serialized pipeline as the periodic check: verdict, report and DB.
            command=['/usr/bin/systemctl','start','--wait','satsuma-integrity-check.service']
        elif operation=='repair':
            # 2.2.45: the panel's "Onar" button runs the maintenance kit (satsuma.maintenance),
            # the same bounded repairs as the six-hourly timer. Panelin "Onar" düğmesi bakım kitini çalıştırır.
            command=['/usr/bin/systemctl','start','--wait','satsuma-maintenance.service']
        elif operation=='security_scan':
            command=['/usr/bin/systemctl','start','--wait','satsuma-core-security-scan-now.service']
        elif operation in ('systemd_security', 'device_inventory'):
            command=[sys.executable,'-X','pycache_prefix=/run/satsuma-python-cache','-B','-m','satsuma.host_diagnostics', '--kind', 'systemd' if operation=='systemd_security' else 'devices']
        else:raise ValueError('Unknown maintenance operation')
        self.log=tempfile.TemporaryFile()
        try:
            self.process=self.popen(command,stdin=subprocess.DEVNULL,stdout=self.log,stderr=subprocess.STDOUT,
                                    env={**os.environ,'DEBIAN_FRONTEND':'noninteractive','PYTHONDONTWRITEBYTECODE':'1'})
        except Exception:
            self.log.close();raise
        self.operation,self.finished,self.result=operation,False,None
        self.command_id=uuid.uuid4().hex
        return {'ok':True,'accepted':True,'status':'RUNNING','operation':operation,
                'command_id':self.command_id}
