import hashlib
import json
import os
import time
from pathlib import Path
from .source_guard import open_eve,validate_stat

class Reader:
    MAX_LINE=4*1024*1024
    def __init__(self,path,store,pipeline,writer_uid=0,opener=open_eve):
        self.path=Path(path);self.store=store;self.pipeline=pipeline
        self.writer_uid=writer_uid;self.opener=opener
        self.file=opener(self.path,writer_uid);self.skipping=False
        st=os.fstat(self.file.fileno());checkpoint=store.get('checkpoint')
        if checkpoint and checkpoint['device']==st.st_dev and checkpoint['inode']==st.st_ino and checkpoint['offset']<=st.st_size:
            self.file.seek(max(0,checkpoint['offset']-128));anchor=self.file.read(min(128,checkpoint['offset']))
            if hashlib.sha256(anchor).hexdigest()==checkpoint.get('anchor'):
                self.file.seek(checkpoint['offset'])
            else:self.file.seek(0);self.store.add('errors',{'component':'reader','error':'checkpoint anchor changed; current file reread'})
        elif checkpoint:self.file.seek(0)
        else:
            self.file.seek(0)
        self.checkpoint()

    def checkpoint(self):
        offset=self.file.tell();st=os.fstat(self.file.fileno())
        self.file.seek(max(0,offset-128));anchor=self.file.read(min(128,offset));self.file.seek(offset)
        self.store.set('checkpoint',{'device':st.st_dev,'inode':st.st_ino,'offset':offset,'anchor':hashlib.sha256(anchor).hexdigest()})

    def poll(self):
        f=self.file
        if self.opener is open_eve:validate_stat(os.fstat(f.fileno()),self.writer_uid)
        if os.fstat(f.fileno()).st_size<f.tell():f.seek(0);self.skipping=False
        processed=0
        for _ in range(1000):
            start=f.tell();line=f.readline(self.MAX_LINE+1)
            if not line:
                try:new=self.path.stat()
                except FileNotFoundError:return processed
                old=os.fstat(f.fileno())
                if (new.st_dev,new.st_ino)!=(old.st_dev,old.st_ino):
                    replacement=self.opener(self.path,self.writer_uid);f.close();self.file=replacement;self.skipping=False;self.checkpoint()
                return processed
            if self.skipping:
                self.skipping=not line.endswith(b'\n');self.checkpoint();continue
            if len(line)>self.MAX_LINE:
                self.store.add('errors',{'component':'reader','error':'oversized EVE line rejected'})
                self.skipping=not line.endswith(b'\n');self.checkpoint();continue
            if not line.endswith(b'\n'):
                f.seek(start)
                try:new=self.path.stat()
                except FileNotFoundError:return processed
                old=os.fstat(f.fileno())
                if (new.st_dev,new.st_ino)!=(old.st_dev,old.st_ino):
                    self.store.add('errors',{'component':'reader','error':'incomplete final line on rotation'})
                    replacement=self.opener(self.path,self.writer_uid);f.close();self.file=replacement;self.checkpoint()
                return processed
            try:
                record=json.loads(line)
                self.pipeline.ingest(record)
            except (ValueError,KeyError,TypeError) as exc:
                self.store.add('errors',{'component':'reader','error':str(exc)[:300],'line_sha256':hashlib.sha256(line).hexdigest()})
                self.pipeline.errors+=1
            except Exception:
                f.seek(start)
                raise
            self.checkpoint();processed+=1
        return processed

    def health(self):
        st=os.fstat(self.file.fileno())
        return {'offset':self.file.tell(),'size':st.st_size,
                'lag_bytes':max(0,st.st_size-self.file.tell()),'modified_at':st.st_mtime}

    def close(self):self.file.close()
