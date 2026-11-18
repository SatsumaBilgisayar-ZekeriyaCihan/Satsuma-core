"""Batch scope regression / Süreç grubu kapsamı regresyonu."""
import unittest
from unittest.mock import patch
from satsuma.worker_memory import WorkerMemory

class Store:
    def __init__(self):self.values={}
    def set(self,k,v):self.values[k]=v
    def add(self,*args):pass
class FakePath:
    def __init__(self,i):self.name=str(i)
    def __lt__(self,other):return self.name < other.name
    def __truediv__(self,part):return self
    def read_text(self):return '1 (fixture) S '+('0 '*18)+'99'
class Root:
    def iterdir(self):return iter([FakePath(i) for i in range(1,130)])
class Monitor:
    def __init__(self,*a):pass
    def drain(self):return []
    def health(self):return {'status':'OBSERVING'}
    def ack(self):pass
class CoverageTests(unittest.TestCase):
    def test_unvisited_processes_prevent_complete_batch_verdict(self):
        from contextlib import ExitStack
        s=Store();w=WorkerMemory(s);w.proc_root=Root()
        class Pipeline:
            def ingest_host(self,e):pass
        with ExitStack() as stack:
            stack.enter_context(patch('satsuma.worker_memory.inspect_process',return_value=[]))
            stack.enter_context(patch('satsuma.worker_memory.validate_executable',return_value={'status':'CODE_MATCH','complete':True}))
            stack.enter_context(patch('satsuma.worker_memory.scan_executable_regions',return_value={'status':'READ','bytes_read':0}))
            stack.enter_context(patch('satsuma.worker_memory.unverifiable_exec',return_value={'status':'UNAVAILABLE'}))
            stack.enter_context(patch('satsuma.worker_memory.access_model',return_value={}))
            w.tick(Pipeline())
        health=s.values['worker.memory.health']
        self.assertIn('inspected',health,repr(health))
        self.assertEqual(health['inspected'],128)
        self.assertEqual(health['coverage'],'PARTIAL')
        self.assertEqual(health['enumerated_processes'],129)
        self.assertEqual(health['batch_processes'],128)
