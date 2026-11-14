from pathlib import Path
import uuid
class EvidenceDirectory:
    def __enter__(self):
        p=Path(__file__).resolve().parents[2]/"test-evidence"/uuid.uuid4().hex
        p.mkdir(parents=True);return str(p)
    def __exit__(self,*args):pass
