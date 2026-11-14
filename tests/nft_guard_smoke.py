"""Kernel state/readback smoke, only inside the authorized isolated CI container.

No packet prevention or vendor remote-control success is inferred from this test.
"""
import importlib.util
from pathlib import Path
import subprocess

spec=importlib.util.spec_from_file_location('guard',Path(__file__).parents[1]/'integrations/satsuma_guard.py')
module=importlib.util.module_from_spec(spec);spec.loader.exec_module(module)
nft=module.Nft()
try:
    nft.setup()
    nft.verify_layout()
    for ip in ['45.33.32.10','2606:4700:4700::1111']:
        nft.block(ip)
        assert nft.contains(ip)
        nft.unblock(ip)
        assert not nft.contains(ip)
    print('ISOLATED_KERNEL_STATE_READBACK_PASS; TRAFFIC_PREVENTION_NOT_TESTED')
finally:
    subprocess.run(['nft','delete','table','inet',nft.TABLE],check=True,capture_output=True)
