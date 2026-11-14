import sys
sys.path.insert(0,'/opt/satsuma-core')
from satsuma.dnsmasq_control import verify_config
if __name__=='__main__': verify_config()
