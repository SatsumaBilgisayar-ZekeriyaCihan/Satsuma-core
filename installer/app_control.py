import sys
sys.path.insert(0,'/opt/satsuma-core')
from satsuma.app_firewall import main
if __name__=='__main__':
    from satsuma.configuration_status import entrypoint
    raise SystemExit(entrypoint(main))
