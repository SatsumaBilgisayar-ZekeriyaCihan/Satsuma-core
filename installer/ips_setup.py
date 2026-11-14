import sys
sys.path.insert(0, '/opt/satsuma-core')
from satsuma.ips import wait_for_listener, write_ready

if __name__ == '__main__':
    wait_for_listener()
    write_ready()
