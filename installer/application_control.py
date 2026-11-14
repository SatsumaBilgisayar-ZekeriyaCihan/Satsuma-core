"""Compatibility launcher for the native continuous App Control daemon."""
import sys
sys.path.insert(0, '/opt/satsuma-core')
from satsuma.app_firewall import main

if __name__ == '__main__':
    main()
