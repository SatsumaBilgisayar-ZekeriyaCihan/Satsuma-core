#!/usr/bin/env python3
"""Static, read-only hardening inventory. No claims about runtime drop-ins.

Do not apply unit restrictions without runtime trial and rollback on Fedora.
"""
import argparse
import json
from pathlib import Path

KEYS = ('User', 'Group', 'ProtectSystem', 'ProtectHome', 'PrivateTmp',
        'PrivateDevices', 'ProtectProc', 'ProcSubset', 'RestrictAddressFamilies',
        'CapabilityBoundingSet', 'AmbientCapabilities', 'ReadWritePaths',
        'InaccessiblePaths', 'DevicePolicy', 'NoNewPrivileges')


def parse_unit(path):
    section = None
    settings = {}
    for line in Path(path).read_text(encoding='utf-8').splitlines():
        line = line.strip()
        if not line or line.startswith(('#', ';')):
            continue
        if line.startswith('[') and line.endswith(']'):
            section = line[1:-1]
        elif section == 'Service' and '=' in line:
            key, value = line.split('=', 1)
            settings[key.strip()] = value.strip()
    return settings


def audit(folder):
    units = []
    for path in sorted(Path(folder).glob('*.service')):
        config = parse_unit(path)
        if not config:
            continue
        root = config.get('User', 'root') == 'root'
        missing = [key for key in ('ProtectSystem', 'ProtectHome', 'PrivateTmp',
                                    'NoNewPrivileges') if key not in config]
        units.append({'service': path.name, 'runs_as_root': root,
                      'static_missing_baselines': missing,
                      'missing_read_visibility_restriction': 'InaccessiblePaths' not in config,
                      'configuration': {key: config.get(key, '(unspecified)') for key in KEYS}})
    return {'scope': 'source unit files only; excludes runtime drop-ins and host state',
            'runtime_verified': False, 'root_units': sum(row['runs_as_root'] for row in units),
            'units': units}


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('units_directory', type=Path)
    args = parser.parse_args()
    print(json.dumps(audit(args.units_directory), ensure_ascii=False, indent=2))


if __name__ == '__main__':
    main()
