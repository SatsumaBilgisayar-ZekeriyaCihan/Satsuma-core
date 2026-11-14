"""Configuration failures are readiness failures, separate from code integrity."""
import json
import sys

EX_CONFIG = 78


class ConfigurationError(ValueError):
    def __init__(self, code, path, detail):
        self.code, self.path, self.detail = code, str(path), str(detail)[:500]
        super().__init__(f'{code}: {self.path}: {self.detail}')


def entrypoint(main):
    """Do not repeatedly restart a service for an unchanged invalid policy."""
    try:
        return main()
    except ConfigurationError as exc:
        print(json.dumps({'status': exc.code, 'path': exc.path,
                          'detail': exc.detail, 'response_unlocked': False}), file=sys.stderr)
        return EX_CONFIG
