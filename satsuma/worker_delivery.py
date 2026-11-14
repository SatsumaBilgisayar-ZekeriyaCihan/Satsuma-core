"""Commit collector baselines only after successful downstream delivery.

Delivery is at least once: a failed batch may replay previously delivered events.
No progress is committed when the pipeline is absent or rejects an event.
"""
from copy import deepcopy
from functools import wraps
import time


class _ProgressStore:
    def __init__(self, store, key, cursor=None):
        self.store, self.key, self.cursor, self.pending = store, key, cursor, {}
    def get(self, key, *args):
        return self.pending[key] if key in self.pending else self.store.get(key, *args)
    def set(self, key, value):
        if key == self.key or (self.cursor and key.startswith(self.cursor)):
            self.pending[key] = deepcopy(value)
        else:
            self.store.set(key, value)
    def __getattr__(self, name):
        return getattr(self.store, name)


class _Delivery:
    def __init__(self, pipeline):
        self.pipeline, self.errors = pipeline, []
    def ingest_audit(self, event):
        return self._deliver("ingest_audit", event)
    def ingest_host(self, event):
        return self._deliver("ingest_host", event)
    def _deliver(self, method, event):
        try:
            return getattr(self.pipeline, method)(event)
        except Exception as exc:
            self.errors.append(str(exc)[:300])
            raise


def delivered_tick(*attributes):
    def decorate(method):
        @wraps(method)
        def tick(self, pipeline=None, *args, **kwargs):
            original = self.store
            state = {key: deepcopy(getattr(self, key)) for key in attributes}
            progress = _ProgressStore(original, getattr(self, 'baseline_key', None), getattr(self, 'cursor_key', None))
            delivery = _Delivery(pipeline)
            self.store = progress
            try:
                if pipeline is None:
                    raise RuntimeError('Pipeline unavailable; collector progress retained')
                result = method(self, delivery, *args, **kwargs)
                if delivery.errors:
                    raise RuntimeError('Downstream delivery failed: ' + delivery.errors[0])
                if isinstance(result, dict) and result.get('ok') is False:
                    raise RuntimeError(str(result.get('error') or 'Collector reported failure'))
                for key, value in progress.pending.items():
                    original.set(key, value)
                if hasattr(self, '_commit_delivery'):
                    self._commit_delivery()
                return result
            except Exception as exc:
                for key, value in state.items():
                    setattr(self, key, value)
                health = {'ok': False, 'status': 'DEGRADED', 'updated_at': time.time(),
                          'error': str(exc)[:500], 'progress_committed': False}
                original.set(getattr(self, 'health_key', 'worker.' + self.name + '.health'), health)
                original.add('errors', {'component':'worker.'+self.name, **health})
                return health
            finally:
                self.store = original
        return tick
    return decorate
