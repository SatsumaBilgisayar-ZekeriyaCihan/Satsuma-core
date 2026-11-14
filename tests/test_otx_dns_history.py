"""A DNS error preserves historical success but never means current readiness.

DNS hatası geçmiş başarıyı korur; güncel hazırlık anlamına gelmez.
"""
import socket
from contextlib import contextmanager
from unittest.mock import Mock
from satsuma import otx,dashboard_api as api
from satsuma.store import Store


def test_dns_failure_retains_last_success_in_worker_and_reader(tmp_path,monkeypatch):
    store=Store(tmp_path/'data',test=True)
    try:
        store.set('otx_health',{'status':'active','last_success':1234567890,'tls_verified':True})
        monkeypatch.setattr(otx,'load_config',lambda:{'api_key':'fixture','cache_ttl_seconds':3600,'max_queries_per_cycle':1})
        monkeypatch.setattr(otx,'load_with_policy',lambda:({'otx_enabled':True}, {}, {}))
        monkeypatch.setattr(otx,'remote_support_ips',lambda store:set())
        monkeypatch.setattr(otx,'run_domains',lambda *args:None)
        monkeypatch.setattr(otx,'request_ipv4',Mock(side_effect=socket.gaierror('Temporary failure in name resolution')))
        otx.run_once(store,response=Mock(),candidates=['8.8.8.8'])
        health=store.get('otx_health')
        assert health['status']=='error' and health['last_success']==1234567890 and not health['tls_verified']
        assert 'name resolution' in health['error']
        @contextmanager
        def connection():yield store.db
        monkeypatch.setattr(api,'_connect',connection)
        monkeypatch.setattr(api,'_otx_config_status',lambda:(True,True))
        result=api.m_otx()
        assert result['status']=='ERROR' and result['last_successful_update']==1234567890
    finally:store.close()


def test_failure_without_previous_success_does_not_invent_it(tmp_path):
    store=Store(tmp_path/'data',test=True)
    try:
        otx.record_health(store,{'status':'error','updated_at':100,'error':'DNS unavailable'})
        assert 'last_success' not in store.get('otx_health')
    finally:store.close()
