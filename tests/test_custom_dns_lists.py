import socket
import pytest
from satsuma import custom_dns_lists as c
from satsuma.dnsmasq_control import render

class Store:
    def __init__(self):self.data={};self.events=[]
    def get(self,key,default=None):return self.data.get(key,default)
    def set(self,key,value):self.data[key]=value
    def add(self,key,value):self.events.append((key,value))


def test_supported_feeds_are_parsed_as_domains_not_executed():
    assert c.parse_data(b'# comment\n0.0.0.0 BAD.EXAMPLE\n127.0.0.1 localhost\n||other.example^\nplain.example\n')==['bad.example','other.example','plain.example']
    for raw in (b'<html>error</html>',b'192.0.2.1',b'https://bad.example/path',b'address=/bad.example/evil',b'bad.example\nserver=attacker'):
        with pytest.raises(ValueError):c.parse_data(raw)


@pytest.mark.parametrize('url',['http://example.com/list','file:///etc/passwd','https://127.0.0.1/list','https://user:password@example.com/list','https://example.com:8443/list'])
def test_invalid_or_private_feed_urls_rejected(url):
    with pytest.raises(ValueError):c.validate_url(url)


def test_private_dns_answer_is_rejected_before_connection(monkeypatch):
    monkeypatch.setattr(c.socket,'getaddrinfo',lambda *a,**k:[(socket.AF_INET,socket.SOCK_STREAM,6,'',('127.0.0.1',443))])
    with pytest.raises(ValueError):c.public_addresses('public.example',443)
    with pytest.raises(ValueError):c.NoRedirect().redirect_request(None,None,None,None,None,None)


def test_success_reaches_dns_rules_and_error_preserves_previous_list():
    store=Store();store.set('dns_policy',{'enabled':True,'upstream':'1.1.1.1'});rendered=[]
    def refresh():
        rendered.append(render(store.get('dns_policy'),c.blocked_domains(store),['safe.bad.example']))
        return {'status':'configured'}
    result=c.change(store,'https://lists.example/hosts','update',refresh,fetcher=lambda url:b'0.0.0.0 bad.example\n')
    assert result['active'] and 'address=/bad.example/#' in rendered[-1]
    assert 'server=/safe.bad.example/1.1.1.1' in rendered[-1]
    old=store.get('custom_dns_sources')
    with pytest.raises(ValueError):c.change(store,'https://lists.example/hosts','update',refresh,fetcher=lambda url:b'<html>error</html>')
    assert store.get('custom_dns_sources')==old
    calls=[]
    def broken():
        calls.append(1)
        if len(calls)==1:raise RuntimeError('DNS reload failed')
        return refresh()
    with pytest.raises(RuntimeError):c.change(store,'https://lists.example/hosts','update',broken,fetcher=lambda url:b'new.example\n')
    assert store.get('custom_dns_sources')==old and len(calls)==2
    c.change(store,'https://lists.example/hosts','remove',refresh)
    assert not c.blocked_domains(store)
