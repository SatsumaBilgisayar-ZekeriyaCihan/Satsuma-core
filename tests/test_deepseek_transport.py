"""Offline HTTPS failures, bounds, consent and zero secret disclosure."""
import io
import json
import os
import stat
import types
import urllib.error
import uuid
from unittest.mock import Mock
import pytest
from satsuma import deepseek_client as client


@pytest.mark.parametrize('failure,expected',[(401,'authentication_failed'),(403,'authentication_failed'),(429,'quota_exceeded'),(500,'api_http_error')])
def test_http_errors_never_expose_server_body_or_headers(monkeypatch,failure,expected):
    secret=uuid.uuid4().hex
    error=urllib.error.HTTPError(client.DEFAULT_ENDPOINT,failure,secret,{'Authorization':secret},io.BytesIO(secret.encode()))
    opener=Mock();opener.open.side_effect=error
    monkeypatch.setattr(client.urllib.request,'build_opener',lambda *a:opener)
    with pytest.raises(client.DeepSeekError) as exc:client._http_post(client.DEFAULT_ENDPOINT,{},secret,1)
    assert str(exc.value)==expected and secret not in str(exc.value)


@pytest.mark.parametrize('body',[b'bad JSON',b'[]',b'x'*(client.MAX_RESPONSE_BYTES+1)])
def test_malformed_and_oversize_http_responses(monkeypatch,body):
    response=Mock();response.__enter__=Mock(return_value=response);response.__exit__=Mock(return_value=False);response.read.return_value=body
    opener=Mock();opener.open.return_value=response;monkeypatch.setattr(client.urllib.request,'build_opener',lambda *a:opener)
    with pytest.raises(client.DeepSeekError):client._http_post(client.DEFAULT_ENDPOINT,{},uuid.uuid4().hex,1)
    response.read.assert_called_once_with(client.MAX_RESPONSE_BYTES+1)


@pytest.mark.parametrize('error',[TimeoutError(),OSError('sensitive network detail'),ValueError('sensitive response')])
def test_network_and_timeout_messages_are_safe(monkeypatch,error):
    opener=Mock();opener.open.side_effect=error;monkeypatch.setattr(client.urllib.request,'build_opener',lambda *a:opener)
    with pytest.raises(client.DeepSeekError) as exc:client._http_post(client.DEFAULT_ENDPOINT,{},uuid.uuid4().hex,1)
    assert str(exc.value) in ('request_timeout','network_or_response_error')


def test_missing_key_and_no_consent_never_start_network(monkeypatch):
    call=Mock();monkeypatch.setattr(client,'_http_post',call);monkeypatch.setattr(client,'load_api_key',lambda:None)
    for confirmed in (False,True):
        with pytest.raises(client.DeepSeekError):client.connection_test({'deepseek_enabled':True},confirmed=confirmed)
    call.assert_not_called()


def test_key_file_no_symlink_or_group_reading_and_no_permission_repair(tmp_path,monkeypatch):
    path=tmp_path/'key';path.write_text(uuid.uuid4().hex);path.chmod(0o640)
    monkeypatch.setattr(client,'KEY_PATH',path);monkeypatch.setattr(client.os,'geteuid',lambda:0)
    assert client.load_api_key() is None and stat.S_IMODE(path.stat().st_mode)==0o640
    link=tmp_path/'link';link.symlink_to(path);monkeypatch.setattr(client,'KEY_PATH',link)
    assert client.load_api_key() is None
    monkeypatch.setattr(client.os,'geteuid',lambda:1000)
    assert client.load_api_key() is None


def test_custom_endpoint_and_redirects_are_refused(monkeypatch):
    with pytest.raises(client.DeepSeekError):client._http_post('https://attacker.invalid',{},uuid.uuid4().hex,1)
    with pytest.raises(client.DeepSeekError):client._NoRedirect().redirect_request(None,None,302,'redirect',{},'https://attacker.invalid')


def test_request_schema_transport_and_unexpected_response(monkeypatch):
    secret=uuid.uuid4().hex;monkeypatch.setattr(client,'load_api_key',lambda:secret)
    call=Mock(return_value={'choices':[{'message':{'content':'{"connection":"ok"}'}}]})
    monkeypatch.setattr(client,'_http_post',call)
    assert client.connection_test({'deepseek_enabled':True},confirmed=True)['connected']
    payload=call.call_args.args[1]
    assert payload['max_tokens']==16 and secret not in json.dumps(payload)
    call.return_value={'choices':[{'message':{'content':json.dumps({'leak':secret})}}]}
    with pytest.raises(client.DeepSeekError) as exc:client.connection_test({'deepseek_enabled':True},confirmed=True)
    assert secret not in str(exc.value)


def test_unsupported_or_freeform_research_input_not_sent(monkeypatch):
    call=Mock();monkeypatch.setattr(client,'_request',call)
    with pytest.raises(client.DeepSeekError):client.generate_rule('T1059; private data','reverse_shell','{}',{})
    with pytest.raises(client.DeepSeekError):client.generate_rule('T1059','raw host command 1.2.3.4','{}',{})
    call.assert_not_called()
