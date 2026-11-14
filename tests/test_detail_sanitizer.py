import importlib.util
from pathlib import Path

module_path = Path(__file__).parents[1] / 'satsuma/dashboard_qt/detail_sanitizer.py'
spec = importlib.util.spec_from_file_location('detail_sanitizer', module_path)
module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(module)
detail_lines, redact_detail = module.detail_lines, module.redact_detail


def test_nested_secrets_are_redacted():
    source={'results':[{'api_key':'very-secret','nested':{'password':'danger','ok':'fine'}},
                       {'Authorization':'Bearer abcdef','safe':'token=xyz'}]}
    output=detail_lines(source)
    assert 'very-secret' not in output
    assert 'danger' not in output
    assert 'abcdef' not in output
    assert 'xyz' not in output
    assert 'fine' in output
    assert 'GİZLENDİ' in output


def test_node_depth_and_text_bounds():
    node={'text':'Z'*100000}
    for _ in range(100):node={'item':node}
    assert len(detail_lines(node)) < 65537
    assert 'DERİNLİK SINIRI' in detail_lines(node)
    assert len(redact_detail('A'*500000)) < 1300


def test_raw_input_is_unchanged():
    original={'token':'secret','data':[1,2]}
    assert redact_detail(original)['token']=='[GİZLENDİ]'
    assert original['token']=='secret'


def test_keys_with_secrets_not_exposed():
    result=detail_lines({'api_token':'xyz','details':[{'private_key':'abc'}]})
    assert 'xyz' not in result and 'abc' not in result


def test_inline_bearer_and_authorization():
    result = detail_lines('Authorization: Bearer abc.xyz\nBearer secret123')
    assert 'abc.xyz' not in result and 'secret123' not in result


def test_embedded_json_and_query_style_secrets_are_masked():
    text = '{"password": "p455-special", "token":"hidden-value"} url?api_key=abc123&mode=check'
    safe = detail_lines(text)
    for secret in ('p455-special', 'hidden-value', 'abc123'):
        assert secret not in safe
    assert 'mode=check' in safe


def test_redact_does_not_mutate_complex_input():
    source = [{'payload': 'Authorization: Bearer example-token', 'result': 'ok'}]
    redacted = redact_detail(source)
    assert redacted[0]['result'] == 'ok'
    assert 'example-token' not in str(redacted)
    assert 'example-token' in str(source)
