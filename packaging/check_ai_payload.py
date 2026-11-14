"""Check an extracted/staged RPM payload without installing or starting it.

Açılmış ya da hazırlanmış RPM içeriğini kurmadan ve başlatmadan denetler.
"""
import json
import os
from pathlib import Path
import subprocess
import sys

REQUIRED=('satsuma/deepseek_client.py','satsuma/deepseek_workflow.py','satsuma/ai_rule_package.py',
    'satsuma/rule_signing.py','satsuma/rule_response.py','satsuma/memory_scope.py',
    'satsuma/dashboard_qt/panels/deepseek.py','schemas/ai-rule-package-v1.schema.json',
    'schemas/rule-response-catalog-v1.json','cli/satsuma-deepseek-test.py','cli/satsuma-research.py')


def inspect(root):
    payload=Path(root)/'usr/lib/satsuma-core/payload'
    for name in REQUIRED:
        path=payload/name
        if not path.is_file() or path.is_symlink():raise RuntimeError('payload missing: '+name)
        if path.suffix=='.py':compile(path.read_bytes(),str(path),'exec')
    assert len(json.loads((payload/'schemas/rule-response-catalog-v1.json').read_text())['rules'])==233
    if any(payload.rglob('deepseek.key')) or any(payload.rglob('*.asc')):raise RuntimeError('unexpected key/signature in runtime payload')
    code='''import json
from pathlib import Path
from satsuma import deepseek_workflow,rule_signing,memory_scope,ai_rule_package
from satsuma.smart_rules import SmartRuleEngine
from satsuma.dashboard_qt.panels.deepseek import DeepSeekPanel
from jsonschema import Draft202012Validator
root=Path.cwd()
assert Path(deepseek_workflow.__file__).is_relative_to(root)
assert Path(DeepSeekPanel.__module__.replace('.', '/')).name=='deepseek'
Draft202012Validator.check_schema(json.loads(ai_rule_package.SCHEMA_PATH.read_text()))
engine=SmartRuleEngine(root/'rules')
assert len(engine.rules)==233 and not engine.load_errors
print(json.dumps({'rules':len(engine.rules),'qt_panel':DeepSeekPanel.PANEL_ID,'operator_methods':len(deepseek_workflow.METHODS)}))
'''
    result=subprocess.run([sys.executable,'-B','-c',code],cwd=payload,env={**os.environ,'PYTHONPATH':str(payload),'QT_QPA_PLATFORM':'offscreen'},
                          check=True,capture_output=True,text=True,timeout=30)
    return {'status':'PASS','required_files':list(REQUIRED),'runtime_imports':json.loads(result.stdout),
            'scope':'extracted_or_staged_payload','rpm_install_tested':False,'systemd_startup_tested':False}

if __name__=='__main__':print(json.dumps(inspect(Path(sys.argv[1])),indent=2))
