import sys,ast
from pathlib import Path
r=Path(__file__).resolve().parents[1];sys.path.insert(0,str(r))
import yaml,pydantic,psutil
from satsuma.smart_rules import SmartRuleEngine
for p in r.rglob('*.py'):ast.parse(p.read_bytes(),filename=str(p))
s=SmartRuleEngine().stats()
if s['total_rules'] != 227 or s['invalid_files']:raise SystemExit(str(s))
print('Python dependencies, syntax, rules: OK')
