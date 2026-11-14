"""Every loaded baseline rule must have a hash-bound editable policy plan.

Yüklenen her temel kuralın özetle bağlı düzenlenebilir politika planı olmalı.
"""
import json
import unittest
from satsuma.rule_response import set_requirement,CATALOG_PATH,POLICY_KEY
from satsuma.smart_rules import SmartRuleEngine

class Store:
    def __init__(self):self.values={};self.records=[]
    def get(self,key,default=None):return self.values.get(key,default)
    def set(self,key,value):self.values[key]=value
    def add(self,kind,value):self.records.append((kind,value))

class CatalogConsistencyTests(unittest.TestCase):
    def test_retired_ram_rules_are_not_in_active_policy_catalog(self):
        engine=SmartRuleEngine(include_managed=False)
        active={r['_id'] for r in engine.rules}
        catalog=json.loads(CATALOG_PATH.read_text())
        catalog_ids={r['rule_id'] for r in catalog['rules']}
        for retired in ('SATSUMA-RAM-106','SATSUMA-RAM-107'):
            self.assertNotIn(retired,active)
            self.assertNotIn(retired,catalog_ids)
        self.assertIn('SATSUMA-RAM-001',active)
    def test_catalog_covers_actual_baseline_ids_without_activating_proposals(self):
        engine=SmartRuleEngine(include_managed=False)
        catalog=json.loads(CATALOG_PATH.read_text())
        self.assertEqual({r['_id'] for r in engine.rules},{r['rule_id'] for r in catalog['rules']})
        self.assertTrue(all(r['proposed_response']['applied'] is False for r in catalog['rules']))
