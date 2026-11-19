"""Eligibility is not authorization, a signal or verified process exit.

Adaylık; yetkilendirme, sinyal veya doğrulanmış süreç çıkışı değildir.
"""
from pathlib import Path
from contextlib import contextmanager
from satsuma import dashboard_api as api
from satsuma.store import Store


def test_rules_expose_actual_central_candidates_without_fabricating_results(tmp_path,monkeypatch):
    store=Store(tmp_path/'data',test=True)
    @contextmanager
    def connection():yield store.db
    monkeypatch.setattr(api,'_connect',connection)
    monkeypatch.setattr(api,'RULES_DIR',Path(__file__).parents[1]/'rules')
    try:
        report=api.m_rules();rows={r['rule_id']:r for r in report['rules']}
        assert report['active_total']==306 and report['direct_stop_total']==0
        assert report['central_policy_candidate_total']>0
        for rid in ('SATSUMA-EXEC-001','SATSUMA-EXEC-007','SATSUMA-EXEC-009','SATSUMA-EXEC-011','SATSUMA-EXFIL-006'):
            row=rows[rid]
            assert row['central_policy_candidate'] and not row['direct_stop_defined']
            assert row['policy_decision']=='not_evaluated' and row['verified_evidence_count'] is None
            assert row['intervention_result']=={'status':'UNKNOWN','executed':None}
        assert not rows['SATSUMA-EXFIL-010']['central_policy_candidate']
        assert not rows['SATSUMA-EXFIL-008']['central_policy_candidate']
    finally:store.close()
