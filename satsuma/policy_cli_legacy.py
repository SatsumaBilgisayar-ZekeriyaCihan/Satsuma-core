import argparse,json,os,time
from pathlib import Path
from .policy import PolicyStore,validate,diff
from .audit_policy import plan as audit_plan,apply as audit_apply
from .nft_policy import plan as nft_plan,apply as nft_apply

def main(argv=None):
 parser=argparse.ArgumentParser(description='Satsuma Core policy manager')
 sub=parser.add_subparsers(dest='command',required=True)
 sub.add_parser('show');p=sub.add_parser('validate');p.add_argument('file')
 p=sub.add_parser('plan');p.add_argument('file')
 p=sub.add_parser('apply');p.add_argument('file');p.add_argument('--expected-revision',required=True,type=int)
 args=parser.parse_args(argv);store=PolicyStore()
 if args.command=='show':print(json.dumps(store.load(),indent=2));return
 candidate=validate(json.loads(Path(args.file).read_text()));current=store.load();candidate['revision']=current['revision']+1
 report={'current_revision':current['revision'],'candidate_revision':candidate['revision'],'changes':diff(current,candidate),'audit':audit_plan(candidate),'nftables':nft_plan(candidate)}
 if args.command in ('validate','plan'):print(json.dumps(report,indent=2));return
 from satsuma.runtime_user import require_service_user; require_service_user()
 saved,record=store.save(candidate,args.expected_revision);details={}
 try:
  details['audit']=audit_apply(saved);details['nftables']=nft_apply(saved);store.record_apply(saved['revision'],'APPLIED',details)
 except Exception as exc:
  store.record_apply(saved['revision'],'PARTIAL' if details else 'SAVED_NOT_APPLIED',{**details,'error':str(exc)})
  raise
 print(json.dumps({'policy':record,**details},indent=2))
