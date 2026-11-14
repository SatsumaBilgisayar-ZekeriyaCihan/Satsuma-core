#!/usr/bin/env python3
"""Research CLI through the same authenticated Operator channel as Qt6.

Signing remains external: export approved canonical bytes, sign with the
operator's GPG, then supply the detached public signature. No key import.
"""
import argparse
import getpass
import json
import sys
import uuid
from pathlib import Path
sys.path.insert(0,str(Path(__file__).resolve().parents[1]))
from satsuma.dashboard_api_client import ReaderClient
from satsuma.operator_service import SOCKET_PATH


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    choice=parser.add_mutually_exclusive_group(required=True)
    choice.add_argument('--list',action='store_true')
    choice.add_argument('--generate',action='store_true')
    choice.add_argument('--approve',metavar='RULE_ID')
    choice.add_argument('--reject',metavar='RULE_ID')
    choice.add_argument('--export',metavar='RULE_ID')
    choice.add_argument('--verify-signature',metavar='RULE_ID')
    choice.add_argument('--activate',metavar='RULE_ID')
    parser.add_argument('--reason',default='')
    parser.add_argument('--technique')
    parser.add_argument('--attack',default='reverse_shell')
    parser.add_argument('--signature-file',type=Path)
    parser.add_argument('--output',type=Path)
    parser.add_argument('--confirm-api',action='store_true')
    parser.add_argument('--confirm-activation',action='store_true')
    args=parser.parse_args();params={'request_id':uuid.uuid4().hex}
    if args.generate:
        if not args.confirm_api:parser.error('--confirm-api gerekli')
        method='deepseek_generate';params.update(technique=args.technique,attack_type=args.attack,confirmed=True)
    elif args.list:method='deepseek_list'
    else:
        mapping=(('approve','deepseek_approve'),('reject','deepseek_reject'),('export','deepseek_export'),
                 ('verify_signature','deepseek_verify_signature'),('activate','deepseek_activate'))
        field,method=next((key,value) for key,value in mapping if getattr(args,key))
        params.update(rule_id=getattr(args,field),reason=args.reason)
        if args.activate:
            if not args.confirm_activation:parser.error('--confirm-activation gerekli')
            params['confirmed']=True
        if args.verify_signature:
            if not args.signature_file:parser.error('--signature-file gerekli')
            with args.signature_file.open('rb') as stream:signature=stream.read(16385)
            if len(signature)>16384 or not signature.startswith(b'-----BEGIN PGP SIGNATURE-----'):parser.error('Yalnız ayrık açık GPG imzası kabul edilir')
            params['signature']=signature.decode('ascii')
    client=ReaderClient(SOCKET_PATH,timeout=60);token=None
    try:
        result=client.call('login',password=getpass.getpass('Satsuma yönetici parolası: '))
        if not result.get('ok'):print('Yönetici doğrulaması başarısız.');return 1
        token=result['token'];result=client.call(method,token=token,**params)
        if args.export and args.output and result.get('signing_payload'):
            args.output.write_bytes(result['signing_payload'].encode())
        print(json.dumps(result,ensure_ascii=False,indent=2));return 0 if result.get('ok') else 1
    except Exception:
        print('Yetkili işlem tamamlanamadı.');return 1
    finally:
        if token:
            try:client.call('logout',token=token)
            except Exception:pass

if __name__=='__main__':raise SystemExit(main())
