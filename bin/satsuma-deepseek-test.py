#!/usr/bin/env python3
"""Explicit, authenticated connection test via the existing Operator IPC.

No local API-key loading or key fragments. This makes one small HTTPS request
only when --confirm-api is supplied and an administrator session is verified.
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
    parser.add_argument('--confirm-api',action='store_true')
    args=parser.parse_args()
    if not args.confirm_api:
        print('Gerçek API isteği için --confirm-api gerekli.');return 1
    client=ReaderClient(SOCKET_PATH,timeout=60);token=None
    try:
        login=client.call('login',password=getpass.getpass('Satsuma yönetici parolası: '))
        if not login.get('ok'):print('Yönetici doğrulaması başarısız.');return 1
        token=login['token']
        result=client.call('deepseek_test_connection',token=token,request_id=uuid.uuid4().hex,confirmed=True)
        print(json.dumps(result,ensure_ascii=False,indent=2))
        return 0 if result.get('ok') else 1
    except Exception:
        print('Yetkili Operator bağlantısı kurulamadı.');return 1
    finally:
        if token:
            try:client.call('logout',token=token)
            except Exception:pass

if __name__=='__main__':raise SystemExit(main())
