import argparse,json,sys
sys.path.insert(0,'/opt/satsuma-core')
from satsuma.package_trust import approve_key


def main():
    parser=argparse.ArgumentParser(description='Satsuma explicit repository signing-key enrollment')
    parser.add_argument('--repo',required=True)
    parser.add_argument('--source',action='append',required=True,help='Exact approved HTTPS baseurl/metalink/mirrorlist; repeat for each source')
    parser.add_argument('--key-file',required=True)
    parser.add_argument('--fingerprint',required=True,help='Full fingerprint verified independently; never a short key ID')
    args=parser.parse_args()
    print(json.dumps(approve_key(args.repo,args.source,args.key_file,args.fingerprint)))


if __name__=='__main__':main()
