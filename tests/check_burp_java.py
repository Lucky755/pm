"""Explicit Java/Montoya contract check; requires the real API JAR, never skips."""
import argparse
import base64
from pathlib import Path
import subprocess
import sys
import tempfile

ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT))
from executor.netguard_root import burp_grant


def main():
    parser=argparse.ArgumentParser();parser.add_argument('--montoya-jar',required=True,type=Path)
    args=parser.parse_args()
    if not args.montoya_jar.is_file():parser.error('Real Montoya API JAR required; no stub or skip')
    base=ROOT/'integrations/burp-bridge/src'
    with tempfile.TemporaryDirectory(prefix='pm-montoya-contract-') as output:
        subprocess.run(['javac','--release','21','--add-modules','jdk.httpserver','-cp',str(args.montoya_jar),'-d',output,
            str(base/'main/java/ScopeGuard.java'),str(base/'main/java/Extension.java'),str(base/'test/java/ScopeGuardContract.java')],check=True)
        spec={'method':'POST','target':'10.0.0.1','scheme':'http','hostname':'app.lab','port':8080,'path':'/contract?q=1',
            'headers':[['Authorization','Bearer offline'],['Cookie','sid=offline']],'body_b64':base64.b64encode(b'contract-body').decode()}
        token='offline_contract_secret';ticket,_=burp_grant(spec,token)
        subprocess.run(['java','-cp',output+':'+str(args.montoya_jar),'ScopeGuardContract',token,ticket],check=True)


if __name__=='__main__':main()
