#!/usr/bin/env python3
"""Change the existing Windows owner account without rebuilding the VM."""
from __future__ import annotations
import argparse, base64, json, re, subprocess, sys, uuid
from pathlib import Path
from profile import load

def _ssh(data):
    s=data['ssh']; cmd=['ssh','-o','BatchMode=yes','-o','ConnectTimeout=10','-p',str(s.get('port',22))]
    if s.get('bind_address'): cmd += ['-o','BindAddress='+s['bind_address']]
    if s.get('identity_file'): cmd += ['-i',s['identity_file']]
    cmd += [s['user']+'@'+s['host']]
    cmd += ['sudo','-n','python3','-'] if s.get('sudo',True) else ['python3','-']
    return cmd

def main():
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument('--profile',required=True,type=Path); p.add_argument('--admin-user',required=True)
    p.add_argument('--credentials-mode',choices=('generate','file'),required=True)
    p.add_argument('--secret-file',help='absolute path on the Linux host; never a local password')
    p.add_argument('--apply',action='store_true'); p.add_argument('--resume',action='store_true')
    a=p.parse_args()
    try:
        data=load(a.profile,new=False)
        if not re.fullmatch(r'[A-Za-z][A-Za-z0-9_.-]{0,19}',a.admin_user): raise ValueError('invalid administrator name')
        if a.credentials_mode=='file' and (not a.secret_file or not a.secret_file.startswith('/') or '..' in Path(a.secret_file).parts):
            raise ValueError('--secret-file must be a clean absolute remote path')
        if not a.apply:
            print(json.dumps({'status':'dry-run','target':data['name'],'current_admin_user':data['windows']['admin_user'],
                              'new_admin_user':a.admin_user,'credentials_mode':a.credentials_mode,
                              'remote':'not contacted; local plan only; no secrets read and no VM or files changed'},ensure_ascii=False,sort_keys=True)); return 0
        helper=(Path(__file__).parents[1]/'assets/templates/account-update.ps1').read_text(encoding='utf-8')
        req={'profile':data,'new_admin_user':a.admin_user,'credentials_mode':a.credentials_mode,'helper_source':helper,
             'secret_file':a.secret_file,'resume':a.resume,'request_id':str(uuid.uuid4()),'apply':True}
        payload=base64.b64encode(json.dumps(req,sort_keys=True).encode()).decode()
        source='from __future__ import annotations\nimport base64,json\nREQUEST=json.loads(base64.b64decode('+repr(payload)+'))\n'
        source += (Path(__file__).with_name('account_remote.py')).read_text(encoding='utf-8').replace('from __future__ import annotations\n','',1)
        r=subprocess.run(_ssh(data),input=source,text=True,capture_output=True,timeout=900,check=False)
        if r.stdout: print(r.stdout,end='')
        if r.stderr: print(r.stderr,file=sys.stderr,end='')
        return r.returncode
    except (OSError,ValueError,KeyError,TypeError,subprocess.SubprocessError) as e:
        print(json.dumps({'status':'blocked','reason':str(e)},ensure_ascii=False)); return 2
if __name__=='__main__': raise SystemExit(main())
