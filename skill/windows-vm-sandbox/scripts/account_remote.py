"""Root-side account transaction; REQUEST is injected by account.py."""
from __future__ import annotations
import base64, hashlib, importlib.util, json, os, secrets, stat, subprocess, sys, time, uuid, xml.etree.ElementTree as ET
from pathlib import Path
try:
    import fcntl
except ImportError:
    fcntl=None

def load_mod(path,name):
    spec=importlib.util.spec_from_file_location(name,path); m=importlib.util.module_from_spec(spec); spec.loader.exec_module(m); return m
def private_json(path):
    p=Path(path)
    if not p.is_absolute() or '..' in p.parts or p.is_symlink(): raise RuntimeError('unsafe private path')
    for parent in [p,*p.parents]:
        st=parent.stat()
        if parent.is_symlink() or st.st_uid!=0 or st.st_mode & 0o022: raise RuntimeError('private file must be root-owned')
    st=p.stat()
    if st.st_mode & 0o077 or st.st_size>65536: raise RuntimeError('private file must be 0600 and bounded')
    return json.loads(p.read_text(encoding='utf-8-sig'))
def write_json(path,value):
    p=Path(path)
    for parent in [p.parent,*p.parent.parents]:
        st=parent.stat()
        if parent.is_symlink() or st.st_uid!=0 or st.st_mode & 0o022: raise RuntimeError('unsafe transaction directory')
    if p.is_symlink(): raise RuntimeError('unsafe transaction marker')
    tmp=p.with_name('.'+p.name+'.'+secrets.token_hex(8)); fd=os.open(tmp,os.O_CREAT|os.O_EXCL|os.O_WRONLY,0o600)
    with os.fdopen(fd,'w',encoding='utf-8') as f: json.dump(value,f,sort_keys=True); f.write('\n'); f.flush(); os.fsync(f.fileno())
    os.replace(tmp,p)
def _account_locked(req):
    profile=req['profile']; root=Path(profile['root']); private=root/'vol/state/private'; marker=private/'account-transition.json'
    prior=private_json(marker) if marker.exists() else None
    if prior and not req.get('resume'): raise RuntimeError('account transition is pending or failed; rerun with --resume')
    if any((root/'vol/recovery'/n).exists() for n in ('owner-transition.json','c-reset-in-progress.json')) or (private/'owner-pending.json').exists(): raise RuntimeError('owner transition is active')
    # Reuse the installed identity/storage checks; this refuses a wrong VM or backing path.
    domain=subprocess.run(['virsh','--readonly','-c','qemu:///system','dumpxml',profile['name']],text=True,capture_output=True,check=False)
    if domain.returncode: raise RuntimeError('VM is not defined')
    xml=ET.fromstring(domain.stdout)
    if xml.findtext('uuid') != profile['uuid']: raise RuntimeError('VM UUID differs from profile')
    disks=xml.findall("devices/disk[@device='disk']/source")
    if len(disks)!=1 or disks[0].get('file')!=str(root/'vol/current.qcow2'):raise RuntimeError('VM system disk differs from selected instance')
    state=subprocess.run(['virsh','--readonly','-c','qemu:///system','domstate',profile['name']],text=True,capture_output=True,check=True).stdout.strip().lower()
    if state not in {'running'}: raise RuntimeError('existing VM must be running')
    libdir=root/'scripts/lib'; qga_path=libdir/(profile['name']+'_qga.py')
    manifest=private_json(private/'runtime-files.json')
    if manifest.get('uuid')!=profile['uuid'] or not manifest.get('sha256'):raise RuntimeError('runtime hash manifest is missing')
    for relative,digest in manifest['sha256'].items():
        path=root/relative
        if Path(relative).is_absolute() or '..' in Path(relative).parts or path.is_symlink() or hashlib.sha256(path.read_bytes()).hexdigest()!=digest:
            raise RuntimeError('runtime hash manifest differs')
    for path in (libdir, qga_path, libdir/'owner_environment.py', libdir/'maintenance.py'):
        st=path.lstat()
        if path.is_symlink() or st.st_uid != 0 or st.st_mode & 0o022: raise RuntimeError('untrusted runtime helper')
    if not qga_path.is_file(): raise RuntimeError('installed guest agent helper missing')
    sys.path.insert(0,str(libdir)); qga=load_mod(qga_path,'account_qga'); oe=load_mod(libdir/'owner_environment.py','account_owner_environment')
    instance=json.loads((root/'instance.json').read_text(encoding='utf-8'))
    if any(instance.get(k)!=profile.get(k) for k in ('name','uuid','root','host_root','network')):raise RuntimeError('instance profile identity differs')
    old=str(profile['windows']['admin_user']);
    new=str(req['new_admin_user'])
    if prior and (prior.get('old_user')!=old or prior.get('new_user')!=new):raise RuntimeError('resume request differs from the pending account transition')
    accepted={old,new} if prior and prior.get('phase') in {'applied','verified'} else {old}
    if str(instance.get('windows',{}).get('admin_user')) not in accepted:raise RuntimeError('profile and instance administrator differ')
    creds=private_json(private/'credentials.json'); oldpw=creds.get(old)
    if not isinstance(oldpw,str) and not prior: raise RuntimeError('current private credentials do not contain the profile administrator')
    pending=private/'account-pending.json'
    if prior and not pending.exists(): raise RuntimeError('account recovery input is missing; refusing password guess or reset')
    if prior and pending.exists():
        pending_data=private_json(pending); oldpw=pending_data.get('old_password',oldpw); newpw=pending_data.get('password')
    elif req['credentials_mode']=='generate': newpw='Vm9!'+secrets.token_urlsafe(30)
    else:
        secret=private_json(req['secret_file']); newpw=secret.get('password') if isinstance(secret,dict) else None
    if not isinstance(newpw,str) or not newpw: raise RuntimeError('new password is missing')
    rid=str(prior.get('request_id') if prior else req.get('request_id') or uuid.uuid4()); write_json(pending,{'request_id':rid,'old_password':oldpw,'password':newpw}); write_json(marker,{'schema_version':1,'request_id':rid,'phase':str(prior.get('phase') if prior else 'prepared'),'old_user':old,'new_user':new,'updated_unix':time.time()})
    request={'schema_version':1,'request_id':rid,'computer_name':profile['name'].upper(),'old_admin_user':old,'admin_user':new,'old_password':oldpw,'password':newpw}
    if prior and prior.get('phase') in {'applied','verified'}:
        result={'sid':prior.get('sid'),'is_admin':True}
    else:
        remote_dir=r'C:\ProgramData\VirtOps'; helper_remote=remote_dir+'\\account-update.ps1'; remote=remote_dir+'\\account-request-'+rid+'.json'
        qga.powershell(r"$p='C:\ProgramData\VirtOps';if(Test-Path -LiteralPath $p){if((Get-Item -LiteralPath $p).Attributes -band [IO.FileAttributes]::ReparsePoint){throw 'STATE_ROOT_REPARSE'}}else{New-Item -ItemType Directory $p|Out-Null};$acl=[Security.AccessControl.DirectorySecurity]::new();$acl.SetAccessRuleProtection($true,$false);foreach($sid in @('S-1-5-18','S-1-5-32-544')){$acl.AddAccessRule([Security.AccessControl.FileSystemAccessRule]::new([Security.Principal.SecurityIdentifier]$sid,'FullControl','ContainerInherit,ObjectInherit','None','Allow'))};[IO.Directory]::SetAccessControl($p,$acl)")
        oe.guest_write(qga,helper_remote,req['helper_source'].encode(),private=False)
        oe.guest_write(qga,remote,json.dumps(request).encode(),private=True)
        output=qga.powershell("& powershell.exe -NoLogo -NoProfile -NonInteractive -ExecutionPolicy RemoteSigned -File '"+helper_remote+"' -RequestPath '"+remote+"';exit 0",timeout=600)
        result=json.loads(output)
        if result.get('state') not in {'succeeded','success'}:raise RuntimeError('guest account update failed; preserve pending input and resume the same request')
    write_json(marker,{'schema_version':1,'request_id':rid,'phase':'applied','old_user':old,'new_user':new,'sid':result.get('sid'),'updated_unix':time.time()})
    verified=result
    if not verified.get('is_admin'): raise RuntimeError('new account admin verification failed')
    write_json(marker,{'schema_version':1,'request_id':rid,'phase':'verified','old_user':old,'new_user':new,'sid':result.get('sid'),'updated_unix':time.time()})
    owner=private_json(private/'owner.json'); owner['admin_user']=new; owner['password']=newpw; owner.setdefault('labels',{})['owner']=new;write_json(private/'owner.json',owner)
    write_json(private/'credentials.json',{new:newpw})
    instance['windows']['admin_user']=new; instance.setdefault('labels',{})['owner']=new; write_json(root/'instance.json',instance)
    reg=load_mod(root/'scripts/lib/instance_registry.py','account_registry'); reg.update_owner(instance)
    marker.unlink(missing_ok=True); pending.unlink(missing_ok=True)
    return {'status':'applied','target':profile['name'],'old_admin_user':old,'admin_user':new,'sid':result.get('sid'),'WinRM':'authenticated'}

def main(req):
    if fcntl is None:return _account_locked(req)
    lock=Path('/run/lock')/(req['profile']['name']+'.lock')
    if lock.is_symlink():raise RuntimeError('unsafe lifecycle lock')
    with lock.open('a+') as stream:
        fcntl.flock(stream,fcntl.LOCK_EX)
        return _account_locked(req)
if 'REQUEST' in globals():
    try: print(json.dumps(main(REQUEST),ensure_ascii=False,sort_keys=True)); raise SystemExit(0)
    except Exception as e: print(json.dumps({'status':'blocked','reason':str(e)[:160]},ensure_ascii=False)); raise SystemExit(2)
