"""C baseline + owner settings transaction. Secrets use root-only files and in-process RPC."""
import base64
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import re
import secrets
import socket
import ssl
import subprocess
import time
import uuid

import maintenance


def load_module(path,name):
    spec=importlib.util.spec_from_file_location(name,path)
    value=importlib.util.module_from_spec(spec);spec.loader.exec_module(value);return value


def private_json(path):
    path=Path(path)
    if not path.is_absolute() or '..' in path.parts:raise RuntimeError('Private configuration path must be clean and absolute')
    for parent in [path,*path.parents]:
        st=parent.stat()
        if parent.is_symlink() or st.st_uid!=0 or st.st_mode&0o022:
            raise RuntimeError('Private configuration needs root-owned, non-writable ancestors')
    fd=os.open(path,os.O_RDONLY|os.O_NOFOLLOW)
    with os.fdopen(fd,'r',encoding='utf-8-sig') as stream:
        st=os.fstat(stream.fileno())
        if st.st_mode&0o077 or st.st_size>65536:raise RuntimeError('Private configuration must be root-only and bounded')
        return json.load(stream)


def write_json(path,data,mode=0o600):
    path=Path(path)
    for parent in path.parents:
        st=parent.stat()
        if parent.is_symlink() or st.st_uid!=0 or st.st_mode&0o022:raise RuntimeError('Unsafe state ancestor')
    if path.is_symlink():raise RuntimeError('Unsafe state destination')
    if path.exists() and (path.stat().st_uid!=0 or path.stat().st_mode&0o022):raise RuntimeError('Unsafe existing state')
    temporary=path.with_name('.'+path.name+'.'+secrets.token_hex(8))
    fd=os.open(temporary,os.O_CREAT|os.O_EXCL|os.O_WRONLY,mode)
    try:
        with os.fdopen(fd,'w',encoding='utf-8') as stream:
            json.dump(data,stream,indent=2);stream.write('\n');stream.flush();os.fsync(stream.fileno())
        os.replace(temporary,path)
    finally:temporary.unlink(missing_ok=True)


def validate_owner(data,name,domain_uuid,discard_data):
    if data.get('schema_version')!=1 or data.get('name')!=name or data.get('uuid')!=domain_uuid:
        raise RuntimeError('Owner profile must identify the existing VM name and UUID')
    user=data.get('admin_user','')
    if not isinstance(user,str) or not re.fullmatch(r'[A-Za-z][A-Za-z0-9_.-]{0,19}',user) or user.lower() in {
        'administrator','guest','defaultaccount','defaultuser0','system','administrators','wdagutilityaccount','localservice','networkservice'}:
        raise RuntimeError('Choose a non-built-in ASCII administrator name of 1-20 characters')
    if data.get('data_policy') not in {'preserve','clear'}:raise RuntimeError('Explicit D policy is required')
    if data['data_policy']=='clear' and not discard_data:raise RuntimeError('D clearing additionally requires --discard-data')
    if data['data_policy']=='preserve' and discard_data:raise RuntimeError('D policy and --discard-data disagree')
    if any(key.lower() in {'password','secret','token'} for key in data):raise RuntimeError('Owner profile must not contain secret values')
    credentials=data.get('credentials',{})
    if not isinstance(credentials,dict) or credentials.get('mode') not in {'generate','file'} or set(credentials)-{'mode','secret_file'}:
        raise RuntimeError('Choose generate or a root-only password file; never embed a password in the profile')
    labels=data.get('labels',{})
    if not isinstance(labels,dict) or set(labels)-{'owner','purpose'} or any(not isinstance(v,str) or len(v)>80 or any(ord(c)<32 for c in v) for v in labels.values()):
        raise RuntimeError('Owner labels must be short public owner/purpose strings')
    return data


def new_owner(data):
    credentials=data['credentials']
    password=('V9!'+secrets.token_urlsafe(30)) if credentials['mode']=='generate' else private_json(credentials['secret_file'])['password']
    if not isinstance(password,str) or len(password)<12 or sum(bool(re.search(p,password)) for p in ('[a-z]','[A-Z]','[0-9]','[^A-Za-z0-9]'))<3:
        raise RuntimeError('Password needs 12+ characters and three character categories')
    return {'name':data['name'],'uuid':data['uuid'],'admin_user':data['admin_user'],'password':password,
            'data_policy':data['data_policy'],'labels':{'owner':data['admin_user'],**data.get('labels',{})}}


def private_rpc(vm,command,arguments):
    """Call the installed libvirt C API in-process; no secret argv/history/file."""
    import ctypes as C
    import ctypes.util
    lib=C.CDLL(ctypes.util.find_library('virt') or 'libvirt.so.0')
    qemu=C.CDLL(ctypes.util.find_library('virt-qemu') or 'libvirt-qemu.so.0')
    libc=C.CDLL(ctypes.util.find_library('c') or 'libc.so.6')
    lib.virConnectOpen.argtypes=[C.c_char_p];lib.virConnectOpen.restype=C.c_void_p
    lib.virDomainLookupByName.argtypes=[C.c_void_p,C.c_char_p];lib.virDomainLookupByName.restype=C.c_void_p
    lib.virDomainFree.argtypes=[C.c_void_p];lib.virDomainFree.restype=C.c_int
    lib.virConnectClose.argtypes=[C.c_void_p];lib.virConnectClose.restype=C.c_int
    qemu.virDomainQemuAgentCommand.argtypes=[C.c_void_p,C.c_char_p,C.c_int,C.c_uint]
    qemu.virDomainQemuAgentCommand.restype=C.c_void_p
    libc.free.argtypes=[C.c_void_p];libc.free.restype=None
    error_callback=C.CFUNCTYPE(None,C.c_void_p,C.c_void_p)(lambda opaque,error:None)
    lib.virConnSetErrorFunc.argtypes=[C.c_void_p,C.c_void_p,C.c_void_p]
    conn=lib.virConnectOpen(b'qemu:///system')
    if not conn:raise RuntimeError('Private guest RPC connection failed')
    domain=None;response_ptr=None
    try:
        lib.virConnSetErrorFunc(conn,None,C.cast(error_callback,C.c_void_p))
        domain=lib.virDomainLookupByName(conn,vm.encode())
        if not domain:raise RuntimeError('Private guest RPC domain not found')
        payload=json.dumps({'execute':command,'arguments':arguments},separators=(',',':')).encode()
        response_ptr=qemu.virDomainQemuAgentCommand(domain,payload,15,0)
        if not response_ptr:raise RuntimeError('Private guest RPC failed; no payload logged')
        response=json.loads(C.string_at(response_ptr))
        if 'error' in response or 'return' not in response:raise RuntimeError('Private guest RPC rejected')
        return response['return']
    finally:
        if response_ptr:libc.free(response_ptr)
        if domain:lib.virDomainFree(domain)
        lib.virConnectClose(conn)


def guest_write(qga,path,content,private=False):
    handle=qga.call('guest-file-open',{'path':path,'mode':'wb'})
    try:
        for offset in range(0,len(content),16384):
            args={'handle':handle,'buf-b64':base64.b64encode(content[offset:offset+16384]).decode()}
            answer=private_rpc(qga.VM,'guest-file-write',args) if private else qga.call('guest-file-write',args)
            if answer.get('count')!=len(content[offset:offset+16384]):raise RuntimeError('Short guest file write')
        qga.call('guest-file-flush',{'handle':handle})
    finally:qga.call('guest-file-close',{'handle':handle})


def invoke_guest(ctl,qga,request,helper):
    directory=r'C:\ProgramData\VirtOps';remote=directory+'\\owner-request-'+request['request_id']+'.json'
    # Set only the private VirtOps directory's DACL, using DACL-only .NET APIs.
    qga.powershell(r"$p='C:\ProgramData\VirtOps';if(Test-Path -LiteralPath $p){$i=Get-Item -LiteralPath $p;if($i.Attributes -band [IO.FileAttributes]::ReparsePoint){throw 'Unsafe owner state directory'}}else{New-Item -ItemType Directory $p|Out-Null};$a=[Security.AccessControl.DirectorySecurity]::new();$a.SetAccessRuleProtection($true,$false);foreach($sid in @('S-1-5-18','S-1-5-32-544')){$a.AddAccessRule([Security.AccessControl.FileSystemAccessRule]::new([Security.Principal.SecurityIdentifier]$sid,'FullControl','ContainerInherit,ObjectInherit','None','Allow'))};[IO.Directory]::SetAccessControl($p,$a)")
    path=Path(__file__).with_name(helper);ctl.require_root_helper(path)
    helper_remote=directory+'\\'+helper
    guest_write(qga,helper_remote,path.read_bytes())
    try:
        guest_write(qga,remote,json.dumps(request).encode(),private=True)
        output=qga.powershell("$o=& powershell.exe -NoLogo -NoProfile -NonInteractive -ExecutionPolicy RemoteSigned -File '"+helper_remote+"' -RequestPath '"+remote+"';$o;exit 0",timeout=600)
        result=json.loads(output)
        if result.get('request_id')!=request['request_id'] or result.get('state') not in {'success','succeeded'}:
            raise RuntimeError('Guest owner step failed: '+str(result.get('code','UNKNOWN'))[:80])
        return result
    finally:
        qga.powershell("Remove-Item -LiteralPath '"+remote+"' -Force -ErrorAction SilentlyContinue",timeout=30)


def host_tls_pin(port,expected):
    context=ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT);context.check_hostname=False;context.verify_mode=ssl.CERT_NONE
    with socket.create_connection(('127.0.0.1',port),timeout=10) as tcp:
        with context.wrap_socket(tcp,server_hostname='localhost') as tls:
            actual=hashlib.sha1(tls.getpeercert(binary_form=True)).hexdigest().upper()
    if actual!=expected.upper():raise RuntimeError('Host published endpoint and authenticated guest endpoint certificate differ')


def wait_guest(qga):
    deadline=time.monotonic()+180
    while time.monotonic()<deadline:
        try:
            qga.call('guest-ping',timeout=5)
            return
        except Exception:
            time.sleep(3)
    raise RuntimeError('Guest management channel did not become ready')


def pending(ctl):
    return maintenance.active(ctl.STORE/'recovery/owner-transition.json')


def data_identity(context):
    d=context['disk']['partitions'].get('D')
    return ({**{k:d[k] for k in ('unique_guid','start_bytes','size_bytes','ntfs_serial')},
             'disk_guid':context['disk']['disk_guid']} if d else None)


def guest_request(ctl,owner,state,*,preflight=False):
    return {'schema_version':1,'request_id':state['request_id'],'computer_name':ctl.VM.upper(),
            'admin_user':owner['admin_user'],'password':owner['password'],'data_policy':owner['data_policy'],
            'clear_authorized':owner['data_policy']=='clear','d_expected':state['d_expected'],
            'preflight_only':preflight}


def ready_guest(ctl,recovery,gate):
    if ctl.domstate() in {'shut off','shutoff'}:
        ctl.start_locked(owner_validation=True)
    if ctl.domstate()=='paused':
        gate.verify();ctl.verify_store_mount();ctl.verify_tpm_bind();ctl.verify_running_cgroup();ctl.verify_services_and_network()
        config=ctl.instance_config()
        if (ctl.free_bytes(ctl.STORE)<ctl.START_STORE_FREE_MIN or
            ctl.free_bytes(Path('/'))<ctl.START_ROOT_FREE_MIN or
            ctl.mem_available()<config['limits']['resume_free_gib']*ctl.GIB):
            raise RuntimeError('Normal disk and resume memory reserves are required')
        ctl.run(['virsh','-c','qemu:///system','resume',ctl.VM])
    if ctl.domstate()!='running':raise RuntimeError('Owner operation needs a running guest after guarded start')
    qga=recovery.qga_module(ctl);wait_guest(qga)
    return qga


def reset(ctl,recovery,discard,owner_profile=None,discard_data=False):
    if not discard:raise RuntimeError('C reset requires --discard')
    if discard_data and not owner_profile:raise RuntimeError('D clearing needs a new explicit owner profile')
    private=ctl.STORE/'state/private';marker=ctl.STORE/'recovery/owner-transition.json'
    configured=private/'owner.json';secret_pending=private/'owner-pending.json'
    fingerprint=None
    if owner_profile:
        profile=validate_owner(private_json(owner_profile),ctl.VM,ctl.DOMAIN_UUID,discard_data)
        fingerprint=hashlib.sha256(json.dumps(profile,sort_keys=True).encode()).hexdigest()
    else:profile=None
    with ctl.lifecycle_lock():
        network=load_module(ctl.NETWORK,'owner_network')
        gate=network.maintenance_gate()
        if pending(ctl):
            state=private_json(marker);owner=private_json(secret_pending)
            if state['profile_hash']!=fingerprint:raise RuntimeError('Pending owner operation belongs to a different request; resume the same profile')
            if state['phase']=='failed':state['phase']=state['resume_from']
        else:
            owner=new_owner(profile) if profile else private_json(configured)
            if not profile:owner['data_policy']='preserve'
            if owner.get('name')!=ctl.VM or owner.get('uuid')!=ctl.DOMAIN_UUID:raise RuntimeError('Stored owner identity differs from VM')
            ctl.verify_store_mount();ctl.verify_tpm_bind();ctl.verify_current_disk();ctl.verify_services_and_network()
            if ctl.domstate()!='running':raise RuntimeError('Start and verify the guest before a new owner reset')
            qga=recovery.qga_module(ctl);qga.call('guest-ping')
            state={'schema_version':1,'name':ctl.VM,'uuid':ctl.DOMAIN_UUID,'request_id':str(uuid.uuid4()),
                   'phase':'prepared','profile_hash':fingerprint,'admin_user':owner['admin_user'],'data_policy':owner['data_policy']}
            write_json(secret_pending,owner);write_json(marker,state)
        stage=state['phase']
        try:
            gate.install();gate.verify()
            def advance(phase):
                nonlocal stage
                stage=phase;state['phase']=phase;state['updated_unix']=time.time();write_json(marker,state)
            if stage=='prepared':
                qga=ready_guest(ctl,recovery,gate)
                context=recovery.collect_context(ctl)
                state['d_expected']=data_identity(context)
                if owner['data_policy']=='clear' and not state['d_expected']:
                    raise RuntimeError('D clearing requested but there is no verified D partition')
                qga=recovery.qga_module(ctl)
                result=invoke_guest(ctl,qga,guest_request(ctl,owner,state,preflight=True),'owner_apply.ps1')
                if result.get('preflight_only') is not True:raise RuntimeError('Read-only owner preflight was not verified')
            if stage in {'prepared','restoring'}:
                advance('restoring')
                recovery.reset(ctl,True,locked=True)
                context=private_json(recovery.CONTEXT)
                state['d_expected']=data_identity(context)
                if owner['data_policy']=='clear' and not state['d_expected']:raise RuntimeError('D clearing requested but there is no verified D partition')
                advance('applying')
            if stage in {'applying','verifying'}:
                qga=ready_guest(ctl,recovery,gate)
                request=guest_request(ctl,owner,state)
                if stage=='applying':
                    state['apply']=invoke_guest(ctl,qga,request,'owner_apply.ps1');advance('verifying')
                state['verification']=invoke_guest(ctl,qga,request,'owner_verify.ps1')
                config=json.loads((ctl.STORE.parent/'instance.json').read_text())
                host_tls_pin(config['network']['winrm_port'],state['verification']['thumbprint'])
                if not state['verification'].get('rdp_service_running'):raise RuntimeError('RDP service is not ready')
                advance('committing')
            if stage=='committing':
                persisted={**owner,'data_policy':'preserve'}
                write_json(configured,persisted)
                write_json(private/'credentials.json',{owner['admin_user']:owner['password']})
                path=ctl.STORE.parent/'instance.json';config=json.loads(path.read_text())
                config['windows']['admin_user']=owner['admin_user'];config['winrm_thumbprint']=state['verification']['thumbprint']
                config.setdefault('labels',{}).update(owner.get('labels',{}))
                config['credentials']={'mode':'existing','secret_file':None,'local_clixml':None}
                write_json(path,config,0o600)
                import instance_registry
                instance_registry.update_owner(config)
                advance('releasing')
            if stage=='releasing':
                if ctl.domstate()!='running':
                    qga=ready_guest(ctl,recovery,gate)
                    request=guest_request(ctl,owner,state)
                    state['verification']=invoke_guest(ctl,qga,request,'owner_verify.ps1')
                    config=json.loads((ctl.STORE.parent/'instance.json').read_text())
                    host_tls_pin(config['network']['winrm_port'],state['verification']['thumbprint'])
                    if not state['verification'].get('rdp_service_running'):raise RuntimeError('RDP service is not ready')
                if ctl.domstate()!='running':raise RuntimeError('Release requires a verified running guest')
                ctl.verify_store_mount();ctl.verify_tpm_bind();ctl.verify_running_cgroup();gate.verify()
                gate.remove();advance('complete');ctl.verify_services_and_network()
                secret_pending.unlink(missing_ok=True)
                ctl.event('owner_environment_ready',request_id=state['request_id'],admin_user=owner['admin_user'],D_policy=owner['data_policy'])
                return {'C_reset':'verified','owner':owner['admin_user'],'D':owner['data_policy'],'actual_state':ctl.domstate(),
                        'request_id':state['request_id'],'WinRM':'authenticated','RDP':'ready_for_login_not_interactively_verified',
                        'profile':str(ctl.STORE.parent/'instance.json')}
            raise RuntimeError('Unknown transition stage')
        except Exception:
            state['resume_from']='releasing' if stage=='complete' else stage
            state['phase']='failed';write_json(marker,state)
            try:
                gate.install()
                if ctl.domstate()=='running':ctl.stop_locked()
            except Exception:
                if ctl.domstate()=='running':ctl.run(['virsh','suspend',ctl.VM],check=False)
            ctl.event('owner_environment_blocked',request_id=state['request_id'],stage=stage)
            raise RuntimeError('Owner transition blocked at '+stage+'; retain maintenance state and resume the same request') from None
