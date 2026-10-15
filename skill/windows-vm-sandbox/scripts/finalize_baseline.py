#!/usr/bin/env python3
"""Run on the Linux host: capture an installed C baseline, or explicitly rehearse C reset."""
from __future__ import annotations
import argparse
import base64
import importlib.util
import json
import os
from pathlib import Path
import sys
import time

from profile import load


def module(path, name):
    st = path.stat()
    if path.is_symlink() or st.st_uid != 0 or st.st_mode & 0o022:
        raise RuntimeError('Unsafe runtime module: ' + str(path))
    spec = importlib.util.spec_from_file_location(name, path)
    result = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(result)
    return result


def execute(data, *, capture, discard):
    root = Path(data['root']); lib = root / 'scripts/lib'; name = data['name']
    for parent in [root, root/'scripts', lib]:
        st = parent.stat()
        if parent.is_symlink() or st.st_uid != 0 or st.st_mode & 0o022:
            raise RuntimeError('Unsafe instance directory: ' + str(parent))
    sys.path.insert(0, str(lib))
    ctl = module(lib/'vmctl.py', 'virtops_controller')
    if ctl.VM != name or ctl.DOMAIN_UUID != data['uuid'] or ctl.STORE != root/'vol':
        raise RuntimeError('Profile and installed controller identity differ')
    # Checks store, disk, TPM, unit, hook, and network identity before any guest write.
    ctl.verify_store_mount();ctl.verify_tpm_bind();ctl.verify_current_disk();ctl.verify_services_and_network()
    recovery = module(lib/(name+'_recovery.py'), 'virtops_recovery')
    if not capture:
        if not discard: raise RuntimeError('Reset rehearsal clears C; --discard is required')
        report = recovery.reset(ctl, True)
        meta = json.loads((root/'vol/recovery/initial-C.json').read_text())
        proof = root/'vol/recovery/reset-enabled.json'
        if proof.is_symlink(): raise RuntimeError('Unsafe reset acceptance path')
        proof.write_text(json.dumps({'verified':True, 'baseline_sha256':meta['wim_sha256'],
                                     'verified_unix':time.time(), 'evidence':report}, indent=2)+'\n')
        proof.chmod(0o600)
        return {'status':'reset_verified', 'report':report,
                'note':'Verify RDP login, authenticated WinRM upload and egress separately before handoff.'}
    rec = root/'vol/recovery'
    if any((rec/p).exists() for p in ('initial-C.wim','initial-C.json','c-reset-in-progress.json')):
        raise RuntimeError('Baseline or recovery marker exists; capture never overwrites it')
    if ctl.domstate() != 'running': raise RuntimeError('Capture requires a healthy running installed guest')
    ctl.verify_running_cgroup()
    if ctl.mem_available()+int(ctl.run(['ps','-o','rss=','-p',str(ctl.qemu_cgroup()[0])]).stdout.strip())*1024 < ctl.START_MEM_AVAILABLE_MIN+2*1024**3:
        raise RuntimeError('Estimated free memory after guest shutdown cannot cover the cold-start gate plus margin; do not stop this VM yet')
    qga = recovery.qga_module(ctl)
    # Install only these two owned recovery scripts. No partition creation or policy changes.
    target = 'C:\\ProgramData\\' + name.upper()
    for suffix in ('reset_context.ps1', 'reset_postboot.ps1'):
        path = lib/(name+'_'+suffix); ctl.require_root_helper(path)
        encoded = base64.b64encode(path.read_bytes()).decode()
        qga.powershell("New-Item -ItemType Directory -Force -Path '"+target+"'|Out-Null;"
                       "[IO.File]::WriteAllBytes('"+target+'\\'+path.name+"',[Convert]::FromBase64String('"+encoded+"'))")
    qga.powershell("& '"+target+'\\'+name+"_reset_postboot.ps1' -InstallStartupTask")
    with ctl.lifecycle_lock():
        context = recovery.collect_context(ctl)
        ctl.stop_locked()
        # Failure leaves the guest stopped with its evidence intact. Do not format/retry blindly.
        recovery.merge_offline_evidence(ctl, context)
        ctl.run([str(ctl.PYTHON3),str(recovery.HELPER),'capture','--context',str(recovery.CONTEXT)], timeout=3700)
        ctl.start_locked()
    deadline=time.monotonic()+180
    while True:
        try:
            qga.call('guest-ping',timeout=5)
            services=qga.json_script("@{RDP=(Get-Service TermService).Status.ToString();WinRM=(Get-Service WinRM).Status.ToString()}|ConvertTo-Json -Compress")
            if services=={'RDP':'Running','WinRM':'Running'}:break
        except Exception:
            pass
        if time.monotonic()>=deadline:raise RuntimeError('Baseline captured, but guest readiness after restart is not verified; inspect, do not capture again')
        time.sleep(3)
    return {'status':'baseline_captured', 'reset_enabled':False,
            'next':'Only after explicit permission to erase C, run --accept-reset --discard.'}


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--profile',required=True,type=Path)
    action=parser.add_mutually_exclusive_group(required=True)
    action.add_argument('--capture',action='store_true');action.add_argument('--accept-reset',action='store_true')
    parser.add_argument('--discard',action='store_true');args=parser.parse_args()
    if sys.platform!='linux' or os.geteuid()!=0: raise RuntimeError('Run on the selected Linux host as root')
    if args.discard and args.capture: raise RuntimeError('--discard is for reset rehearsal only')
    print(json.dumps(execute(load(args.profile),capture=args.capture,discard=args.discard),ensure_ascii=False,indent=2))


if __name__=='__main__':
    try: main()
    except Exception as exc:
        print(json.dumps({'status':'blocked','reason':str(exc)},ensure_ascii=False));raise SystemExit(2)
