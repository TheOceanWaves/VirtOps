#!/usr/bin/env python3
"""Read installed guest readiness and certificate pin through trusted host QGA, without credentials."""
import argparse
import importlib.util
import json
import os
from pathlib import Path
import subprocess
import sys
import xml.etree.ElementTree as ET

from profile import load


def inspect(data):
    xml=ET.fromstring(subprocess.check_output(['virsh','--readonly','-c','qemu:///system','dumpxml',data['name']],text=True))
    if xml.findtext('uuid')!=data['uuid']:raise RuntimeError('VM UUID differs from profile')
    root=Path(data['root']);path=root/'scripts/lib'/(data['name']+'_qga.py')
    for parent in (root,root/'scripts',path.parent,path):
        st=parent.stat()
        if parent.is_symlink() or st.st_uid!=0 or st.st_mode&0o022:raise RuntimeError('Unsafe QGA helper path')
    spec=importlib.util.spec_from_file_location('virtops_qga',path);qga=importlib.util.module_from_spec(spec);spec.loader.exec_module(qga)
    if qga.VM!=data['name']:raise RuntimeError('QGA helper VM identity differs')
    qga.call('guest-ping')
    name=data['name']
    script=r"""
$listeners=@(Get-ChildItem WSMan:\localhost\Listener | Where-Object {$_.Keys -contains 'Transport=HTTPS'})
$pins=@(foreach($l in $listeners){(Get-Item ($l.PSPath+'\CertificateThumbprint')).Value})
@{computer_name=$env:COMPUTERNAME;time_utc=[DateTime]::UtcNow.ToString('o');
  provision_success=(Test-Path 'C:\Windows\Temp\__NAME__-provision.success');
  winrm=(Get-Service WinRM).Status.ToString();rdp=(Get-Service TermService).Status.ToString();
  enabled_users=@(Get-LocalUser|Where-Object Enabled|Select-Object -ExpandProperty Name);
  memory_bytes=(Get-CimInstance Win32_ComputerSystem).TotalPhysicalMemory;
  logical_cpus=(Get-CimInstance Win32_ComputerSystem).NumberOfLogicalProcessors;
  winrm_thumbprints=$pins;default_routes=@(Get-NetRoute -DestinationPrefix '0.0.0.0/0' -ErrorAction SilentlyContinue|Select-Object NextHop,InterfaceAlias)}|ConvertTo-Json -Depth 5 -Compress
""".replace('__NAME__',name)
    return json.loads(qga.powershell(script))


if __name__=='__main__':
    parser=argparse.ArgumentParser(description=__doc__);parser.add_argument('--profile',required=True,type=Path);args=parser.parse_args()
    try:
        if sys.platform!='linux' or os.geteuid()!=0:raise RuntimeError('Run on the selected Linux host as root')
        print(json.dumps(inspect(load(args.profile)),ensure_ascii=False,indent=2))
    except Exception as exc:
        print(json.dumps({'status':'not_ready_or_blocked','reason':str(exc)},ensure_ascii=False));raise SystemExit(2)
