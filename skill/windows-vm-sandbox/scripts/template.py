#!/usr/bin/env python3
"""Linux-host commands for a disposable builder and immutable Windows images."""
from __future__ import annotations
import argparse
import importlib.util
import json
import os
from pathlib import Path
import re
import sys
import time
import uuid

from profile import load
from base_image import ASSETS, digest, disk_info, generalized_state, inspect_manifest, run, trusted


def write_json(path, value):
    text=json.dumps(value,ensure_ascii=False,indent=2)+'\n'
    fd=os.open(path,os.O_WRONLY|os.O_CREAT|os.O_EXCL,0o600)
    with os.fdopen(fd,'w',encoding='utf-8') as stream:stream.write(text)


def source(data):
    if data.get('template_builder') is not True:
        raise ValueError('source must be explicitly designated template_builder=true; delivered personal VMs are not template builders')
    root=trusted(data['root']);lib=trusted(root/'scripts/lib')
    sys.path.insert(0,str(lib))
    def module(name,filename):
        path=trusted(lib/filename)
        spec=importlib.util.spec_from_file_location(name,path);value=importlib.util.module_from_spec(spec);spec.loader.exec_module(value);return value
    ctl=module('virtops_template_ctl','vmctl.py')
    if ctl.VM!=data['name'] or ctl.DOMAIN_UUID!=data['uuid'] or ctl.STORE!=root/'vol':raise ValueError('builder controller identity differs')
    actual=json.loads((root/'instance.json').read_text())
    if actual.get('template_builder') is not True:raise ValueError('installed source is not designated a disposable builder')
    if any(actual.get(k)!=data.get(k) for k in ('name','uuid','root','network','windows')):raise ValueError('builder profile differs from installed instance')
    ctl.verify_store_mount();ctl.verify_tpm_bind();ctl.verify_current_disk()
    for marker in ('owner-transition.json','c-reset-in-progress.json'):
        if (root/'vol/recovery'/marker).exists():raise ValueError('builder recovery is pending')
    if (root/'vol/state/private/account-transition.json').exists():raise ValueError('builder account transition is pending')
    return root,ctl,module('virtops_template_qga',data['name']+'_qga.py')


def generalize(data, *, apply=False, discard_builder=False):
    root,ctl,qga=source(data)
    if ctl.domstate()!='running':raise ValueError('generalize requires a healthy running disposable builder')
    if apply and not discard_builder:raise ValueError('--discard-builder explicitly authorizes removing the builder account/profile and resealing this source')
    script=(ASSETS/'templates/template-prepare.ps1').read_bytes()
    # Check uses an in-memory script block: a dry-run writes no guest files.
    code=script.decode('utf-8-sig')
    if not apply:
        out=qga.json_script('& {\n'+code+'\n} -BuilderAdmin '+repr(data['windows']['admin_user']))
        return {'status':'ready','target':data['name'],'evidence':out,'next':'generalize --apply --discard-builder on this dedicated source only'}
    marker=root/'vol/state/private/template-builder.json'
    if marker.exists():raise ValueError('builder generalization record exists; inspect or capture, never blindly repeat destructive preparation')
    # Run from memory so the published disk contains no helper/secret request.
    write_json(marker,{'schema_version':1,'uuid':data['uuid'],'stage':'generalizing'})
    evidence=qga.json_script('& {\n'+code+'\n} -BuilderAdmin '+repr(data['windows']['admin_user'])+' -DiscardBuilder')
    if evidence.get('state')!='sysprep_started' or evidence.get('builder_account_removed') is not True:raise ValueError('builder did not enter Sysprep')
    marker.write_text(json.dumps({'schema_version':1,'uuid':data['uuid'],'evidence':evidence,'stage':'generalizing'},indent=2))
    deadline=time.monotonic()+300
    while ctl.domstate()!='shut off':
        if time.monotonic()>deadline:raise ValueError('Sysprep has not shut down the builder; keep source isolated and inspect Sysprep logs')
        time.sleep(2)
    return {'status':'generalized_source_stopped','target':data['name'],'next':'capture; do not restart this builder'}


def capture(data, image_id, *, apply=False):
    if not re.fullmatch('[a-z][a-z0-9-]{1,39}',image_id):raise ValueError('image id must be 2-40 lowercase letters/digits/hyphens')
    root,ctl,_=source(data)
    if ctl.domstate()!='shut off':raise ValueError('template capture requires a shut-off source; never use a live disk')
    marker=trusted(root/'vol/state/private/template-builder.json')
    record=json.loads(marker.read_text())
    if record['uuid']!=data['uuid'] or record['evidence'].get('builder_account_removed') is not True:raise ValueError('builder generalization evidence missing')
    image=root/'vol/current.qcow2';info=disk_info(image)
    evidence=record['evidence']
    manifest={'schema_version':1,'kind':'generalized-windows-qcow2','image_id':image_id,'disk':'disk.qcow2',
              'sha256':'','virtual_size':info['virtual-size'],
              'windows':{'language':data['windows']['language'],'edition':evidence['edition'],'architecture':'amd64'},
              'c_partition':evidence['c_partition'],
              'generalization':{'image_state':'IMAGE_STATE_GENERALIZE_RESEAL_TO_OOBE','builder_account_removed':True}}
    with ctl.lifecycle_lock():
        if ctl.domstate()!='shut off':raise ValueError('builder restarted during capture')
        generalized_state(image,manifest)
        library=Path(data['host_root'])/'images'
        destination=library/image_id
        if destination.exists() or destination.is_symlink():raise ValueError('image id already exists; published images are never overwritten')
        if not apply:return {'status':'ready','target':image_id,'virtual_size':info['virtual-size'],'next':'capture --apply'}
        library.mkdir(mode=0o755,exist_ok=True);trusted(library)
        # Normal startup remains blocked by the builder marker. Source disposal
        # is a separate explicit destroy after the published image is verified.
        temp=library/('.publish-'+str(uuid.uuid4()));temp.mkdir(mode=0o700)
        try:
            copy=temp/'disk.qcow2'
            run(['qemu-img','convert','-f','qcow2','-O','qcow2',str(image),str(copy)],timeout=3600)
            disk_info(copy);run(['qemu-img','check','-f','qcow2',str(copy)],timeout=600)
            manifest['sha256']=digest(copy)
            write_json(temp/'manifest.json',manifest)
            copy.chmod(0o444);(temp/'manifest.json').chmod(0o444);temp.chmod(0o555)
            temp.rename(destination)
        except Exception:
            # Do not remove a potentially useful partial image or a foreign
            # destination. The unpublished private path is safe to inspect.
            raise
    return {'status':'published','manifest':str(destination/'manifest.json'),'sha256':manifest['sha256'],
            'next':'create independent instances from this manifest; never boot the builder again'}


def main():
    parser=argparse.ArgumentParser(description=__doc__);sub=parser.add_subparsers(dest='action',required=True)
    for action in ('generalize','capture'):
        p=sub.add_parser(action);p.add_argument('--profile',required=True,type=Path);p.add_argument('--apply',action='store_true')
        if action=='generalize':p.add_argument('--discard-builder',action='store_true')
        else:p.add_argument('--image-id',required=True)
    p=sub.add_parser('inspect');p.add_argument('--manifest',required=True,type=Path)
    args=parser.parse_args()
    try:
        if sys.platform!='linux' or os.geteuid()!=0:raise ValueError('run template.py on the selected Linux host as root')
        if args.action=='inspect':result={'status':'verified','image':inspect_manifest(args.manifest)}
        elif args.action=='generalize':result=generalize(load(args.profile),apply=args.apply,discard_builder=args.discard_builder)
        else:result=capture(load(args.profile),args.image_id,apply=args.apply)
        print(json.dumps(result,ensure_ascii=False,indent=2));return 0
    except Exception as exc:
        # No password is read by these operations. Source-specific error output
        # remains in the controlled builder rather than serialized command argv.
        print(json.dumps({'status':'blocked','reason':str(exc)},ensure_ascii=False));return 2


if __name__=='__main__':raise SystemExit(main())
