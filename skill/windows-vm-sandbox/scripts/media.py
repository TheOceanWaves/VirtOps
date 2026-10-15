#!/usr/bin/env python3
"""Inspect both downloaded ISOs before a full VM profile or WIM index exists."""
import argparse
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import xml.etree.ElementTree as ET

from prepare_host import media_info, run, verify_virtio


def inspect_windows(path):
    with tempfile.TemporaryDirectory(prefix='virtops-media-') as directory:
        run(['mount','-o','loop,ro,nodev,nosuid,noexec',str(path),directory])
        try:
            image=next((Path(directory)/'sources'/n for n in ('install.wim','install.esd') if (Path(directory)/'sources'/n).is_file()),None)
            if image is None:raise RuntimeError('Windows ISO lacks sources/install.wim or install.esd')
            xml=ET.fromstring(subprocess.check_output(['wimlib-imagex','info',str(image),'--xml'],timeout=120))
            return [{'index':int(n.attrib['INDEX']),'name':n.findtext('NAME'),'edition':n.findtext('WINDOWS/EDITIONID'),
                     'arch':n.findtext('WINDOWS/ARCH'),'language':n.findtext('WINDOWS/LANGUAGES/DEFAULT')} for n in xml.findall('IMAGE')]
        finally:run(['umount',directory])


def main():
    p=argparse.ArgumentParser(description=__doc__);p.add_argument('--windows-iso',required=True,type=Path);p.add_argument('--virtio-iso',required=True,type=Path);a=p.parse_args()
    if sys.platform!='linux' or os.geteuid()!=0:raise RuntimeError('Run on the selected Linux host as root')
    for path in (a.windows_iso,a.virtio_iso):
        if not path.is_absolute() or not path.is_file():raise RuntimeError('NEEDS_DOWNLOAD: '+str(path))
    result={'windows':media_info(a.windows_iso),'virtio':media_info(a.virtio_iso)}
    result['images']=inspect_windows(a.windows_iso);verify_virtio(str(a.virtio_iso));result['virtio']['required_files_present']=True
    print(json.dumps(result,ensure_ascii=False,indent=2))


if __name__=='__main__':
    try:main()
    except (OSError,RuntimeError,subprocess.SubprocessError,ET.ParseError) as exc:
        print(json.dumps({'status':'blocked','reason':str(exc)},ensure_ascii=False));raise SystemExit(2)
