#!/usr/bin/env python3
"""Invoke existing VM management through SSH; no global command installation."""
import argparse
import base64
import json
from pathlib import Path
import subprocess
import sys

from profile import load


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('action', choices=['inspect', 'start', 'stop', 'status', 'logs', 'counters', 'reset', 'delete', 'recreate'])
    parser.add_argument('--profile', required=True, type=Path)
    parser.add_argument('--discard', action='store_true')
    parser.add_argument('--discard-data', action='store_true')
    parser.add_argument('--owner-profile', type=Path)
    parser.add_argument('--all', action='store_true', help='status: list every registered VM on the host')
    parser.add_argument('--network-only', action='store_true', help='logs: return only VM network-block records')
    args = parser.parse_args()
    try:
        data = load(args.profile)
        if data.get('image',{}).get('kind')=='base' and args.action in {'reset','delete','recreate'}:
            raise ValueError('Template-derived instances use destroy.py or instance.py rebuild for full replacement; legacy definition/C reset commands do not apply')
        if args.action == 'reset' and not args.discard:
            raise ValueError('reset clears C:; user authorization and --discard are required')
        if args.action != 'reset' and (args.discard_data or args.owner_profile):
            raise ValueError('--owner-profile/--discard-data are valid only for reset')
        if args.all and args.action != 'status':
            raise ValueError('--all is valid only for status')
        if args.network_only and args.action != 'logs':
            raise ValueError('--network-only is valid only for logs')
        owner_profile = None
        if args.owner_profile:
            owner_profile = str(args.owner_profile)
            if not owner_profile.startswith('/') or '..' in Path(owner_profile).parts:
                raise ValueError('--owner-profile must be an absolute remote Linux path')
        ssh = data['ssh']
        command = ['ssh', '-o', 'BatchMode=yes', '-o', 'ConnectTimeout=10', '-p', str(ssh.get('port', 22))]
        if ssh.get('bind_address'):
            command += ['-o', 'BindAddress=' + ssh['bind_address']]
        if ssh.get('identity_file'):
            command += ['-i', ssh['identity_file']]
        command += [ssh['user'] + '@' + ssh['host']]
        command += ['sudo', '-n', 'python3', '-'] if ssh.get('sudo', True) else ['python3', '-']
        payload = base64.b64encode(json.dumps({'profile': data, 'action': args.action, 'discard': args.discard,
                                                'discard_data': args.discard_data, 'owner_profile': owner_profile,
                                                'all': args.all,
                                                'network_only': args.network_only}).encode()).decode()
        source = 'import base64,json\nREQUEST=json.loads(base64.b64decode(' + repr(payload) + '))\n'
        source += (Path(__file__).with_name('host_remote.py')).read_text(encoding='utf-8')
        completed = subprocess.run(command, input=source, text=True, capture_output=True, timeout=3800 if args.action == 'reset' else 180)
        if completed.stdout:
            print(completed.stdout, end='')
        if completed.stderr:
            print(completed.stderr, file=sys.stderr, end='')
        return completed.returncode
    except (OSError, ValueError, KeyError, subprocess.SubprocessError) as exc:
        print(json.dumps({'status': 'blocked', 'reason': str(exc)}))
        return 2


if __name__ == '__main__':
    raise SystemExit(main())
