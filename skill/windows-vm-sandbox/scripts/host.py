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
    args = parser.parse_args()
    try:
        data = load(args.profile)
        if args.action == 'reset' and not args.discard:
            raise ValueError('reset clears C:; user authorization and --discard are required')
        ssh = data['ssh']
        command = ['ssh', '-o', 'BatchMode=yes', '-o', 'ConnectTimeout=10', '-p', str(ssh.get('port', 22))]
        if ssh.get('bind_address'):
            command += ['-o', 'BindAddress=' + ssh['bind_address']]
        if ssh.get('identity_file'):
            command += ['-i', ssh['identity_file']]
        command += [ssh['user'] + '@' + ssh['host']]
        command += ['sudo', '-n', 'python3', '-'] if ssh.get('sudo', True) else ['python3', '-']
        payload = base64.b64encode(json.dumps({'profile': data, 'action': args.action, 'discard': args.discard}).encode()).decode()
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
