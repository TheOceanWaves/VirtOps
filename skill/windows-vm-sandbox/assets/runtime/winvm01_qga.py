"""Host-admin bridge to the Windows guest agent; never logs command arguments."""
import base64
import json
import subprocess
import time

VM = 'winvm01'


def call(command, arguments=None, timeout=15):
    payload = {'execute': command}
    if arguments is not None: payload['arguments'] = arguments
    result = subprocess.run(['virsh','qemu-agent-command',VM,json.dumps(payload),'--timeout',str(timeout)],
                            capture_output=True,text=True,timeout=timeout+10)
    if result.returncode: raise RuntimeError('Guest agent unavailable: '+result.stderr.strip()[:400])
    answer=json.loads(result.stdout)
    if 'error' in answer: raise RuntimeError('Guest agent RPC error: '+str(answer['error'])[:400])
    return answer['return']


def powershell(script, timeout=180):
    script = "[Console]::OutputEncoding=[Text.UTF8Encoding]::new($false);$ProgressPreference='SilentlyContinue';" + script
    encoded=base64.b64encode(script.encode('utf-16le')).decode()
    job=call('guest-exec',{'path':r'C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe',
        'arg':['-NoLogo','-NoProfile','-NonInteractive','-ExecutionPolicy','Bypass','-EncodedCommand',encoded],
        'capture-output':True})
    deadline=time.monotonic()+timeout
    while time.monotonic()<deadline:
        result=call('guest-exec-status',{'pid':job['pid']})
        if result.get('exited'):
            out=base64.b64decode(result.get('out-data','')).decode('utf-8-sig',errors='replace')
            err=base64.b64decode(result.get('err-data','')).decode('utf-8-sig',errors='replace')
            if result.get('exitcode')!=0: raise RuntimeError('Windows command failed: '+err[:1600])
            return out
        time.sleep(1)
    raise RuntimeError('Windows command did not finish before timeout')


def json_script(script, timeout=180):
    return json.loads(powershell(script,timeout=timeout))
