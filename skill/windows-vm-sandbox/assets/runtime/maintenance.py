"""Per-instance maintenance gate, inside existing private chains; no shared-chain flush."""
from pathlib import Path
import json
import shlex
import subprocess


def active(path):
    path=Path(path)
    if not path.exists():return False
    st=path.stat()
    if path.is_symlink() or st.st_uid!=0 or st.st_mode&0o077:
        raise RuntimeError('Unsafe owner transition state')
    state=json.loads(path.read_text())
    if state.get('phase') not in {'prepared','restoring','applying','verifying','committing','releasing','complete','failed'}:
        raise RuntimeError('Unknown owner transition phase')
    return state['phase']!='complete'


class Gate:
    def __init__(self,name,published,forward_chain,output_chain,run=None):
        self.chain=name.upper()+'_MAINT'
        self.parents=(forward_chain,output_chain)
        self.published=published
        self.run=run or self._run

    @staticmethod
    def _run(args):
        return subprocess.run(args,text=True,capture_output=True,timeout=15)

    def command(self,*args,check=True):
        result=self.run(['iptables-nft','-w','5','-t','filter',*args])
        if check and result.returncode:raise RuntimeError('Maintenance firewall operation failed')
        return result

    def rules(self):
        return [['-p','tcp','--dport',str(guest),'-m','conntrack','--ctorigsrc','127.0.0.1','--ctorigdst','127.0.0.1',
                 '--ctorigdstport',str(published),'-j','RETURN'] for published,guest in self.published]+[['-j','DROP']]

    def prepare(self):
        result=self.command('-S',self.chain,check=False)
        if result.returncode:
            self.command('-N',self.chain)
            for rule in self.rules():self.command('-A',self.chain,*rule)
        else:self.verify_chain()

    def verify_chain(self):
        listing=self.command('-S',self.chain).stdout.splitlines()
        if len([x for x in listing if x.startswith('-A ')])!=len(self.rules()):
            raise RuntimeError('Partial maintenance chain; stop and repair, never flush a live gate')
        for rule in self.rules():self.command('-C',self.chain,*rule)

    def install(self):
        self.prepare()
        for parent in self.parents:
            if self.command('-S',parent,check=False).returncode:continue
            jump=['-j',self.chain]
            if self.command('-C',parent,*jump,check=False).returncode:self.command('-I',parent,'1',*jump)
        self.verify(require_parents=False)

    def verify(self,require_parents=True):
        self.verify_chain()
        for parent in self.parents:
            result=self.command('-S',parent,check=False)
            if result.returncode and not require_parents:continue
            if result.returncode:raise RuntimeError('Missing private maintenance parent')
            rows=[shlex.split(x) for x in result.stdout.splitlines() if x.startswith('-A ')]
            if not rows or rows[0]!=['-A',parent,'-j',self.chain]:
                raise RuntimeError('Maintenance gate must precede established-session ACCEPT')

    def remove(self):
        for parent in self.parents:
            while not self.command('-C',parent,'-j',self.chain,check=False).returncode:
                self.command('-D',parent,'-j',self.chain)
        if not self.command('-S',self.chain,check=False).returncode:
            self.command('-F',self.chain);self.command('-X',self.chain)
