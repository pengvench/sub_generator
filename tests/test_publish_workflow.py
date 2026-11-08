"""Exercise the workflow's actual publish shell against local Git remotes."""
from pathlib import Path
import os
import shutil
import subprocess
import tempfile
import textwrap
import unittest

ROOT=Path(__file__).resolve().parents[1]
BASH=(r'C:\Program Files\Git\bin\bash.exe' if os.name=='nt' else shutil.which('bash'))

def git(cwd,*args):
    process=subprocess.run(['git',*args],cwd=cwd,capture_output=True,text=True,check=True)
    return process.stdout.strip()

@unittest.skipUnless(BASH and Path(BASH).exists(),'Bash is required for the GitHub workflow')
class PublishWorkflowTests(unittest.TestCase):
    def exercise(self,advanced):
        workflow=(ROOT/'.github/workflows/refresh-subs.yml').read_text(encoding='utf-8')
        step=workflow.split('      - name: "Publish: commit + sync + push"',1)[1]
        script=textwrap.dedent(step.split('        run: |\n',1)[1])
        with tempfile.TemporaryDirectory(prefix='.publish-',dir=Path(__file__).parent) as directory:
            base=Path(directory).resolve()
            self.assertTrue(base.is_relative_to(Path(__file__).parent.resolve()))
            remote=base/'remote.git'
            seed=base/'seed'
            runner=base/'runner'
            git(base,'init','--bare','--initial-branch=main',str(remote))
            git(base,'clone',str(remote),str(seed))
            git(seed,'config','user.name','Test')
            git(seed,'config','user.email','test@example.invalid')
            git(seed,'config','commit.gpgsign','false')
            (seed/'data').mkdir()
            (seed/'data/preload.txt').write_text('old data\n')
            (seed/'data/sources.txt').write_text('old sources\n')
            (seed/'code.txt').write_text('old code\n')
            git(seed,'add','.')
            git(seed,'commit','-m','Initial')
            git(seed,'push','origin','main')
            git(base,'clone',str(remote),str(runner))
            git(runner,'config','commit.gpgsign','false')
            (runner/'data/preload.txt').write_text('fresh checked data\n')
            if advanced:
                (seed/'data/sources.txt').write_text('new sources and mirrors\n')
                (seed/'code.txt').write_text('new code\n')
                git(seed,'add','.')
                git(seed,'commit','-m','Concurrent user edit')
                git(seed,'push','origin','main')
            changed=(base/'changed.z').as_posix()
            script=script.replace('/tmp/publish_changed.z','"'+changed+'"')
            process=subprocess.run([str(BASH),'-c',script],cwd=runner,capture_output=True,text=True)
            self.assertEqual(process.returncode,0,process.stdout+'\n'+process.stderr)
            self.assertEqual(git(base,'--git-dir',str(remote),'show','main:data/preload.txt'),'fresh checked data')
            self.assertEqual(git(base,'--git-dir',str(remote),'show','main:code.txt'),'new code' if advanced else 'old code')
            self.assertEqual(git(base,'--git-dir',str(remote),'show','main:data/sources.txt'),
                             'new sources and mirrors' if advanced else 'old sources')

    def test_publish_after_remote_advanced_preserves_code_and_sources(self):
        self.exercise(True)

    def test_publish_without_concurrent_edit(self):
        self.exercise(False)

if __name__=='__main__':
    unittest.main()
