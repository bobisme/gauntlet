#!/usr/bin/env python3
"""Validate durable topology evidence and exercise ownership-safe cleanup."""
import asyncio
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import time
import unittest

ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / 'scripts/candidate-topology.py'
EVIDENCE = ROOT / 'fixtures/contracts/candidate-topology-observed.json'

def validate(x):
    def require(condition, message):
        if not condition: raise ValueError(message)
    require(set(x) == {'scenario','exit_code','script_sha256','teapot_sha256','hallpass_sha256','fixture_sha256','worker','verifier','ledger_verified','ledger_totals','project_requests','enforced'}, 'unexpected observation schema')
    require(x['scenario'] == 'private verifier topology, loopback only' and x['exit_code'] == 0 and x['enforced'] is False, 'invalid result')
    require(x['script_sha256'] == hashlib.sha256(SCRIPT.read_bytes()).hexdigest(), 'script hash mismatch')
    require(x['teapot_sha256'] == '6d15d625e10afa768a221f64eb7a2a245a64a7babbe61cf74ce8d4ff33b2f458', 'wrong Teapot')
    require(x['hallpass_sha256'] == 'be289583707b9a6810d148dbddf4e3c0c09fddd74b78d4e00cab47f8c30e993d', 'wrong Hallpass')
    require(len(x['fixture_sha256']) == 64 and all(c in '0123456789abcdef' for c in x['fixture_sha256']), 'invalid fixture hash')
    w = x['worker']; labels = ['fixture/ground-truth.json','fixture-source','fixture/admin-secret','fixture/verifier-passwords.json','exploration/.teapot','verifier/.teapot','local.pass.toml']
    require(set(w) == {'reads','connections','identities','default_verifier_logins','podman','image_id','network','gateway','container_removed'}, 'invalid worker schema')
    require(all(set(r) == {'path','refused','error'} for r in w['reads']), 'invalid read schema')
    require([r['path'] for r in w['reads']] == labels and all(r['refused'] for r in w['reads']), 'invalid protected reads')
    require(set(w['connections']) == {'fixture','verifier_proxy'} and all(c['refused'] for c in w['connections'].values()), 'invalid connection probes')
    require(all(set(c) == {'refused','error'} for c in w['connections'].values()), 'invalid connection schema')
    require(w['identities'] == [{'name':n,'status':200,'id':'user-'+n} for n in ('alice','bob')], 'invalid worker identities')
    require(w['default_verifier_logins'] == [{'name':n,'status':401} for n in ('alice-verify','bob-verify')], 'invalid default verifier logins')
    require(w['network'] == 'none' and w['container_removed'] is True, 'invalid boundary')
    require(x['verifier']['sessions'] == ['alice-verify','bob-verify'] and x['verifier']['status'] == 200 and x['verifier']['subject'] == 'user-alice-verify', 'invalid verifier')
    require(x['ledger_verified'] is True and len(x['ledger_totals']) == 1 and len(x['project_requests']) == 2, 'invalid accounting')
    require('/tmp/' not in json.dumps(x) and 'password' not in json.dumps(x).lower().replace('verifier-passwords.json','').replace('default_verifier_logins',''), 'unredacted data')

class EvidenceTest(unittest.TestCase):
    def test_committed_observation(self):
        data = json.loads(EVIDENCE.read_text()); validate(data)
        data['script_sha256'] = '0' * 64
        with self.assertRaises(ValueError): validate(data)

class CleanupTest(unittest.TestCase):
    def run_worker(self, write_cid):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp); fake = root/'podman'
            fake.write_text('''#!/usr/bin/python3
import os, pathlib, sys, time
args = sys.argv[1:]; root = pathlib.Path(os.environ['FAKE_ROOT']); args.pop(0)
if args[0] == 'info': print('true')
elif args[:2] == ['image','inspect']: print('a'*64)
elif args[0] == '--version': print('fake')
elif args[0] == 'run':
    if os.environ['WRITE_CID'] == 'yes': pathlib.Path(args[args.index('--cidfile')+1]).write_text('b'*64+'\\n')
    (root/'started').write_text('yes'); time.sleep(60)
elif args[0] == 'rm': (root/'removed').write_text(args[-1])
elif args[:2] == ['container','exists']: sys.exit(1)
else: sys.exit(2)
'''); fake.chmod(0o755)
            runner = root/'runner.py'
            runner.write_text('''import asyncio, importlib.util, os, sys
spec=importlib.util.spec_from_file_location('candidate',sys.argv[1]); m=importlib.util.module_from_spec(spec); spec.loader.exec_module(m)
asyncio.run(m.worker(1,2,3,[],dict(os.environ)))
''')
            env = dict(os.environ, PATH=f'{root}:/usr/bin:/bin', FAKE_ROOT=tmp, WRITE_CID='yes' if write_cid else 'no')
            process = subprocess.Popen([sys.executable,'-I','-B',str(runner),str(SCRIPT)],env=env,stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL)
            try:
                deadline=time.monotonic()+10
                while not (root/'started').exists() and time.monotonic()<deadline:
                    self.assertIsNone(process.poll()); time.sleep(.05)
                self.assertTrue((root/'started').exists())
                process.send_signal(__import__('signal').SIGINT); process.wait(timeout=10)
                self.assertNotEqual(process.returncode,0)
                if write_cid: self.assertEqual((root/'removed').read_text(),'b'*64)
                else: self.assertFalse((root/'removed').exists())
            finally:
                if process.poll() is None: process.kill(); process.wait()
    def test_cid_is_used_on_interrupt(self): self.run_worker(True)
    def test_missing_cid_never_removes_by_name(self): self.run_worker(False)

if __name__ == '__main__': unittest.main()
