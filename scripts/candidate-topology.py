#!/usr/bin/env python3
"""Exercise a local candidate; not a custody certification."""
import argparse
import asyncio
import datetime as dt
import hashlib
import json
import os
from pathlib import Path
import re
import secrets
import signal
import subprocess
import tempfile
import threading
import time

ROOT = Path(__file__).resolve().parents[1]
PIN = '6d15d625e10afa768a221f64eb7a2a245a64a7babbe61cf74ce8d4ff33b2f458'
HALLPASS_PIN = 'be289583707b9a6810d148dbddf4e3c0c09fddd74b78d4e00cab47f8c30e993d'
PODMAN = ['podman', '--remote=false']
WORKER = r'''
import http.client, json, os, socket, sys
port, verifier_port, *paths = sys.argv[1:]
reads = []
labels = ('fixture/ground-truth.json','fixture-source','fixture/admin-secret','fixture/verifier-passwords.json','exploration/.teapot','verifier/.teapot','local.pass.toml')
for label, path in zip(labels, paths):
    try:
        os.stat(path)
        if not os.path.isdir(path):
            with open(path, 'rb') as f: f.read(1)
    except OSError as e: reads.append({'path':label,'refused':True,'error':e.strerror})
    else: reads.append({'path':label,'refused':False})
connections = {}
for name, p in (('fixture',port),('verifier_proxy',verifier_port)):
    try:
        s = socket.create_connection(('127.0.0.1',int(p)),timeout=2); s.close()
    except OSError as e: connections[name] = {'refused':True,'error':e.strerror}
    else: connections[name] = {'refused':False}
class Proxy(http.client.HTTPConnection):
    def connect(self):
        self.sock = socket.socket(socket.AF_UNIX); self.sock.settimeout(10)
        self.sock.connect('/gateway/proxy.sock')
def request(method,path,body=None,headers=None):
    c = Proxy('proxy'); c.request(method,'http://127.0.0.1:'+port+path,body,headers or {})
    r = c.getresponse(); result = r.status,dict(r.getheaders()),r.read(); c.close(); return result
identities = []
default_verifier_logins = []
for name in ('alice-verify','bob-verify'):
    body = json.dumps({'username':name,'password':name+'-password'})
    status, _, _ = request('POST','/app/login',body,{'Content-Type':'application/json'})
    default_verifier_logins.append({'name':name,'status':status})
for name in ('alice','bob'):
    body = json.dumps({'username':name,'password':name+'-password'})
    status, headers, _ = request('POST','/app/login',body,{'Content-Type':'application/json'})
    if status != 200: raise RuntimeError('login failed: '+name+' '+str(status))
    cookie = headers['set-cookie'].split(';',1)[0]
    status, _, body = request('GET','/app/api/me',headers={'Cookie':cookie})
    identities.append({'name':name,'status':status,'id':json.loads(body)['id']})
print(json.dumps({'reads':reads,'connections':connections,'identities':identities,'default_verifier_logins':default_verifier_logins}))
'''

def digest(path): return hashlib.sha256(path.read_bytes()).hexdigest()
def require(condition, message):
    if not condition: raise RuntimeError(message)
def run(argv, env, timeout=30):
    p = subprocess.run([str(x) for x in argv], env=env, text=True, capture_output=True, timeout=timeout)
    if p.returncode: raise RuntimeError(f'command failed ({p.returncode}): {argv[0:2]}: {p.stderr}')
    return p.stdout

async def worker(proxy_port, fixture_port, verifier_port, paths, env):
    version = run([*PODMAN,'--version'],env).strip()
    if run([*PODMAN,'info','--format','{{.Host.Security.Rootless}}'],env).strip() != 'true': raise RuntimeError('rootless Podman required')
    image = run([*PODMAN,'image','inspect','--format','{{.Id}}','docker.io/library/python:3.12-alpine'],env).strip()
    if len(image) != 64 or any(c not in '0123456789abcdef' for c in image): raise RuntimeError('invalid image ID')
    async def relay(reader, writer):
        try:
            rr, rw = await asyncio.open_connection('127.0.0.1',proxy_port)
            async def copy(src,dst):
                try:
                    while chunk := await src.read(65536):
                        dst.write(chunk); await dst.drain()
                finally: dst.close()
            await asyncio.gather(copy(reader,rw),copy(rr,writer))
        except (OSError,ConnectionError): writer.close()
    with tempfile.TemporaryDirectory(prefix='scourge-topology-gateway-') as directory:
        gateway = Path(directory)/'gateway'; gateway.mkdir()
        server = await asyncio.start_unix_server(relay,path=str(gateway/'proxy.sock'))
        os.chmod(gateway/'proxy.sock',0o600); name = 'scourge-topology-'+secrets.token_hex(16)
        cidfile = Path(directory)/'container.cid'
        command = [*PODMAN,'run','--pull=never','--network=none','--read-only','--name',name,'--cidfile',str(cidfile),
                   '--http-proxy=false','--cap-drop=all','--security-opt=no-new-privileges','--pids-limit=64',
                   '--mount',f'type=bind,src={gateway},dst=/gateway,ro=true','--entrypoint','python3',image,
                   '-I','-c',WORKER,str(fixture_port),str(verifier_port),*map(str,paths)]
        process = None
        parent = os.getppid()
        task = asyncio.current_task()
        async def watch_parent():
            while os.getppid() == parent:
                await asyncio.sleep(.2)
            task.cancel()
        watcher = asyncio.create_task(watch_parent())
        try:
            process = await asyncio.create_subprocess_exec(*command,env=env,stdout=asyncio.subprocess.PIPE,stderr=asyncio.subprocess.PIPE)
            stdout, stderr = await asyncio.wait_for(process.communicate(),90)
            if process.returncode: raise RuntimeError('worker failed: '+stderr.decode(errors='replace'))
            result = json.loads(stdout)
        finally:
            watcher.cancel()
            if process and process.returncode is None:
                process.terminate()
                try: await asyncio.wait_for(process.wait(),5)
                except asyncio.TimeoutError: process.kill(); await process.wait()
            server.close(); await server.wait_closed()
            if not cidfile.is_file():
                raise RuntimeError('container ID unavailable; no container removed; inspect manually: '+name)
            cid = cidfile.read_text().strip()
            if len(cid) != 64 or any(c not in '0123456789abcdef' for c in cid):
                raise RuntimeError('invalid container ID; no container removed; inspect manually: '+name)
            run([*PODMAN,'rm','--force','--ignore',cid],env)
            p = subprocess.run([*PODMAN,'container','exists',cid],env=env,timeout=30)
            if p.returncode != 1: raise RuntimeError('container removal not verified: '+cid)
        require(all(x['refused'] for x in result['reads']), 'protected path visible')
        require(all(x['refused'] for x in result['connections'].values()), 'direct connection succeeded')
        require(result['identities'] == [{'name':n,'status':200,'id':'user-'+n} for n in ('alice','bob')], 'exploration identity mismatch')
        require(result['default_verifier_logins'] == [{'name':n,'status':401} for n in ('alice-verify','bob-verify')], 'default verifier login succeeded')
        result.update({'podman':version,'image_id':image,'network':'none','gateway':'read-only Unix relay to exploration proxy only','container_removed':True})
        return result

class GuardedTemp:
    def __init__(self):
        self.temp = tempfile.TemporaryDirectory(prefix='scourge-topology-')
        self.keep = True
    def __enter__(self): return self.temp.name
    def __exit__(self, *_):
        if self.keep:
            self.temp._finalizer.detach()
            print('Cleanup incomplete; retained private directory: '+self.temp.name, file=__import__('sys').stderr)
        else: self.temp.cleanup()

def main():
    parent = os.getppid()
    def watch_parent():
        while os.getppid() == parent:
            time.sleep(.2)
        os.kill(os.getpid(), signal.SIGTERM)
    threading.Thread(target=watch_parent, daemon=True).start()
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--teapot',type=Path,required=True); parser.add_argument('--hallpass',type=Path,required=True)
    args = parser.parse_args(); teapot = args.teapot.resolve(); hallpass = args.hallpass.resolve()
    if digest(teapot) != PIN: raise RuntimeError('Teapot binary does not match pinned contract')
    if digest(hallpass) != HALLPASS_PIN: raise RuntimeError('Hallpass binary does not match observed experiment')
    guard = GuardedTemp()
    with guard as temp:
        root = Path(temp); agent = root/'agent'; agent.mkdir()
        env = dict(os.environ,HOME=temp,XDG_CONFIG_HOME=str(root/'config'),XDG_STATE_HOME=str(root/'state'),XDG_DATA_HOME=str(root/'data'),NO_COLOR='1',CARGO_NET_OFFLINE='true',CARGO_BUILD_JOBS='2')
        for k in ('TEAPOT_PASS','TEAPOT_ENFORCED','TEAPOT_PLAYPEN','TEAPOT_DETACHED','CONTAINER_HOST','CONTAINER_CONNECTION','CONTAINER_SSHKEY','DOCKER_HOST'): env.pop(k,None)
        hostenv = dict(os.environ, CARGO_NET_OFFLINE='true', CARGO_BUILD_JOBS='2')
        for k in ('CONTAINER_HOST','CONTAINER_CONNECTION','CONTAINER_SSHKEY','DOCKER_HOST'): hostenv.pop(k,None)
        log = (root/'fixture.log').open('w+')
        fixture = subprocess.Popen(['python3','-I',str(ROOT/'fixtures/target/package.py'),'--package-dir',str(root/'fixture'),'--agent-tree',str(agent),'--port','0','--private-verifiers'],env=hostenv,stdout=subprocess.DEVNULL,stderr=log,start_new_session=True)
        started = []; projects = [root/'exploration',root/'verifier']
        def tp(i,*words): return json.loads(run([teapot,'--project',projects[i],'--json',*words],env))
        def interrupt(_sig, _frame): raise KeyboardInterrupt()
        old_term = signal.signal(signal.SIGTERM, interrupt)
        try:
            port = None
            for _ in range(600):
                log.flush(); content = (root/'fixture.log').read_text(); match = re.search(r'fixture\s+listening\s+http://127\.0\.0\.1:(\d+)',content)
                if match: port = int(match.group(1)); break
                if fixture.poll() is not None: raise RuntimeError('fixture failed: '+content[-4000:])
                time.sleep(.2)
            if not port: raise RuntimeError('fixture start timeout')
            passfile = root/'local.pass.toml'; run([hallpass,'init',passfile],env)
            now = dt.datetime.now(dt.timezone.utc); stamp = lambda t: t.strftime('%Y-%m-%dT%H:%M:%SZ')
            passfile.write_text(f'''format = 1
id = "scourge-candidate"
name = "Local candidate experiment"
[approval]
owner = "local experiment"
reference = "bn-34o"
operator = "local experiment"
valid_from = {stamp(now-dt.timedelta(hours=1))}
valid_until = {stamp(now+dt.timedelta(days=1))}
revoked = false
[[destination]]
label = "fixture"
address = "127.0.0.1"
protocol = "tcp"
ports = {port}
[ceilings]
requests = 100
'''); passfile.chmod(0o600)
            run([hallpass,'check',passfile,'--json'],env); listeners = []
            for i,p in enumerate(projects):
                p.mkdir(); tp(i,'projects','init'); tp(i,'pass','attach',str(passfile))
                started.append(i)
                start = tp(i,'proxy','start','--listen','127.0.0.1:0','--detach','--pass',str(passfile),'--no-enforce')
                listeners.append(int(start['proxy']['engine']['listener'].rsplit(':',1)[1])); tp(i,'scope','add','127.0.0.1')
            import urllib.request
            secret = (root/'fixture'/'admin-secret').read_text().strip()
            request = urllib.request.Request(f'http://127.0.0.1:{port}/app/_reset', method='POST', headers={'X-Fixture-Admin-Secret':secret})
            with urllib.request.build_opener(urllib.request.ProxyHandler({})).open(request,timeout=10) as response:
                require(response.status == 204, 'reset failed')
            passwords = json.loads((root/'fixture'/'verifier-passwords.json').read_text())
            require((root/'fixture'/'verifier-passwords.json').stat().st_mode & 0o777 == 0o600, 'verifier password file is not private')
            require(len(passwords) == 2 and passwords[0] != passwords[1] and all(len(p) == 64 for p in passwords), 'invalid generated verifier passwords')
            for name, password in zip(('alice-verify','bob-verify'),passwords):
                tp(1,'sessions','create',name)
                login = tp(1,'requests','send','POST',f'http://127.0.0.1:{port}/app/login','--session',name,'--header','Content-Type: application/json','--body',json.dumps({'username':name,'password':password}))
                require(login['sent']['status'] == 200, 'verifier login failed after reset')
            sent = tp(1,'requests','send','GET',f'http://127.0.0.1:{port}/app/api/me','--session','alice-verify')['sent']
            flow = tp(1,'flows','show',str(sent['flow']),'--part','response')['flow']
            require(sent['status'] == 200 and json.loads(flow['response_body'])['id'] == 'user-alice-verify', 'verifier flow mismatch')
            paths = [root/'fixture'/'ground-truth.json',ROOT/'fixtures/target/src/main.rs',root/'fixture'/'admin-secret',root/'fixture'/'verifier-passwords.json',projects[0]/'.teapot',projects[1]/'.teapot',passfile]
            require(all(p.exists() and os.access(p,os.R_OK) for p in paths), 'referee cannot read protected path')
            result = asyncio.run(worker(listeners[0],port,listeners[1],paths,hostenv))
            ledger = json.loads(run([hallpass,'ledger',passfile,'--json'],env)); require(ledger['verified'], 'ledger verification failed')
            health = [tp(i,'proxy','status')['proxy']['health']['requests'] for i in range(2)]
            observation = {'scenario':'private verifier topology, loopback only', 'exit_code':0,
                           'script_sha256':digest(Path(__file__).resolve()),
                           'teapot_sha256':digest(teapot),'hallpass_sha256':digest(hallpass),
                           'fixture_sha256':digest(root/'fixture'/'scourge-fixture'),
                           'worker':result,'verifier':{'sessions':['alice-verify','bob-verify'],'flow_id':sent['flow'],'status':sent['status'],'subject':'user-alice-verify'},
                           'ledger_verified':ledger['verified'],'ledger_totals':ledger['totals'],
                           'project_requests':health,'enforced':False}
        finally:
            cleanup_errors = []
            for i in reversed(started):
                try:
                    if tp(i,'proxy','status')['proxy']['running']:
                        tp(i,'proxy','stop')
                    require(tp(i,'proxy','status')['proxy']['running'] is False, 'engine still running')
                except Exception as e: cleanup_errors.append(str(e))
            if fixture.poll() is None:
                os.killpg(fixture.pid,signal.SIGTERM)
                try: fixture.wait(timeout=10)
                except subprocess.TimeoutExpired: os.killpg(fixture.pid,signal.SIGKILL); fixture.wait()
            log.close()
            signal.signal(signal.SIGTERM, old_term)
            if cleanup_errors:
                guard.keep = True
                raise RuntimeError('engine cleanup failed: '+ '; '.join(cleanup_errors))
            guard.keep = False
    print(json.dumps(observation,indent=2),flush=True)
if __name__ == '__main__': main()
