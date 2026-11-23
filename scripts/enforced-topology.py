#!/usr/bin/env python3
"""Disposable enforcement probe; stdout is a JSONL evidence log."""
import argparse
import datetime as dt
import hashlib
import json
import os
from pathlib import Path
import re
import subprocess
import tempfile
import urllib.request

parser = argparse.ArgumentParser()
for name in ('teapot', 'hallpass', 'playpen', 'fixture'):
    parser.add_argument('--' + name, required=True, type=Path)
parser.add_argument('--address', required=True)
args = parser.parse_args()
bins = {n: getattr(args, n).resolve() for n in ('teapot', 'hallpass', 'playpen', 'fixture')}
print(json.dumps({'binaries': {n: hashlib.sha256(p.read_bytes()).hexdigest() for n, p in bins.items()}, 'address': args.address}), flush=True)
with tempfile.TemporaryDirectory(prefix='scourge-topology-') as tmp:
    root = Path(tmp)
    env = dict(os.environ, HOME=tmp, XDG_CONFIG_HOME=tmp+'/config', XDG_STATE_HOME=tmp+'/state', XDG_DATA_HOME=tmp+'/data', TEAPOT_PLAYPEN=str(bins['playpen']), NO_COLOR='1')
    for key in ('TEAPOT_PASS', 'TEAPOT_ENFORCED', 'TEAPOT_DETACHED'):
        env.pop(key, None)
    def run(label, argv):
        try:
            p = subprocess.run(list(map(str, argv)), env=env, capture_output=True, text=True, timeout=40)
            result = {'step': label, 'argv': list(map(str, argv)), 'exit': p.returncode, 'stdout': p.stdout, 'stderr': p.stderr}
        except subprocess.TimeoutExpired as e:
            result = {'step': label, 'timeout': True, 'stdout': str(e.stdout), 'stderr': str(e.stderr)}
        print(json.dumps(result), flush=True)
        return result
    server = subprocess.Popen([str(bins['fixture']), '--listen', args.address+':0', '--admin-secret', 'disposable-secret'], env=env, stdout=subprocess.DEVNULL, stderr=subprocess.PIPE, text=True)
    started = False
    project = root / 'project'
    project.mkdir()
    try:
        line = server.stderr.readline()
        print(json.dumps({'step':'fixture', 'stderr':line}), flush=True)
        match = re.search(r'(\d+\.\d+\.\d+\.\d+):(\d+)', line)
        if not match:
            raise RuntimeError('fixture did not report its listening address')
        port = int(match.group(2))
        login_url = f'http://{args.address}:{port}/app/login'
        login_body = '{"username":"alice","password":"alice-password"}'
        request = urllib.request.Request(login_url, data=login_body.encode(), headers={'Content-Type':'application/json'})
        with urllib.request.build_opener(urllib.request.ProxyHandler({})).open(request, timeout=5) as response:
            print(json.dumps({'step': 'direct-fixture', 'status': response.status}), flush=True)
        passfile = root / 'local.pass.toml'
        now = dt.datetime.now(dt.timezone.utc)
        stamp = lambda t: t.strftime('%Y-%m-%dT%H:%M:%SZ')
        passfile.write_text(f'''format = 1
id = "scourge-topology"
name = "Disposable local topology"
[approval]
owner = "local experiment"
reference = "bn-qpi"
operator = "local experiment"
valid_from = {stamp(now - dt.timedelta(hours=1))}
valid_until = {stamp(now + dt.timedelta(hours=1))}
revoked = false
[[destination]]
label = "fixture"
address = "{args.address}"
protocol = "tcp"
ports = {port}
[ceilings]
requests = 100
''')
        passfile.chmod(0o600)
        print(json.dumps({'step':'pass', 'contents':passfile.read_text(), 'sha256':hashlib.sha256(passfile.read_bytes()).hexdigest()}), flush=True)
        run('check', [bins['hallpass'], 'check', passfile, '--json'])
        def tp(*cmd): return run(' '.join(cmd), [bins['teapot'], '--project', project, '--json', *cmd])
        tp('projects', 'init')
        tp('pass', 'attach', str(passfile))
        result = tp('proxy', 'start', '--listen', '127.0.0.1:0', '--detach', '--pass', str(passfile), '--enforce')
        started = result.get('exit') == 0
        if started:
            tp('scope', 'add', args.address)
            tp('pass', 'show')
            tp('proxy', 'status')
            tp('requests', 'send', 'POST', login_url, '--header', 'Content-Type: application/json', '--body', login_body)
            tp('requests', 'send', 'GET', f'http://{args.address}:{port+1 if port < 65535 else port-1}/outside')
        run('ledger', [bins['hallpass'], 'ledger', passfile, '--json'])
    finally:
        if started:
            tp('proxy', 'stop')
            run('ledger-after-stop', [bins['hallpass'], 'ledger', passfile, '--json'])
        server.terminate()
        server.wait(timeout=10)
