#!/usr/bin/env python3
"""Capture or check Teapot contracts against the inventory's exact binary digest."""
import argparse
import hashlib
import http.server
import json
import pathlib
import subprocess
import tempfile
import threading

ROOT = pathlib.Path(__file__).resolve().parents[1]
OUT = ROOT / 'fixtures/contracts'
COMMANDS = ['version', 'proxy status', 'sessions check', 'requests send', 'flows show',
            'macros run', 'flows replay', 'pass show', 'jobs list', 'jobs stop',
            'rules list', 'intercept status', 'intercept rules list', 'scripts list',
            'sessions show', 'config list']

class Handler(http.server.BaseHTTPRequestHandler):
    def do_GET(self):
        self.send_response(200)
        self.send_header('Content-Type', 'application/json')
        self.end_headers()
        self.wfile.write(b'{"id":"fixture"}')
    def do_POST(self):
        self.rfile.read(int(self.headers.get('Content-Length', '0')))
        self.send_response(201)
        self.send_header('Content-Type', 'application/json')
        self.end_headers()
        self.wfile.write(b'{"id":"created"}')
    def log_message(self, *_args):
        pass

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--capture', action='store_true', help='replace captured fixtures')
    parser.add_argument('--binary', type=pathlib.Path, required=True)
    args = parser.parse_args()
    binary = args.binary.resolve()
    inventory = json.loads((ROOT / 'docs/inventory.json').read_text())
    manifest = json.loads((OUT / 'manifest.json').read_text())
    teapot = next(x for x in inventory['tools'] if x['tool'] == 'teapot')
    assert teapot['checkout']['head'] == manifest['source_commit'], 'source pin differs from inventory'
    assert hashlib.sha256(binary.read_bytes()).hexdigest() == manifest['binary_sha256'], 'Teapot digest differs from contract manifest'
    OUT.mkdir(parents=True, exist_ok=True)
    captures = {}
    def invoke(name, words, *, project=None, expected_exit=0):
        argv = [str(binary)] + (['--project', str(project)] if project else []) + ['--json'] + words
        result = subprocess.run(argv, capture_output=True, text=True, timeout=30)
        if result.returncode != expected_exit:
            raise RuntimeError(f'{name}: exit {result.returncode}: {result.stdout} {result.stderr}')
        data = json.loads(result.stdout if result.stdout else result.stderr)
        captures[name] = {'argv': argv[1:], 'exit_code': result.returncode, 'output': data}
        return data
    for command in COMMANDS:
        invoke('schema-' + command.replace(' ', '-'), ['schema', *command.split()])
    server = http.server.ThreadingHTTPServer(('127.0.0.1', 0), Handler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    url = f'http://127.0.0.1:{server.server_port}'
    try:
        with tempfile.TemporaryDirectory(prefix='scourge-contract-') as directory:
            project = pathlib.Path(directory)
            def run(name, *words):
                return invoke(name, list(words), project=project)
            run('setup-project', 'projects', 'init')
            try:
                run('setup-engine', 'proxy', 'start', '--listen', '127.0.0.1:0', '--detach')
                run('setup-scope', 'scope', 'add', '127.0.0.1')
                run('setup-session', 'sessions', 'create', 'alice')
                macro = project / '.teapot/macros/plant.toml'
                macro.write_text('format = 1\n\n[[steps]]\nstate_changing = false\n[steps.request]\nmethod = "GET"\nurl = "' + url + '/probe"\n\n[[steps]]\nstate_changing = true\n[steps.request]\nmethod = "POST"\nurl = "' + url + '/plant"\nbody = { text = "plant" }\n')
                run('describe', 'version')
                run('describe-status', 'proxy', 'status')
                check = run('check-session', 'sessions', 'check', 'alice', '--url', url + '/probe')
                assert check['check']['state'] == 'unknown' and check['check']['units'] == 2
                sent = run('send', 'requests', 'send', 'GET', url + '/probe', '--session', 'alice')
                flow = sent['sent']['flow']
                read = run('read-flow', 'flows', 'show', str(flow), '--base64', '--stored')
                assert read['flow']['id'] == flow and read['flow']['response_body_info']['whole']
                dry = run('dry-run', 'macros', 'run', 'plant', '--session', 'alice', '--dry-run')
                assert dry['run']['dry_run'] and dry['run']['units'] == 2
                macro_result = run('macro-send', '--yes', 'macros', 'run', 'plant', '--session', 'alice')
                assert macro_result['run']['outcome'] == 'completed' and len(macro_result['run']['steps']) == 2
                assert all(isinstance(step['flow'], int) for step in macro_result['run']['steps'])
                assert run('units-left', 'pass', 'show')['pass']['state'] == 'unbound'
                assert any(job['id'] == macro_result['run']['job'] for job in run('list-jobs', 'jobs', 'list')['jobs'])
                assert run('cancel', 'jobs', 'stop', '--all')['stopped']['jobs'] == []
                for name, words in [('edit-rules', ('rules', 'list')), ('edit-intercept', ('intercept', 'status')),
                                    ('edit-intercept-rules', ('intercept', 'rules', 'list')),
                                    ('edit-scripts', ('scripts', 'list')), ('edit-session', ('sessions', 'show', 'alice')),
                                    ('edit-config', ('config', 'list'))]:
                    run(name, *words)
            finally:
                run('cleanup-engine', 'proxy', 'stop')
    finally:
        server.shutdown()
        server.server_close()
        thread.join()
    if args.capture:
        for name, data in captures.items():
            (OUT / (name + '.json')).write_text(json.dumps(data, indent=2, sort_keys=True) + '\n')
    else:
        for name, data in captures.items():
            saved = json.loads((OUT / (name + '.json')).read_text())
            assert saved['exit_code'] == data['exit_code']
            assert set(saved['output']) == set(data['output']), name
            if name.startswith('schema-'):
                assert saved['output'] == data['output'], name
    print(f'{"captured" if args.capture else "checked"} {len(captures)} contracts')

if __name__ == '__main__':
    main()
