// In-worker connector. The worker has --network=none, so the only reachable
// services are loopback listeners created here. Each listener forwards to a
// referee-owned Unix-socket relay mounted read-only at /gateway:
//
//   M0_PROXY_PORT  -> /gateway/proxy.sock   (optional pinned Teapot proxy)
//   18080          -> /gateway/model.sock   (host-owned pinned Responses relay)
//
// The baseline entrypoint sets M0_PROXY_PORT and gets both listeners. The
// native Codex boundary deliberately leaves it unset and reuses this forwarder
// in model-only mode. The script writes nothing to stdout.
const net = require('net');

const listeners = [
  [18080, '/gateway/model.sock'],
];
const proxyText = process.env.M0_PROXY_PORT;
if (proxyText !== undefined && proxyText !== '') {
  const proxyPort = Number(proxyText);
  if (!Number.isInteger(proxyPort) || proxyPort < 1 || proxyPort > 65535) {
    process.stderr.write('M0_PROXY_PORT is not a valid port\n');
    process.exit(2);
  }
  listeners.unshift([proxyPort, '/gateway/proxy.sock']);
}

for (const [port, path] of listeners) {
  net
    .createServer((client) => {
      const upstream = net.connect(path);
      const close = () => {
        client.destroy();
        upstream.destroy();
      };
      client.on('error', close);
      upstream.on('error', close);
      client.pipe(upstream).pipe(client);
    })
    .on('error', (error) => {
      process.stderr.write(`listener ${port}: ${error.message}\n`);
      process.exit(1);
    })
    .listen(port, '127.0.0.1');
}

// Exit only when the worker entrypoint signals; a timer keeps the process
// alive without ever touching stdout.
setInterval(() => {}, 1 << 30);
