// In-worker connector. The worker has --network=none, so the only reachable
// services are loopback listeners created here. Each listener forwards to a
// referee-owned Unix-socket relay mounted read-only at /gateway:
//
//   PROXY_PORT     -> /gateway/proxy.sock   (the pinned Teapot proxy listener)
//   18080          -> /gateway/model.sock   (CONNECT tunnel to the pinned model API)
//
// The script is started by entry.sh and writes nothing to stdout.
const net = require('net');

const proxyPort = Number(process.env.M0_PROXY_PORT || '0');
if (!Number.isInteger(proxyPort) || proxyPort < 1 || proxyPort > 65535) {
  process.stderr.write('M0_PROXY_PORT is not a valid port\n');
  process.exit(2);
}

const listeners = [
  [proxyPort, '/gateway/proxy.sock'],
  [18080, '/gateway/model.sock'],
];

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
