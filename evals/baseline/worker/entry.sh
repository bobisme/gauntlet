#!/bin/bash
# Worker entrypoint for one scored M0.4 baseline session.
#
# Runs entirely inside the rootless, network-disabled, read-only boundary. The
# only host state it can reach is what the runner mounted: the fresh Teapot
# project/runtime, the frozen visible inputs, the read-only auth file for the
# model client, and the two referee-owned relays under /gateway.
set -uo pipefail

export PATH=/opt/adapter/bin:/opt/node/bin:/usr/bin:/bin
export NO_COLOR=1
export TERM=dumb
export PI_OFFLINE=1
export PI_SKIP_VERSION_CHECK=1
export PI_TELEMETRY=0
export PI_CODING_AGENT_DIR=/pi-agent
export HOME=/home/pi

node /opt/adapter/forward.js &
forward_pid=$!
trap 'kill "$forward_pid" 2>/dev/null; wait "$forward_pid" 2>/dev/null' EXIT

# Wait for both loopback listeners without using tools the agent might shadow.
for _ in $(seq 1 100); do
  if node -e '
    const net=require("net");
    let ok=0,total=2;
    for (const p of [Number(process.env.M0_PROXY_PORT),18080]) {
      const s=net.connect(p,"127.0.0.1");
      s.on("connect",()=>{s.destroy();if(++ok===total)process.exit(0)});
      s.on("error",()=>process.exit(1));
    }
    setTimeout(()=>process.exit(1),500);
  ' >/dev/null 2>&1; then
    break
  fi
  sleep 0.1
done

cd /workspace
exec /opt/node/bin/node /opt/pi/dist/bundle/cli.js \
  --provider orcacyber \
  --model orca/orcacyber-flash-1.0 \
  --thinking high \
  --mode json \
  --print \
  --no-session \
  --no-extensions \
  --no-mcp \
  --no-skills \
  --no-context-files \
  --no-prompt-templates \
  --no-themes \
  --no-approve \
  --tools bash \
  "$(cat /workspace/task.txt)"
