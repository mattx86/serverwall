#!/bin/bash
set -e

CONFIG=/opt/serverwall/etc/serverwall.toml

# First-run initialisation (idempotent — skips files that already exist)
if [ ! -f "$CONFIG" ]; then
    echo "[entrypoint] Running first-time init..."
    /opt/serverwall/bin/serverwall --init
    chown -R serverwall: /opt/serverwall
fi

echo "[entrypoint] Starting serverwall proxy..."
su -s /bin/bash serverwall -c \
    "RUST_LOG=${RUST_LOG:-info} /opt/serverwall/bin/serverwall \
        --config /opt/serverwall/etc/serverwall.toml" &
PROXY_PID=$!

echo "[entrypoint] Starting serverwall-webui..."
su -s /bin/bash serverwall -c \
    "RUST_LOG=${RUST_LOG:-info} /opt/serverwall/bin/serverwall-webui \
        --config /opt/serverwall/etc/serverwall.toml" &
WEBUI_PID=$!

# Wait for either process to exit
wait -n $PROXY_PID $WEBUI_PID
echo "[entrypoint] A service exited. Stopping container."
kill $PROXY_PID $WEBUI_PID 2>/dev/null || true
