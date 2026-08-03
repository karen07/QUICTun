#!/bin/sh

OUTDIR="${OUTDIR:-systemd}"
CLIENTS="${CLIENTS:-32}"

QUICTUN_BIN="${QUICTUN_BIN:-/usr/bin/QUICTun}"
QUICTUN_DIR="${QUICTUN_DIR:-/etc/QUICTun}"

SERVER_CONF="${SERVER_CONF:-$QUICTUN_DIR/server.conf}"
CLIENT_CONF_PREFIX="${CLIENT_CONF_PREFIX:-$QUICTUN_DIR/client}"

SERVER_WG_PREFIX="${SERVER_WG_PREFIX:-server}"
CLIENT_WG_PREFIX="${CLIENT_WG_PREFIX:-client}"

SERVICE_NAME_PREFIX="${SERVICE_NAME_PREFIX:-QUICTun}"

need_cmd() {
    command -v "$1" >/dev/null 2>&1 || {
        echo "Command not found: $1" >&2
        exit 1
    }
}

need_cmd mkdir
need_cmd rm

rm -rf "$OUTDIR"
mkdir -p "$OUTDIR"

# ===== Server unit =====
server_unit="$OUTDIR/${SERVICE_NAME_PREFIX}-server.service"

{
    echo "[Unit]"
    echo "Description=QUICTun Server"
    echo "Wants=network-online.target"
    echo "After=network-online.target"
    echo ""

    i=1
    while [ "$i" -le "$CLIENTS" ]; do
        echo "Wants=wg-quick@${SERVER_WG_PREFIX}${i}.service"
        i=$((i + 1))
    done

    echo ""

    i=1
    while [ "$i" -le "$CLIENTS" ]; do
        echo "After=wg-quick@${SERVER_WG_PREFIX}${i}.service"
        i=$((i + 1))
    done

    echo ""
    echo "[Service]"
    echo "Type=simple"
    echo "ExecStart=${QUICTUN_BIN} ${SERVER_CONF}"
    echo "Restart=on-failure"
    echo "RestartSec=1"
    echo "TimeoutStopSec=5"
    echo "StandardOutput=journal"
    echo "StandardError=journal"
    echo ""
    echo "[Install]"
    echo "WantedBy=multi-user.target"
} >"$server_unit"

# ===== Client units =====
i=1
while [ "$i" -le "$CLIENTS" ]; do
    client_unit="$OUTDIR/${SERVICE_NAME_PREFIX}-client${i}.service"

    {
        echo "[Unit]"
        echo "Description=QUICTun Client ${i}"
        echo "Wants=network-online.target"
        echo "After=network-online.target"
        echo "Wants=wg-quick@${CLIENT_WG_PREFIX}${i}.service"
        echo "After=wg-quick@${CLIENT_WG_PREFIX}${i}.service"
        echo ""
        echo "[Service]"
        echo "Type=simple"
        echo "ExecStart=${QUICTUN_BIN} ${CLIENT_CONF_PREFIX}${i}.conf"
        echo "Restart=on-failure"
        echo "RestartSec=1"
        echo "TimeoutStopSec=5"
        echo "StandardOutput=journal"
        echo "StandardError=journal"
        echo ""
        echo "[Install]"
        echo "WantedBy=multi-user.target"
    } >"$client_unit"

    i=$((i + 1))
done

echo "Systemd units generated in: $OUTDIR"
