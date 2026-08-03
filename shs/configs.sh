#!/bin/sh

CERTS_DIR="${CERTS_DIR:-certs}"
OUTDIR="${OUTDIR:-configs}"
CLIENTS="${CLIENTS:-32}"

QUIC_SERVER_IP="${QUIC_SERVER_IP:-0.0.0.0}"
QUIC_SERVER_PORT="${QUIC_SERVER_PORT:-443}"

WG_SERVER_IP="${WG_SERVER_IP:-127.0.0.1}"
WG_SERVER_BASE_PORT="${WG_SERVER_BASE_PORT:-60000}"

WG_CLIENT_LISTEN_IP="${WG_CLIENT_LISTEN_IP:-127.0.0.1}"
WG_CLIENT_LISTEN_PORT="${WG_CLIENT_LISTEN_PORT:-60000}"

SNI="${SNI:-example.com}"
SERVER_CERTS_PATH="${SERVER_CERTS_PATH:-/etc/QUICTun/server}"
CLIENT_CERTS_PREFIX="${CLIENT_CERTS_PREFIX:-/etc/QUICTun/client}"
PEER_NAME_PREFIX="${PEER_NAME_PREFIX:-client}"

SERVER_LOG_PATH="${SERVER_LOG_PATH:-/var/log/QUICTun_log.txt}"
SERVER_STAT_PATH="${SERVER_STAT_PATH:-/var/log/QUICTun_stat.txt}"

CLIENT_LOG_PATH="${CLIENT_LOG_PATH:-/var/log/QUICTun_log.txt}"
CLIENT_STAT_PATH="${CLIENT_STAT_PATH:-/var/log/QUICTun_stat.txt}"

need_cmd() {
    command -v "$1" >/dev/null 2>&1 || {
        echo "Command not found: $1" >&2
        exit 1
    }
}

cert_hash_b64() {
    cert_path="$1"
    openssl x509 -in "$cert_path" -outform DER \
        | openssl dgst -sha256 -binary \
        | openssl base64 -A
}

need_cmd openssl
need_cmd mkdir
need_cmd rm

rm -rf "$OUTDIR"
mkdir -p "$OUTDIR"

# ===== Server config =====
cat >"$OUTDIR/server.conf" <<EOF
[Interface]
    QuicListen = $QUIC_SERVER_IP:$QUIC_SERVER_PORT
    CertsPath = $SERVER_CERTS_PATH
    LogPath = $SERVER_LOG_PATH
    StatPath = $SERVER_STAT_PATH
    SNI = $SNI
EOF

# ===== Client configs + server peers =====
i=1
while [ "$i" -le "$CLIENTS" ]; do
    cert_path="$CERTS_DIR/client$i/cert.pem"
    if [ ! -f "$cert_path" ]; then
        echo "Missing certificate: $cert_path" >&2
        exit 1
    fi

    hash="$(cert_hash_b64 "$cert_path")"
    wg_server_port=$((WG_SERVER_BASE_PORT + i - 1))
    peer_name="${PEER_NAME_PREFIX}${i}"

    cat >>"$OUTDIR/server.conf" <<EOF

# $peer_name
[Peer]
    PeerCertSHA256 = $hash
    WgEndpoint = $WG_SERVER_IP:$wg_server_port
EOF

    cat >"$OUTDIR/client$i.conf" <<EOF
[Interface]
    QuicEndpoint = $QUIC_SERVER_IP:$QUIC_SERVER_PORT
    WgListen = $WG_CLIENT_LISTEN_IP:$WG_CLIENT_LISTEN_PORT
    CertsPath = ${CLIENT_CERTS_PREFIX}$i
    LogPath = $CLIENT_LOG_PATH
    StatPath = $CLIENT_STAT_PATH
    SNI = $SNI
EOF

    i=$((i + 1))
done

echo "QUICTun configs generated in: $OUTDIR"
