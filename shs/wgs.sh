#!/bin/sh

OUTDIR="${OUTDIR:-wgs}"
CLIENTS="${CLIENTS:-32}"

WG_ENDPOINT_IP="${WG_ENDPOINT_IP:-127.0.0.1}"
WG_BASE_PORT="${WG_BASE_PORT:-60000}"

NET_A="${NET_A:-10}"
NET_B="${NET_B:-10}"

MTU="${MTU:-1340}"
PERSISTENT_KEEPALIVE="${PERSISTENT_KEEPALIVE:-1}"

need_cmd() {
    command -v "$1" >/dev/null 2>&1 || {
        echo "Command not found: $1" >&2
        exit 1
    }
}

ip4_from_index() {
    idx="$1"
    third=$((idx / 256))
    fourth=$((idx % 256))
    printf "%s.%s.%s.%s" "$NET_A" "$NET_B" "$third" "$fourth"
}

ip6_from_index() {
    idx="$1"
    third=$((idx / 256))
    fourth=$((idx % 256))
    printf "fe80::%s:%s:%s:%s" "$NET_A" "$NET_B" "$third" "$fourth"
}

need_cmd wg
need_cmd mkdir
need_cmd rm

rm -rf "$OUTDIR"
mkdir -p "$OUTDIR"

i=1
while [ "$i" -le "$CLIENTS" ]; do
    base=$(((i - 1) * 2))

    srv_host=$base
    cli_host=$((base + 1))

    srv_ip4="$(ip4_from_index "$srv_host")"
    cli_ip4="$(ip4_from_index "$cli_host")"

    srv_ip6="$(ip6_from_index "$srv_host")"
    cli_ip6="$(ip6_from_index "$cli_host")"

    srv_port=$((WG_BASE_PORT + i - 1))

    srv_priv="$(wg genkey)"
    srv_pub="$(printf '%s' "$srv_priv" | wg pubkey)"

    cli_priv="$(wg genkey)"
    cli_pub="$(printf '%s' "$cli_priv" | wg pubkey)"

    # ===== Server WG config =====
    cat >"$OUTDIR/server$i.conf" <<EOF
[Interface]
    PrivateKey = $srv_priv
    Address = $srv_ip4/31, $srv_ip6/64
    ListenPort = $srv_port
    MTU = $MTU
    Table = off

[Peer]
    PublicKey = $cli_pub
    AllowedIPs = 0.0.0.0/0, ::/0
    PersistentKeepalive = $PERSISTENT_KEEPALIVE
EOF

    # ===== Client WG config =====
    cat >"$OUTDIR/client$i.conf" <<EOF
[Interface]
    PrivateKey = $cli_priv
    Address = $cli_ip4/31, $cli_ip6/64
    MTU = $MTU
    Table = off

[Peer]
    PublicKey = $srv_pub
    Endpoint = $WG_ENDPOINT_IP:$WG_BASE_PORT
    AllowedIPs = 0.0.0.0/0, ::/0
    PersistentKeepalive = $PERSISTENT_KEEPALIVE
EOF

    # ===== OpenWrt client UCI =====
    cat >"$OUTDIR/openwrt-client$i.uci" <<EOF
config interface 'VPN'
    option proto 'wireguard'
    option private_key '$cli_priv'
    list addresses '$cli_ip4/31'
    list addresses '$cli_ip6/64'
    option defaultroute '0'
    option mtu '$MTU'

config wireguard_VPN
    option description 'server$i.conf'
    option public_key '$srv_pub'
    option route_allowed_ips '1'
    list allowed_ips '0.0.0.0/0'
    list allowed_ips '::/0'
    option persistent_keepalive '$PERSISTENT_KEEPALIVE'
    option endpoint_host '$WG_ENDPOINT_IP'
    option endpoint_port '$WG_BASE_PORT'
EOF

    i=$((i + 1))
done

echo "WG configs generated in: $OUTDIR"
