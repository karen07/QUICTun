#!/bin/sh

OUTDIR="${OUTDIR:-certs}"
CLIENTS="${CLIENTS:-32}"
CA_CN="${CA_CN:-Root CA}"
SERVER_CN="${SERVER_CN:-example.com}"
CLIENT_CN_PREFIX="${CLIENT_CN_PREFIX:-client}"
DAYS="${DAYS:-3650}"

need_cmd() {
    command -v "$1" >/dev/null 2>&1 || {
        echo "Command not found: $1" >&2
        exit 1
    }
}

need_cmd openssl
need_cmd mkdir
need_cmd rm
need_cmd cp

rm -rf "$OUTDIR"
mkdir -p "$OUTDIR"

# ===== CA =====
mkdir -p "$OUTDIR/ca"

openssl genpkey -algorithm ED25519 -out "$OUTDIR/ca/ca.key" >/dev/null 2>&1
openssl req -new -x509 \
    -key "$OUTDIR/ca/ca.key" \
    -out "$OUTDIR/ca/ca.pem" \
    -days "$DAYS" \
    -subj "/CN=$CA_CN" \
    >/dev/null 2>&1

# ===== Server cert =====
mkdir -p "$OUTDIR/server"

openssl genpkey -algorithm ED25519 -out "$OUTDIR/server/cert.key" >/dev/null 2>&1
openssl req -new \
    -key "$OUTDIR/server/cert.key" \
    -out "$OUTDIR/server/cert.csr" \
    -subj "/CN=$SERVER_CN" \
    >/dev/null 2>&1
openssl x509 -req \
    -in "$OUTDIR/server/cert.csr" \
    -CA "$OUTDIR/ca/ca.pem" \
    -CAkey "$OUTDIR/ca/ca.key" \
    -CAcreateserial \
    -out "$OUTDIR/server/cert.pem" \
    -days "$DAYS" \
    >/dev/null 2>&1
cp "$OUTDIR/ca/ca.pem" "$OUTDIR/server/ca.pem"
rm -f "$OUTDIR/server/cert.csr"

# ===== Client certs =====
i=1
while [ "$i" -le "$CLIENTS" ]; do
    dir="$OUTDIR/client$i"
    mkdir -p "$dir"

    openssl genpkey -algorithm ED25519 -out "$dir/cert.key" >/dev/null 2>&1
    openssl req -new \
        -key "$dir/cert.key" \
        -out "$dir/cert.csr" \
        -subj "/CN=${CLIENT_CN_PREFIX}${i}" \
        >/dev/null 2>&1
    openssl x509 -req \
        -in "$dir/cert.csr" \
        -CA "$OUTDIR/ca/ca.pem" \
        -CAkey "$OUTDIR/ca/ca.key" \
        -CAcreateserial \
        -out "$dir/cert.pem" \
        -days "$DAYS" \
        >/dev/null 2>&1
    cp "$OUTDIR/ca/ca.pem" "$dir/ca.pem"
    rm -f "$dir/cert.csr"

    i=$((i + 1))
done

rm -f "$OUTDIR/ca/ca.srl"

echo "Certificates generated in: $OUTDIR"
