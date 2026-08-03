#!/bin/sh

# === config ===
PROBE_IP4="1.1.1.1"
PROBE_IP6="fd00::1"

IPERF_BASE_PORT=5200
QUIC_PORT=443
WG_PORT=60000

WARMUP_SEC=20
IPERF_DURATION_SEC=120
IPERF_WAIT_SEC=$((IPERF_DURATION_SEC + 5))
RESTART_DELAY_BEFORE_SEC=$((IPERF_DURATION_SEC / 2))
RESTART_DOWN_SEC=5

MAX_CNX_TTL=10
TARGET_SPEED_MBIT=100

NET_A=10
NET_B=10

DEFAULT_COLS=208

REMOTE_QUICTUN_BIN="/usr/bin/QUICTun"
REMOTE_QUICTUN_DIR="/etc/QUICTun"
REMOTE_SYSTEMD_DIR="/etc/systemd/system"
REMOTE_WG_DIR="/etc/wireguard"

SERVICE_SERVER="QUICTun-server.service"
SERVICE_CLIENT_PREFIX="QUICTun-client"
# === config ===

if [ -t 1 ]; then
    GREEN='\033[0;32m'
    NC='\033[0m'
    cols=$(tput cols 2>/dev/null || echo "$DEFAULT_COLS")
else
    GREEN=''
    NC=''
    cols="$DEFAULT_COLS"
fi

green() { printf "${GREEN}%s${NC}\n" "$*"; }

direct=0
short_ttl=0
udp=0
ipv6=0
mode="normal"
build_type="Release"

for a in "$@"; do
    [ "$a" = "--direct" ] && direct=1
    [ "$a" = "--short-ttl" ] && short_ttl=1
    [ "$a" = "--udp" ] && udp=1
    [ "$a" = "--restart" ] && mode="restart"
    [ "$a" = "--ASAN" ] && build_type="Debug_ASan"
    [ "$a" = "--ipv6" ] && ipv6=1
done

check_hosts_available() {
    missing=""

    for h in $alls; do
        printf "Checking %s... " "$h"

        if ssh \
            -o BatchMode=yes \
            -o ConnectTimeout=5 \
            -o ConnectionAttempts=1 \
            -o ServerAliveInterval=2 \
            -o ServerAliveCountMax=1 \
            "$h" "true" >/dev/null 2>&1; then
            echo "ok"
        else
            echo "failed"
            missing="$missing $h"
        fi
    done

    if [ -n "$missing" ]; then
        echo ""
        echo "Unavailable VM(s):$missing"
        echo ""
        echo "Try manually:"
        for h in $missing; do
            echo "  ssh $h"
        done
        echo ""
        echo "Start the VMs or fix SSH before running the test."
        exit 1
    fi
}

ip4_from_index() {
    idx="$1"
    third=$((idx / 256))
    fourth=$((idx % 256))
    printf "%s.%s.%s.%s" "$NET_A" "$NET_B" "$third" "$fourth"
}

server_ip_for_client_idx() {
    i="$1"
    base=$(((i - 1) * 2))
    ip4_from_index "$base"
}

client_ip_for_client_idx() {
    i="$1"
    base=$(((i - 1) * 2))
    ip4_from_index $((base + 1))
}

get_remote_ip() {
    host="$1"

    if [ "$ipv6" -eq 1 ]; then
        # shellcheck disable=SC2029
        ssh "$host" "ip -6 route get '$PROBE_IP6' | awk '
            {
                for (i = 1; i <= NF; i++) {
                    if (\$i == \"src\") {
                        print \$(i+1)
                        exit
                    }
                }
            }'"
    else
        # shellcheck disable=SC2029
        ssh "$host" "ip route get '$PROBE_IP4' | awk '
            {
                for (i = 1; i <= NF; i++) {
                    if (\$i == \"src\") {
                        print \$(i+1)
                        exit
                    }
                }
            }'"
    fi
}

format_host_port() {
    host="$1"
    port="$2"

    if [ "$ipv6" -eq 1 ]; then
        printf '[%s]:%s' "$host" "$port"
    else
        printf '%s:%s' "$host" "$port"
    fi
}

remote_prepare_dirs() {
    for h in $alls; do
        # shellcheck disable=SC2029
        ssh "$h" "
            sudo mkdir -p '$REMOTE_QUICTUN_DIR' &&
            sudo mkdir -p '$REMOTE_WG_DIR' &&
            sudo mkdir -p '$REMOTE_SYSTEMD_DIR'
        " >/dev/null 2>&1
    done
}

disable_all_services() {
    # shellcheck disable=SC2029
    ssh "$server" "
        sudo systemctl disable --now '$SERVICE_SERVER' >/dev/null 2>&1 || true
    " >/dev/null 2>&1

    i=1
    for h in $clients; do
        # shellcheck disable=SC2029
        ssh "$h" "
            sudo systemctl disable --now '${SERVICE_CLIENT_PREFIX}${i}.service' \
                >/dev/null 2>&1 || true
        " >/dev/null 2>&1
        i=$((i + 1))
    done
}

kill_all() {
    for h in $alls; do
        # shellcheck disable=SC2029
        ssh "$h" "sudo pkill tcpdump" >/dev/null 2>&1
        # shellcheck disable=SC2029
        ssh "$h" "sudo pkill iperf3" >/dev/null 2>&1
    done

    # shellcheck disable=SC2029
    ssh "$server" \
        "sudo systemctl stop '$SERVICE_SERVER' >/dev/null 2>&1 || true" \
        >/dev/null 2>&1

    i=1
    for h in $clients; do
        # shellcheck disable=SC2029
        ssh "$h" \
            "sudo systemctl stop '${SERVICE_CLIENT_PREFIX}${i}.service' \
                >/dev/null 2>&1 || true" \
            >/dev/null 2>&1
        i=$((i + 1))
    done

    i=1
    for h in $clients; do
        # shellcheck disable=SC2029
        ssh "$server" \
            "sudo systemctl stop 'wg-quick@server$i' >/dev/null 2>&1 || true" \
            >/dev/null 2>&1
        # shellcheck disable=SC2029
        ssh "$h" \
            "sudo systemctl stop 'wg-quick@client$i' >/dev/null 2>&1 || true" \
            >/dev/null 2>&1
        i=$((i + 1))
    done
}

restart_quictun() {
    who="$1"

    if [ "$who" = "server" ]; then
        # shellcheck disable=SC2029
        ssh "$server" "sudo systemctl restart '$SERVICE_SERVER'" >/dev/null 2>&1
        sleep "$RESTART_DOWN_SEC"
        return 0
    fi

    i=1
    for h in $clients; do
        # shellcheck disable=SC2029
        ssh "$h" \
            "sudo systemctl restart '${SERVICE_CLIENT_PREFIX}${i}.service'" \
            >/dev/null 2>&1
        i=$((i + 1))
    done

    sleep "$RESTART_DOWN_SEC"
}

iperf_start_servers() {
    prefix="$1"
    i=1
    for h in $clients; do
        bind_ip="$(server_ip_for_client_idx "$i")"
        port=$((i + IPERF_BASE_PORT))
        cmd="sudo sh -c 'nohup iperf3 -s -J -1 -B $bind_ip -p $port \
>${prefix}_$port.txt 2>&1 &'"
        # shellcheck disable=SC2029
        ssh "$server" "$cmd" >/dev/null 2>&1
        i=$((i + 1))
    done
}

iperf_start_clients() {
    prefix="$1"
    client_args="$2"

    proto_args=""
    rate_args=""

    if [ "$udp" -eq 1 ]; then
        proto_args="-u"
        rate_args="-b ${TARGET_SPEED_MBIT}M"
    fi

    i=1
    for h in $clients; do
        dst_ip="$(server_ip_for_client_idx "$i")"
        port=$((i + IPERF_BASE_PORT))
        cmd="sudo sh -c 'nohup iperf3 -c $dst_ip -J -p $port \
-t $IPERF_DURATION_SEC $client_args $proto_args $rate_args >${prefix}_$port.txt 2>&1 &'"
        # shellcheck disable=SC2029
        ssh "$h" "$cmd" >/dev/null 2>&1
        i=$((i + 1))
    done
}

iperf_kill_all() {
    for h in $alls; do
        # shellcheck disable=SC2029
        ssh "$h" "sudo pkill iperf3" >/dev/null 2>&1
    done
}

iperf_run() {
    prefix="$1"
    client_args="$2"
    wait_sec="$3"
    restart_before="$4"
    restart_who="$5"

    iperf_start_servers "$prefix"
    iperf_start_clients "$prefix" "$client_args"

    if [ -n "$restart_who" ]; then
        sleep "$restart_before"
        restart_quictun "$restart_who"
        sleep "$restart_before"
    else
        sleep "$wait_sec"
    fi

    iperf_kill_all
}

print_iperf_per_client() {
    title="$1"
    prefix="$2"
    receiver_side="$3"

    all_tmp_paths=""
    i=1
    for h in $clients; do
        port=$((i + IPERF_BASE_PORT))

        tmp=$(mktemp)
        all_tmp_paths="$all_tmp_paths $tmp"

        if [ "$receiver_side" = "client" ]; then
            src_host="$h"
        else
            src_host="$server"
        fi

        # shellcheck disable=SC2029
        ssh "$src_host" "cat ${prefix}_$port.txt" | jq -r '
            def f2(x): ((x*100|round)/100);
            def mbit(x): (x/1000000);

            "Interval\tMbits/sec",
            (.intervals[].sum
              | "\(f2(.start))-\(f2(.end))\t\(f2(mbit(.bits_per_second)))"
            ),
            "----",
            (.end.sum_received
              | "0.00-\(f2(.seconds))\t\(f2(mbit(.bits_per_second)))"
            )
        ' | column -ts "$(printf '\t')" >"$tmp"

        i=$((i + 1))
    done

    echo ""
    green "$title"
    # shellcheck disable=SC2086
    pr -m -t -w "$cols" $all_tmp_paths | expand -t 8
    # shellcheck disable=SC2086
    rm -f $all_tmp_paths
}

sum_iperf_mbits() {
    prefix="$1"
    receiver_side="$2"

    sum=0
    i=1
    for h in $clients; do
        port=$((i + IPERF_BASE_PORT))

        if [ "$receiver_side" = "client" ]; then
            src_host="$h"
        else
            src_host="$server"
        fi

        val=$(
            # shellcheck disable=SC2029
            ssh "$src_host" "cat ${prefix}_$port.txt" \
                | jq -r ".end.sum_received.bits_per_second / 1000000"
        )

        sum=$(awk -v s="$sum" -v v="$val" 'BEGIN{printf "%.10f", (s+v)}')

        i=$((i + 1))
    done

    awk -v s="$sum" 'BEGIN{printf "%.2f\n", s}'
}

print_logs_glob() {
    glob_arg="$1"
    all_tmp_paths=""

    for h in $alls; do
        tmp=$(mktemp)
        all_tmp_paths="$all_tmp_paths $tmp"
        # shellcheck disable=SC2029
        ssh "$h" "cat $glob_arg 2>/dev/null || true" >"$tmp"
    done

    # shellcheck disable=SC2086
    pr -m -t -w "$cols" $all_tmp_paths | expand -t 8
    # shellcheck disable=SC2086
    rm -f $all_tmp_paths
}

print_quictun_logs() {
    green "===== journal: server ====="
    # shellcheck disable=SC2029
    ssh "$server" "sudo journalctl -u '$SERVICE_SERVER' -n 200 --no-pager" || true

    i=1
    for h in $clients; do
        green "===== journal: client$i ($h) ====="
        # shellcheck disable=SC2029
        ssh "$h" \
            "sudo journalctl -u '${SERVICE_CLIENT_PREFIX}${i}.service' \
                -n 200 --no-pager" || true
        i=$((i + 1))
    done

    green "===== /var/log/QUICTun_log.txt ====="
    print_logs_glob "/var/log/QUICTun_log.txt"

    green "===== /var/log/QUICTun_stat.txt ====="
    print_logs_glob "/var/log/QUICTun_stat.txt"
}

build_binary() {
    rm -rf build
    if [ "$short_ttl" -eq 1 ]; then
        cmake -S . -B build \
            -DCMAKE_BUILD_TYPE="$build_type" \
            -DCMAKE_C_FLAGS="-DMAX_CNX_TTL=$MAX_CNX_TTL -DDEPLOY" \
            >/dev/null 2>&1
    else
        cmake -S . -B build \
            -DCMAKE_BUILD_TYPE="$build_type" \
            -DCMAKE_C_FLAGS="-DDEPLOY" \
            >/dev/null 2>&1
    fi

    cmake --build build -j 8 >/dev/null 2>&1 || {
        echo "build failed, re-running with output:"
        cmake --build build -j 8
        exit 1
    }
}

deploy_and_configure() {
    echo "$alls"

    remote_prepare_dirs
    disable_all_services

    for h in $alls; do
        scp build/QUICTun "$h:/tmp/QUICTun" >/dev/null 2>&1
        # shellcheck disable=SC2029
        ssh "$h" "
            sudo install -m 0755 /tmp/QUICTun '$REMOTE_QUICTUN_BIN' &&
            rm -f /tmp/QUICTun
        " >/dev/null 2>&1
    done

    SERVER_IP=$(get_remote_ip "$server")
    [ -n "$SERVER_IP" ] || {
        echo "failed to detect server IP"
        exit 1
    }

    QUIC_LISTEN=$(format_host_port "$SERVER_IP" "$QUIC_PORT")

    scp -r certs/server "$server:/tmp/server" >/dev/null 2>&1
    scp configs/server.conf "$server:/tmp/server.conf" >/dev/null 2>&1

    # shellcheck disable=SC2029
    ssh "$server" "
        sudo rm -rf '$REMOTE_QUICTUN_DIR/server' &&
        sudo mkdir -p '$REMOTE_QUICTUN_DIR' &&
        sudo cp -r /tmp/server '$REMOTE_QUICTUN_DIR/server' &&
        sudo install -m 0644 /tmp/server.conf '$REMOTE_QUICTUN_DIR/server.conf' &&
        sudo sed -i -E \
            's|^[[:space:]]*QuicListen[[:space:]]*=.*$|\tQuicListen = $QUIC_LISTEN|' \
            '$REMOTE_QUICTUN_DIR/server.conf' &&
        rm -rf /tmp/server /tmp/server.conf
    " >/dev/null 2>&1

    scp "systemd/$SERVICE_SERVER" "$server:/tmp/$SERVICE_SERVER" >/dev/null 2>&1
    # shellcheck disable=SC2029
    ssh "$server" "
        sudo install -m 0644 /tmp/$SERVICE_SERVER \
            '$REMOTE_SYSTEMD_DIR/$SERVICE_SERVER' &&
        rm -f /tmp/$SERVICE_SERVER
    " >/dev/null 2>&1

    server_wg_found=0
    for f in wgs/server*.conf; do
        [ -e "$f" ] || continue
        server_wg_found=1
        base=$(basename "$f")
        scp "$f" "$server:/tmp/$base.wg" >/dev/null 2>&1
    done

    if [ "$server_wg_found" -eq 1 ]; then
        # shellcheck disable=SC2029
        ssh "$server" "
            sudo mkdir -p '$REMOTE_WG_DIR' &&
            sudo rm -f '$REMOTE_WG_DIR'/server*.conf &&
            for f in /tmp/server*.conf.wg; do
                [ -e \"\$f\" ] || continue
                base=\$(basename \"\$f\" .wg)
                sudo install -m 0600 \"\$f\" '$REMOTE_WG_DIR'/\"\$base\"
                rm -f \"\$f\"
            done
        " >/dev/null 2>&1
    fi

    i=1
    for h in $clients; do
        scp -r "certs/client$i" "$h:/tmp/client$i" >/dev/null 2>&1
        scp "configs/client$i.conf" "$h:/tmp/client$i.conf" >/dev/null 2>&1

        QUIC_ENDPOINT=$(format_host_port "$SERVER_IP" "$QUIC_PORT")

        # shellcheck disable=SC2029
        ssh "$h" "
            sudo rm -rf '$REMOTE_QUICTUN_DIR/client$i' &&
            sudo mkdir -p '$REMOTE_QUICTUN_DIR' &&
            sudo cp -r /tmp/client$i '$REMOTE_QUICTUN_DIR/client$i' &&
            sudo install -m 0644 /tmp/client$i.conf \
                '$REMOTE_QUICTUN_DIR/client$i.conf' &&
            sudo sed -i -E \
                's|^[[:space:]]*QuicEndpoint[[:space:]]*=.*$|\tQuicEndpoint = $QUIC_ENDPOINT|' \
                '$REMOTE_QUICTUN_DIR/client$i.conf' &&
            rm -rf /tmp/client$i /tmp/client$i.conf
        " >/dev/null 2>&1

        scp "wgs/client$i.conf" "$h:/tmp/client$i.conf.wg" >/dev/null 2>&1

        # shellcheck disable=SC2029
        ssh "$h" "
            sudo install -m 0600 /tmp/client$i.conf.wg \
                '$REMOTE_WG_DIR/client$i.conf' &&
            rm -f /tmp/client$i.conf.wg
        " >/dev/null 2>&1

        if [ "$direct" -eq 1 ] && [ "$mode" = "normal" ]; then
            wg_port=$((WG_PORT + i - 1))
            WG_ENDPOINT=$(format_host_port "$SERVER_IP" "$wg_port")
            # shellcheck disable=SC2029
            ssh "$h" "
                sudo sed -i -E \
                    's|^[[:space:]]*Endpoint[[:space:]]*=.*$|\tEndpoint = $WG_ENDPOINT|' \
                    '$REMOTE_WG_DIR/client$i.conf'
            " >/dev/null 2>&1
        fi

        scp "systemd/${SERVICE_CLIENT_PREFIX}${i}.service" \
            "$h:/tmp/${SERVICE_CLIENT_PREFIX}${i}.service" >/dev/null 2>&1

        # shellcheck disable=SC2029
        ssh "$h" "
            sudo install -m 0644 /tmp/${SERVICE_CLIENT_PREFIX}${i}.service \
                '$REMOTE_SYSTEMD_DIR/${SERVICE_CLIENT_PREFIX}${i}.service' &&
            rm -f /tmp/${SERVICE_CLIENT_PREFIX}${i}.service
        " >/dev/null 2>&1

        i=$((i + 1))
    done

    for h in $alls; do
        # shellcheck disable=SC2029
        ssh "$h" "sudo systemctl daemon-reload" >/dev/null 2>&1
    done
}

start_QUICTun() {
    for h in $alls; do
        # shellcheck disable=SC2029
        ssh "$h" "sudo modprobe wireguard" >/dev/null 2>&1
    done

    # shellcheck disable=SC2029
    ssh "$server" "sudo systemctl enable --now '$SERVICE_SERVER'" >/dev/null 2>&1

    i=1
    for h in $clients; do
        # shellcheck disable=SC2029
        ssh "$h" \
            "sudo systemctl enable --now '${SERVICE_CLIENT_PREFIX}${i}.service'" \
            >/dev/null 2>&1
        i=$((i + 1))
    done
}

run_mode_normal() {
    iperf_run "iperf3_R" "-R" "$IPERF_WAIT_SEC" "" ""
    iperf_run "iperf3" "" "$IPERF_WAIT_SEC" "" ""
}

run_mode_restart() {
    iperf_run "iperf3_S_R" "-R" "" "$RESTART_DELAY_BEFORE_SEC" "server"
    iperf_run "iperf3_S" "" "" "$RESTART_DELAY_BEFORE_SEC" "server"

    iperf_run "iperf3_C_R" "-R" "" "$RESTART_DELAY_BEFORE_SEC" "clients"
    iperf_run "iperf3_C" "" "" "$RESTART_DELAY_BEFORE_SEC" "clients"
}

print_mode_normal() {
    print_iperf_per_client "DOWNLOAD" "iperf3_R" "client"
    print_iperf_per_client "UPLOAD" "iperf3" "server"

    download_sum=$(sum_iperf_mbits "iperf3_R" "client")
    upload_sum=$(sum_iperf_mbits "iperf3" "server")

    echo ""
    green "DOWNLOAD SUM $download_sum Mbits/sec"
    green "UPLOAD   SUM $upload_sum Mbits/sec"
}

print_mode_restart() {
    print_iperf_per_client "DOWNLOAD SERVER RESTART" "iperf3_S_R" "client"
    print_iperf_per_client "UPLOAD SERVER RESTART" "iperf3_S" "server"
    print_iperf_per_client "DOWNLOAD CLIENTS RESTART" "iperf3_C_R" "client"
    print_iperf_per_client "UPLOAD CLIENTS RESTART" "iperf3_C" "server"

    download_sum_s=$(sum_iperf_mbits "iperf3_S_R" "client")
    upload_sum_s=$(sum_iperf_mbits "iperf3_S" "server")
    download_sum_c=$(sum_iperf_mbits "iperf3_C_R" "client")
    upload_sum_c=$(sum_iperf_mbits "iperf3_C" "server")

    echo ""
    green "DOWNLOAD SERVER RESTART  SUM $download_sum_s Mbits/sec"
    green "UPLOAD   SERVER RESTART  SUM $upload_sum_s Mbits/sec"
    green "DOWNLOAD CLIENTS RESTART SUM $download_sum_c Mbits/sec"
    green "UPLOAD   CLIENTS RESTART SUM $upload_sum_c Mbits/sec"
}

generate_artifacts() {
    ./shs/certs.sh
    ./shs/configs.sh
    ./shs/wgs.sh
    ./shs/systemds.sh
}

# ===== main =====

server="vm0"
clients="vm1 vm2 vm3"
alls="$clients $server"

check_hosts_available

generate_artifacts
build_binary
deploy_and_configure

kill_all

if [ "$direct" -eq 0 ]; then
    start_QUICTun
fi

sleep "$WARMUP_SEC"

if [ "$mode" = "restart" ]; then
    run_mode_restart
else
    run_mode_normal
fi

kill_all
print_quictun_logs

if [ "$mode" = "restart" ]; then
    print_mode_restart
else
    print_mode_normal
fi
