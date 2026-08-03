#!/bin/sh

LOG_DIR="log"
DEPLOY="./deploy.sh"

rm -rf "$LOG_DIR"
mkdir -p "$LOG_DIR"

say() {
    printf '%s\n' "$*"
}

set_compiler() {
    cc_bin="$1"
    cxx_bin="$2"

    CC_PATH=$(command -v "$cc_bin" 2>/dev/null || true)
    CXX_PATH=$(command -v "$cxx_bin" 2>/dev/null || true)

    if [ -z "$CC_PATH" ] || [ -z "$CXX_PATH" ]; then
        say "skip compiler pair: $cc_bin / $cxx_bin (not found)"
        return 1
    fi

    export CC="$CC_PATH"
    export CXX="$CXX_PATH"

    say "CC=$CC"
    say "CXX=$CXX"
    say ""

    return 0
}

build_suffix() {
    suffix=""

    [ "$use_asan" -eq 1 ] && suffix="${suffix}_asan"
    [ "$use_udp" -eq 1 ] && suffix="${suffix}_udp" || suffix="${suffix}_tcp"
    [ "$use_restart" -eq 1 ] && suffix="${suffix}_restart"
    [ "$use_short_ttl" -eq 1 ] && suffix="${suffix}_short_ttl"
    [ "$use_ipv6" -eq 1 ] && suffix="${suffix}_ipv6"

    printf '%s\n' "$suffix"
}

build_args() {
    args=""

    [ "$use_asan" -eq 1 ] && args="$args --ASAN"
    [ "$use_udp" -eq 1 ] && args="$args --udp"
    [ "$use_restart" -eq 1 ] && args="$args --restart"
    [ "$use_short_ttl" -eq 1 ] && args="$args --short-ttl"
    [ "$use_ipv6" -eq 1 ] && args="$args --ipv6"

    printf '%s\n' "$args"
}

run_case() {
    compiler_prefix="$1"

    suffix=$(build_suffix)
    args=$(build_args)
    log_file="$LOG_DIR/${compiler_prefix}_log${suffix}.txt"

    say ">>> $DEPLOY$args"
    say ">>> log: $log_file"

    # shellcheck disable=SC2086
    if $DEPLOY $args >"$log_file" 2>&1; then
        say "OK"
    else
        say "FAIL"
    fi
    say ""
}

run_matrix_for_compiler() {
    compiler_prefix="$1"

    for use_asan in 0 1; do
        for use_udp in 0 1; do
            for use_restart in 0 1; do
                for use_short_ttl in 0 1; do
                    for use_ipv6 in 0 1; do
                        run_case "$compiler_prefix"
                    done
                done
            done
        done
    done
}

if set_compiler gcc g++; then
    run_matrix_for_compiler gcc
fi

if set_compiler clang clang++; then
    run_matrix_for_compiler clang
fi
