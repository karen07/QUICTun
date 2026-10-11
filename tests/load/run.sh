#!/bin/sh
set -eu

ROOT=$(CDPATH='' cd -- "$(dirname -- "$0")/../.." && pwd)
cd "$ROOT"

[ "$#" -le 1 ] || {
    printf 'Usage: %s [QUICTun-binary]\n' "$0" >&2
    exit 2
}

# Debugging mode: exercise the load suite against an existing binary.
if [ -n "${QUICTUN_BIN:-${1:-}}" ]; then
    binary=${QUICTUN_BIN:-$1}
    case "$binary" in
        /*) ;;
        *) binary="$ROOT/$binary" ;;
    esac
    [ -x "$binary" ] || {
        printf 'ERROR: QUICTun binary not executable: %s\n' "$binary" >&2
        exit 2
    }
    QUICTUN_BIN=$binary
    export QUICTUN_BIN
    exec python3 -B tests/load/test_load.py
fi

command -v docker >/dev/null 2>&1 || {
    printf 'ERROR: Docker is required for load tests.\n' >&2
    exit 2
}
if [ ! -f picoquic/CMakeLists.txt ] || [ ! -f picotls/CMakeLists.txt ]; then
    printf 'ERROR: missing picoquic/picotls submodules.\n' >&2
    printf 'Run: git submodule update --init --recursive\n' >&2
    exit 2
fi

IMAGE=${IMAGE:-quictun-load:local}
if [ "${LOAD_NO_CACHE:-${QUICTUN_TEST_NO_CACHE:-0}}" = 1 ]; then
    docker build --pull --no-cache -f tests/load/Dockerfile -t "$IMAGE" .
else
    docker build -f tests/load/Dockerfile -t "$IMAGE" .
fi

status=0
for profile in gcc-release clang-release clang-asan-ubsan; do
    printf '\n========================================\n'
    printf 'QUICTun LOAD/STRESS: %s\n' "$profile"
    printf '========================================\n\n'

    if [ "$profile" = clang-asan-ubsan ]; then
        set -- -e 'ASAN_OPTIONS=detect_leaks=1:halt_on_error=1:abort_on_error=1' \
            -e 'UBSAN_OPTIONS=halt_on_error=1:print_stacktrace=1'
    else
        set --
    fi

    if docker run --rm --init \
        -e "QUICTUN_BIN=/src/build/tests/load/$profile/QUICTun" \
        -e "QUICTUN_STRESS_SCALE=${QUICTUN_STRESS_SCALE:-1}" \
        -e "QUICTUN_LONG_STRESS_PACKETS=${QUICTUN_LONG_STRESS_PACKETS:-0}" \
        -e "QUICTUN_LONG_STRESS_PPS=${QUICTUN_LONG_STRESS_PPS:-4000}" \
        "$@" "$IMAGE" python3 -u -B tests/load/test_load.py; then
        printf '[PASS] load: %s\n' "$profile"
    else
        printf '[FAIL] load: %s\n' "$profile" >&2
        status=1
    fi
done

[ "$status" -eq 0 ] || exit "$status"
printf '\nALL QUICTun LOAD/STRESS COMPILER/SANITIZER RUNS PASSED\n'
