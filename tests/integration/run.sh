#!/bin/sh
set -eu

ROOT=$(CDPATH='' cd -- "$(dirname -- "$0")/../.." && pwd)
cd "$ROOT"

[ "$#" -le 1 ] || {
    printf 'Usage: %s [QUICTun-binary]\n' "$0" >&2
    exit 2
}

# Debugging mode: exercise the integration suite against an existing binary.
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
    exec python3 -B tests/integration/test_quictun.py
fi

command -v docker >/dev/null 2>&1 || {
    printf 'ERROR: Docker is required for integration tests.\n' >&2
    exit 2
}
if [ ! -f picoquic/CMakeLists.txt ] || [ ! -f picotls/CMakeLists.txt ]; then
    printf 'ERROR: missing picoquic/picotls submodules.\n' >&2
    printf 'Run: git submodule update --init --recursive\n' >&2
    exit 2
fi

IMAGE=${IMAGE:-quictun-integration:local}
if [ "${INTEGRATION_NO_CACHE:-${QUICTUN_TEST_NO_CACHE:-0}}" = 1 ]; then
    docker build --pull --no-cache -f tests/integration/Dockerfile -t "$IMAGE" .
else
    docker build -f tests/integration/Dockerfile -t "$IMAGE" .
fi

status=0
for profile in gcc-release clang-release clang-asan-ubsan; do
    printf '\n========================================\n'
    printf 'QUICTun INTEGRATION: %s\n' "$profile"
    printf '========================================\n\n'

    if [ "$profile" = clang-asan-ubsan ]; then
        set -- -e 'ASAN_OPTIONS=detect_leaks=1:halt_on_error=1:abort_on_error=1' \
            -e 'UBSAN_OPTIONS=halt_on_error=1:print_stacktrace=1'
    else
        set --
    fi

    if docker run --rm --init \
        --cap-add NET_ADMIN --cap-add NET_RAW --cap-add SYS_ADMIN \
        --security-opt seccomp=unconfined --security-opt apparmor=unconfined \
        -e "QUICTUN_BIN=/src/build/tests/integration/$profile/QUICTun" \
        -e "QUICTUN_E2E_PACKETS=${QUICTUN_E2E_PACKETS:-64}" \
        -e "QUICTUN_REQUIRE_NETEM=${QUICTUN_REQUIRE_NETEM:-1}" \
        "$@" "$IMAGE" python3 -u -B tests/integration/test_quictun.py; then
        printf '[PASS] integration: %s\n' "$profile"
    else
        printf '[FAIL] integration: %s\n' "$profile" >&2
        status=1
    fi
done

[ "$status" -eq 0 ] || exit "$status"
printf '\nALL QUICTun INTEGRATION COMPILER/SANITIZER RUNS PASSED\n'
