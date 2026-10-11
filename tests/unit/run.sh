#!/bin/sh
set -eu

ROOT=$(CDPATH='' cd -- "$(dirname -- "$0")/../.." && pwd)
cd "$ROOT"

usage() {
    printf 'Usage: %s [--install-only | unit-binary]\n' "$0" >&2
    exit 2
}

[ "$#" -le 1 ] || usage
if [ "${1:-}" = --install-only ]; then
    exec python3 -B tests/unit/test_install.py
fi

# An explicit prebuilt binary is useful when debugging a single test process.
if [ -n "${QUICTUN_UNIT_BIN:-${1:-}}" ]; then
    unit_bin=${QUICTUN_UNIT_BIN:-$1}
    case "$unit_bin" in
        /*) ;;
        *) unit_bin="$ROOT/$unit_bin" ;;
    esac
    [ -x "$unit_bin" ] || {
        printf 'ERROR: unit binary not executable: %s\n' "$unit_bin" >&2
        exit 2
    }
    exec "$unit_bin"
fi

# Like AntiBlock's unit suite, this runs directly on the host, without Docker.
python3 -B tests/unit/test_install.py

if [ ! -f picoquic/CMakeLists.txt ] || [ ! -f picotls/CMakeLists.txt ]; then
    printf 'ERROR: missing picoquic/picotls submodules.\n' >&2
    printf 'Run: git submodule update --init --recursive\n' >&2
    exit 2
fi

for profile in gcc-release clang-release clang-asan-ubsan; do
    case "$profile" in
        gcc-release)
            compiler=gcc
            build_type=Release
            ;;
        clang-release)
            compiler=clang
            build_type=Release
            ;;
        clang-asan-ubsan)
            compiler=clang
            build_type=Debug_ASan
            ;;
        *)
            printf 'ERROR: unknown unit test profile: %s\n' "$profile" >&2
            exit 2
            ;;
    esac

    printf '\n========================================\n'
    printf 'QUICTun UNIT: %s\n' "$profile"
    printf '========================================\n\n'

    build="$ROOT/build/tests/unit/$profile"
    cmake -S "$ROOT" -B "$build" \
        -DCMAKE_BUILD_TYPE="$build_type" \
        -DCMAKE_C_COMPILER="$compiler" \
        -DQUICTUN_BUILD_TESTS=ON
    cmake --build "$build" --parallel "${QUICTUN_TEST_JOBS:-2}" \
        --target QUICTun quictun-unit

    stage="$build/install-stage"
    rm -rf "$stage"
    mkdir -p "$stage"
    DESTDIR="$stage" cmake --install "$build" --prefix /usr
    installed=$(find "$stage" \( -type f -o -type l \) -print)
    if [ "$installed" != "$stage/usr/bin/QUICTun" ] \
        || [ ! -x "$stage/usr/bin/QUICTun" ]; then
        printf 'FAIL: unexpected cmake install contents:\n%s\n' "$installed" >&2
        exit 1
    fi
    printf '[PASS] cmake install: only /usr/bin/QUICTun\n'

    if [ "$profile" = clang-asan-ubsan ]; then
        ASAN_OPTIONS='detect_leaks=1:halt_on_error=1:abort_on_error=1' \
            UBSAN_OPTIONS='halt_on_error=1:print_stacktrace=1' \
            "$build/quictun-unit"
    else
        "$build/quictun-unit"
    fi
done

printf '\nALL QUICTun UNIT COMPILER/SANITIZER RUNS PASSED\n'
