FROM archlinux:latest

RUN pacman -Syu --noconfirm --needed \
        base-devel cmake clang ninja openssl python git zlib \
    && pacman -Scc --noconfirm

WORKDIR /src
COPY . .

# Keep the load suite independently buildable, like AntiBlock's load Dockerfile.
RUN set -eu; \
    for profile in gcc-release clang-release clang-asan-ubsan; do \
        case "$profile" in \
            gcc-release) compiler=gcc; build_type=Release ;; \
            clang-release) compiler=clang; build_type=Release ;; \
            clang-asan-ubsan) compiler=clang; build_type=Debug_ASan ;; \
        esac; \
        build="/src/build/tests/load/$profile"; \
        cmake -S /src -B "$build" \
            -DCMAKE_BUILD_TYPE="$build_type" \
            -DCMAKE_C_COMPILER="$compiler" \
            -DQUICTUN_BUILD_TESTS=OFF \
        && cmake --build "$build" --parallel 2 --target QUICTun \
        && stage="/tmp/install-$profile" \
        && mkdir -p "$stage" \
        && DESTDIR="$stage" cmake --install "$build" --prefix /usr \
        && installed=$(find "$stage" \( -type f -o -type l \) -print) \
        && [ "$installed" = "$stage/usr/bin/QUICTun" ] \
        && [ -x "$stage/usr/bin/QUICTun" ] \
        || exit 1; \
        rm -rf "$stage"; \
    done
