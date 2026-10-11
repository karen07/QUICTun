#!/usr/bin/env python3
"""Regression test for QUICTun's CMake install contract.

Use the *actual, unchanged* top-level CMakeLists.txt with small stand-in
picoquic/picotls targets. This tests directory-scoped install propagation
without downloading/building third-party dependencies. It does not replace
building and installing QUICTun against the real submodules.
"""

import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile

ROOT = Path(__file__).resolve().parents[2]


def run(*args: str, env: dict[str, str] | None = None) -> None:
    subprocess.run(
        args, check=True, env=env, stdout=subprocess.PIPE, stderr=subprocess.PIPE
    )


def write(path: Path, text: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text, encoding="utf-8")


def main() -> int:
    if not shutil.which("cmake") or not shutil.which("cc"):
        print("ERROR: cmake and a C compiler are required", file=sys.stderr)
        return 2
    with tempfile.TemporaryDirectory(prefix="quictun-install-test-") as td:
        temp = Path(td)
        src = temp / "source"
        build = temp / "build"
        src.mkdir()
        shutil.copy2(ROOT / "CMakeLists.txt", src / "CMakeLists.txt")
        write(src / "src" / "main.c", "int main(void) { return 0; }\n")
        write(src / "picoquic" / "core.c", "int picoquic_stub(void) { return 0; }\n")
        write(src / "picoquic" / "demo.c", "int main(void) { return 0; }\n")
        write(
            src / "picoquic" / "picoquic.h", "/* header that must not be installed */\n"
        )
        write(
            src / "picoquic" / "CMakeLists.txt",
            """\
add_library(picoquic-core STATIC core.c)
add_executable(picoquicdemo demo.c)
install(TARGETS picoquic-core ARCHIVE DESTINATION lib)
install(TARGETS picoquicdemo RUNTIME DESTINATION bin)
install(FILES picoquic.h DESTINATION include)
add_subdirectory(picotls)
""",
        )
        write(
            src / "picoquic" / "picotls" / "tls.c",
            "int picotls_stub(void) { return 0; }\n",
        )
        write(
            src / "picoquic" / "picotls" / "CMakeLists.txt",
            """\
add_library(picotls-core STATIC tls.c)
install(TARGETS picotls-core ARCHIVE DESTINATION lib)
""",
        )

        run("cmake", "-S", str(src), "-B", str(build), "-DCMAKE_INSTALL_PREFIX=/usr")
        run("cmake", "--build", str(build), "--parallel", "2")
        if not (build / "picoquic" / "libpicoquic-core.a").is_file():
            raise AssertionError("required picoquic-core dependency did not build")
        if (build / "picoquic" / "picoquicdemo").exists():
            raise AssertionError(
                "optional upstream demo was built in the default target"
            )
        print("[PASS] required picoquic library builds; unrelated demos are excluded")

        for prefix in ("/usr", "/opt/quictun"):
            stage = temp / ("stage_usr" if prefix == "/usr" else "stage_opt")
            env = dict(os.environ, DESTDIR=str(stage))
            run("cmake", "--install", str(build), "--prefix", prefix, env=env)
            actual = sorted(
                item.relative_to(stage).as_posix()
                for item in stage.rglob("*")
                if item.is_file()
            )
            expected = ["usr/bin/QUICTun"]
            if actual != expected:
                raise AssertionError(
                    f"Unexpected staged files for prefix={prefix}:\n"
                    f"actual:   {actual}\nexpected: {expected}"
                )
            print(f"[PASS] DESTDIR + --prefix {prefix}: installs only /usr/bin/QUICTun")
    return 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except (subprocess.CalledProcessError, AssertionError) as exc:
        print(f"[FAIL] install regression: {exc}", file=sys.stderr)
        sys.exit(1)
