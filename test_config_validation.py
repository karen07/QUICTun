#!/usr/bin/env python3
import os
import shutil
import socket
import subprocess
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Optional

DEFAULT_BIN = Path("./build/QUICTun")

CLIENT_QUIC_PORT = 18443
CLIENT_WG_PORT = 16000
SERVER_QUIC_PORT = 18443
SERVER_WG_PORT_BASE = 16000

TEST_DIR = Path("./test_config_validation")


@dataclass
class Case:
    name: str
    config_text: Optional[str]
    expect_substring: str
    use_missing_file: bool = False
    no_args: bool = False
    certs_layout: Optional[str] = None
    occupy_port_field: Optional[str] = None


def run_cmd(argv: list[str]) -> subprocess.CompletedProcess:
    return subprocess.run(
        argv,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
    )


def prepare_test_dir() -> None:
    TEST_DIR.mkdir(parents=True, exist_ok=True)

    for path in TEST_DIR.iterdir():
        if path.is_file():
            path.unlink()
        elif path.is_dir():
            shutil.rmtree(path)


def make_certs_dir(base: Path, layout: str) -> Path:
    certs_dir = base
    certs_dir.mkdir(parents=True, exist_ok=True)

    if layout == "missing_cert_pem":
        (certs_dir / "cert.key").write_text("dummy key\n", encoding="utf-8")
        (certs_dir / "ca.pem").write_text("dummy ca\n", encoding="utf-8")
    elif layout == "missing_cert_key":
        (certs_dir / "cert.pem").write_text("dummy cert\n", encoding="utf-8")
        (certs_dir / "ca.pem").write_text("dummy ca\n", encoding="utf-8")
    elif layout == "missing_ca_pem":
        (certs_dir / "cert.pem").write_text("dummy cert\n", encoding="utf-8")
        (certs_dir / "cert.key").write_text("dummy key\n", encoding="utf-8")
    elif layout == "invalid_ca_pem":
        (certs_dir / "cert.pem").write_text("dummy cert\n", encoding="utf-8")
        (certs_dir / "cert.key").write_text("dummy key\n", encoding="utf-8")
        (certs_dir / "ca.pem").write_text("this is not a pem file\n", encoding="utf-8")
    else:
        raise ValueError(f"unknown certs layout: {layout}")

    return certs_dir


def run_case(bin_path: Path, case: Case, idx: int) -> tuple[bool, str]:
    if case.no_args:
        proc = run_cmd([str(bin_path)])
        output = proc.stdout + proc.stderr
        ok = proc.returncode != 0 and case.expect_substring in output
        return ok, output

    if case.use_missing_file:
        missing = TEST_DIR / "missing.conf"
        if missing.exists():
            missing.unlink()
        proc = run_cmd([str(bin_path), str(missing)])
        output = proc.stdout + proc.stderr
        ok = proc.returncode != 0 and case.expect_substring in output
        return ok, output

    assert case.config_text is not None

    conf_path = TEST_DIR / f"{idx}.conf"
    config_text = f"# {case.name}\n{case.config_text}"

    if case.certs_layout is not None:
        certs_dir = TEST_DIR / f"{idx}_certs"
        make_certs_dir(certs_dir, case.certs_layout)
        config_text = config_text.replace(
            "/tmp/quictun-certs", str(certs_dir.resolve())
        )

    conf_path.write_text(config_text, encoding="utf-8")

    occupied_sock = None
    if case.occupy_port_field is not None:
        occupied_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        occupied_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)

        if case.occupy_port_field == "QuicListen":
            occupied_sock.bind(("127.0.0.1", SERVER_QUIC_PORT))
        elif case.occupy_port_field == "WgListen":
            occupied_sock.bind(("127.0.0.1", CLIENT_WG_PORT))
        else:
            raise ValueError(f"unknown occupy_port_field: {case.occupy_port_field}")

    try:
        proc = run_cmd([str(bin_path), str(conf_path)])
    finally:
        if occupied_sock is not None:
            occupied_sock.close()

    output = proc.stdout + proc.stderr
    ok = proc.returncode != 0 and case.expect_substring in output
    return ok, output


def make_many_peers_config(count: int) -> str:
    lines = [
        "[Interface]",
        f"QuicListen = 127.0.0.1:{SERVER_QUIC_PORT}",
        "CertsPath = /tmp/quictun-certs",
        "SNI = example.com",
        "",
    ]
    for i in range(count):
        lines.extend(
            [
                "[Peer]",
                f"PeerCertSHA256 = HASH_{i}",
                f"WgEndpoint = 127.0.0.1:{SERVER_WG_PORT_BASE + i}",
                "",
            ]
        )
    return "\n".join(lines)


def main() -> int:
    bin_path = Path(os.environ.get("QUICTUN_BIN", str(DEFAULT_BIN)))

    if not bin_path.exists():
        print(f"ERROR: binary not found: {bin_path}")
        print("Build it first, for example:")
        print("  cmake -S . -B build -DCMAKE_BUILD_TYPE=Release")
        print("  cmake --build build -j 8")
        return 2

    prepare_test_dir()

    cases = [
        Case(
            name="No config argument",
            config_text=None,
            expect_substring="Usage",
            no_args=True,
        ),
        Case(
            name="Config file missing",
            config_text=None,
            expect_substring="Config parse failed",
            use_missing_file=True,
        ),
        Case(
            name="Malformed config syntax",
            config_text=f"""\
[Interface]
QuicEndpoint 127.0.0.1:{CLIENT_QUIC_PORT}
WgListen = 127.0.0.1:{CLIENT_WG_PORT}
CertsPath = /tmp/quictun-certs
SNI = example.com
""",
            expect_substring="config parse error:",
        ),
        Case(
            name="Invalid addr:port",
            config_text=f"""\
[Interface]
QuicEndpoint = not_an_ip:{CLIENT_QUIC_PORT}
WgListen = 127.0.0.1:{CLIENT_WG_PORT}
CertsPath = /tmp/quictun-certs
SNI = example.com
""",
            expect_substring="config parse error:",
        ),
        Case(
            name="IPv6 without brackets",
            config_text=f"""\
[Interface]
QuicEndpoint = 2001:db8::1:{CLIENT_QUIC_PORT}
WgListen = 127.0.0.1:{CLIENT_WG_PORT}
CertsPath = /tmp/quictun-certs
SNI = example.com
""",
            expect_substring="config parse error:",
        ),
        Case(
            name="Port zero",
            config_text="""\
[Interface]
QuicEndpoint = 127.0.0.1:0
WgListen = 127.0.0.1:16000
CertsPath = /tmp/quictun-certs
SNI = example.com
""",
            expect_substring="config parse error:",
        ),
        Case(
            name="Port > 65535",
            config_text="""\
[Interface]
QuicEndpoint = 127.0.0.1:70000
WgListen = 127.0.0.1:16000
CertsPath = /tmp/quictun-certs
SNI = example.com
""",
            expect_substring="config parse error:",
        ),
        Case(
            name="QuicListen unspecified 0.0.0.0",
            config_text=f"""\
[Interface]
QuicListen = 0.0.0.0:{SERVER_QUIC_PORT}
CertsPath = /tmp/quictun-certs
SNI = example.com

[Peer]
PeerCertSHA256 = HASH_1
WgEndpoint = 127.0.0.1:{SERVER_WG_PORT_BASE}
""",
            expect_substring="config parse error:",
        ),
        Case(
            name="QuicListen unspecified [::]",
            config_text=f"""\
[Interface]
QuicListen = [::]:{SERVER_QUIC_PORT}
CertsPath = /tmp/quictun-certs
SNI = example.com

[Peer]
PeerCertSHA256 = HASH_1
WgEndpoint = 127.0.0.1:{SERVER_WG_PORT_BASE}
""",
            expect_substring="config parse error:",
        ),
        Case(
            name="QuicEndpoint unspecified 0.0.0.0",
            config_text=f"""\
[Interface]
QuicEndpoint = 0.0.0.0:{CLIENT_QUIC_PORT}
WgListen = 127.0.0.1:{CLIENT_WG_PORT}
CertsPath = /tmp/quictun-certs
SNI = example.com
""",
            expect_substring="config parse error:",
        ),
        Case(
            name="QuicEndpoint unspecified [::]",
            config_text=f"""\
[Interface]
QuicEndpoint = [::]:{CLIENT_QUIC_PORT}
WgListen = 127.0.0.1:{CLIENT_WG_PORT}
CertsPath = /tmp/quictun-certs
SNI = example.com
""",
            expect_substring="config parse error:",
        ),
        Case(
            name="WgListen unspecified 0.0.0.0",
            config_text=f"""\
[Interface]
QuicEndpoint = 127.0.0.1:{CLIENT_QUIC_PORT}
WgListen = 0.0.0.0:{CLIENT_WG_PORT}
CertsPath = /tmp/quictun-certs
SNI = example.com
""",
            expect_substring="config parse error:",
        ),
        Case(
            name="WgListen unspecified [::]",
            config_text=f"""\
[Interface]
QuicEndpoint = 127.0.0.1:{CLIENT_QUIC_PORT}
WgListen = [::]:{CLIENT_WG_PORT}
CertsPath = /tmp/quictun-certs
SNI = example.com
""",
            expect_substring="config parse error:",
        ),
        Case(
            name="WgEndpoint unspecified 0.0.0.0",
            config_text=f"""\
[Interface]
QuicListen = 127.0.0.1:{SERVER_QUIC_PORT}
CertsPath = /tmp/quictun-certs
SNI = example.com

[Peer]
PeerCertSHA256 = HASH_1
WgEndpoint = 0.0.0.0:{SERVER_WG_PORT_BASE}
""",
            expect_substring="config parse error:",
        ),
        Case(
            name="WgEndpoint unspecified [::]",
            config_text=f"""\
[Interface]
QuicListen = 127.0.0.1:{SERVER_QUIC_PORT}
CertsPath = /tmp/quictun-certs
SNI = example.com

[Peer]
PeerCertSHA256 = HASH_1
WgEndpoint = [::]:{SERVER_WG_PORT_BASE}
""",
            expect_substring="config parse error:",
        ),
        Case(
            name="Duplicate PeerCertSHA256",
            config_text=f"""\
[Interface]
QuicListen = 127.0.0.1:{SERVER_QUIC_PORT}
CertsPath = /tmp/quictun-certs
SNI = example.com

[Peer]
PeerCertSHA256 = SAME_HASH
WgEndpoint = 127.0.0.1:{SERVER_WG_PORT_BASE}

[Peer]
PeerCertSHA256 = SAME_HASH
WgEndpoint = 127.0.0.1:{SERVER_WG_PORT_BASE + 1}
""",
            expect_substring="duplicate key or section",
        ),
        Case(
            name="Peer without PeerCertSHA256",
            config_text=f"""\
[Interface]
QuicListen = 127.0.0.1:{SERVER_QUIC_PORT}
CertsPath = /tmp/quictun-certs
SNI = example.com

[Peer]
WgEndpoint = 127.0.0.1:{SERVER_WG_PORT_BASE}
""",
            expect_substring="config parse error:",
        ),
        Case(
            name="Peer without WgEndpoint",
            config_text=f"""\
[Interface]
QuicListen = 127.0.0.1:{SERVER_QUIC_PORT}
CertsPath = /tmp/quictun-certs
SNI = example.com

[Peer]
PeerCertSHA256 = HASH_1
""",
            expect_substring="config parse error:",
        ),
        Case(
            name="Missing CertsPath",
            config_text=f"""\
[Interface]
QuicEndpoint = 127.0.0.1:{CLIENT_QUIC_PORT}
WgListen = 127.0.0.1:{CLIENT_WG_PORT}
SNI = example.com
""",
            expect_substring="CertsPath is required",
        ),
        Case(
            name="Missing SNI",
            config_text=f"""\
[Interface]
QuicEndpoint = 127.0.0.1:{CLIENT_QUIC_PORT}
WgListen = 127.0.0.1:{CLIENT_WG_PORT}
CertsPath = /tmp/quictun-certs
""",
            expect_substring="SNI is required",
        ),
        Case(
            name="CertsPath directory exists but cert.pem is missing",
            config_text=f"""\
[Interface]
QuicEndpoint = 127.0.0.1:{CLIENT_QUIC_PORT}
WgListen = 127.0.0.1:{CLIENT_WG_PORT}
CertsPath = /tmp/quictun-certs
SNI = example.com
""",
            expect_substring="Picoquic create failed",
            certs_layout="missing_cert_pem",
        ),
        Case(
            name="CertsPath directory exists but cert.key is missing",
            config_text=f"""\
[Interface]
QuicEndpoint = 127.0.0.1:{CLIENT_QUIC_PORT}
WgListen = 127.0.0.1:{CLIENT_WG_PORT}
CertsPath = /tmp/quictun-certs
SNI = example.com
""",
            expect_substring="Picoquic create failed",
            certs_layout="missing_cert_key",
        ),
        Case(
            name="Server mode: ca.pem is missing",
            config_text=f"""\
[Interface]
QuicListen = 127.0.0.1:{SERVER_QUIC_PORT}
CertsPath = /tmp/quictun-certs
SNI = example.com

[Peer]
PeerCertSHA256 = HASH_1
WgEndpoint = 127.0.0.1:{SERVER_WG_PORT_BASE}
""",
            expect_substring="Picoquic create failed",
            certs_layout="missing_ca_pem",
        ),
        Case(
            name="Server mode: ca.pem is invalid",
            config_text=f"""\
[Interface]
QuicListen = 127.0.0.1:{SERVER_QUIC_PORT}
CertsPath = /tmp/quictun-certs
SNI = example.com

[Peer]
PeerCertSHA256 = HASH_1
WgEndpoint = 127.0.0.1:{SERVER_WG_PORT_BASE}
""",
            expect_substring="Picoquic create failed",
            certs_layout="invalid_ca_pem",
        ),
        Case(
            name="Occupied QuicListen port",
            config_text=f"""\
[Interface]
QuicListen = 127.0.0.1:{SERVER_QUIC_PORT}
CertsPath = /tmp/quictun-certs
SNI = example.com

[Peer]
PeerCertSHA256 = HASH_1
WgEndpoint = 127.0.0.1:{SERVER_WG_PORT_BASE}
""",
            expect_substring="Can't bind to quic listen",
            occupy_port_field="QuicListen",
        ),
        Case(
            name="Occupied WgListen port",
            config_text=f"""\
[Interface]
QuicEndpoint = 127.0.0.1:{CLIENT_QUIC_PORT}
WgListen = 127.0.0.1:{CLIENT_WG_PORT}
CertsPath = /tmp/quictun-certs
SNI = example.com
""",
            expect_substring="Can't bind to wg listen",
            occupy_port_field="WgListen",
        ),
        Case(
            name="Both client and server mode selected",
            config_text=f"""\
[Interface]
QuicListen = 127.0.0.1:{SERVER_QUIC_PORT}
QuicEndpoint = 127.0.0.1:{CLIENT_QUIC_PORT}
WgListen = 127.0.0.1:{CLIENT_WG_PORT}
CertsPath = /tmp/quictun-certs
SNI = example.com

[Peer]
PeerCertSHA256 = HASH_1
WgEndpoint = 127.0.0.1:{SERVER_WG_PORT_BASE}
""",
            expect_substring="Choose exactly one mode",
        ),
        Case(
            name="No mode selected",
            config_text="""\
[Interface]
CertsPath = /tmp/quictun-certs
SNI = example.com
""",
            expect_substring="Choose exactly one mode:",
        ),
        Case(
            name="Server mode without peers",
            config_text=f"""\
[Interface]
QuicListen = 127.0.0.1:{SERVER_QUIC_PORT}
CertsPath = /tmp/quictun-certs
SNI = example.com
""",
            expect_substring="Server mode requires at least one [Peer]",
        ),
        Case(
            name="Key outside section",
            config_text=f"""\
QuicListen = 127.0.0.1:{SERVER_QUIC_PORT}
CertsPath = /tmp/quictun-certs
SNI = example.com
""",
            expect_substring="config parse error:",
        ),
        Case(
            name="Unknown section",
            config_text="""\
[Foo]
Bar = baz
""",
            expect_substring="config parse error:",
        ),
        Case(
            name="Unknown key in Interface",
            config_text=f"""\
[Interface]
QuicEndpoint = 127.0.0.1:{CLIENT_QUIC_PORT}
WgListen = 127.0.0.1:{CLIENT_WG_PORT}
CertsPath = /tmp/quictun-certs
SNI = example.com
Foo = bar
""",
            expect_substring="config parse error:",
        ),
        Case(
            name="Unknown key in Peer",
            config_text=f"""\
[Interface]
QuicListen = 127.0.0.1:{SERVER_QUIC_PORT}
CertsPath = /tmp/quictun-certs
SNI = example.com

[Peer]
PeerCertSHA256 = HASH_1
WgEndpoint = 127.0.0.1:{SERVER_WG_PORT_BASE}
Foo = bar
""",
            expect_substring="config parse error:",
        ),
        Case(
            name="Too many peers",
            config_text=make_many_peers_config(33),
            expect_substring="config parse error:",
        ),
        Case(
            name="Empty CertsPath",
            config_text=f"""\
[Interface]
QuicEndpoint = 127.0.0.1:{CLIENT_QUIC_PORT}
WgListen = 127.0.0.1:{CLIENT_WG_PORT}
CertsPath =
SNI = example.com
""",
            expect_substring="config parse error:",
        ),
        Case(
            name="Empty SNI",
            config_text=f"""\
[Interface]
QuicEndpoint = 127.0.0.1:{CLIENT_QUIC_PORT}
WgListen = 127.0.0.1:{CLIENT_WG_PORT}
CertsPath = /tmp/quictun-certs
SNI =
""",
            expect_substring="config parse error:",
        ),
        Case(
            name="Empty PeerCertSHA256",
            config_text=f"""\
[Interface]
QuicListen = 127.0.0.1:{SERVER_QUIC_PORT}
CertsPath = /tmp/quictun-certs
SNI = example.com

[Peer]
PeerCertSHA256 =
WgEndpoint = 127.0.0.1:{SERVER_WG_PORT_BASE}
""",
            expect_substring="config parse error:",
        ),
        Case(
            name="Empty WgEndpoint",
            config_text=f"""\
[Interface]
QuicListen = 127.0.0.1:{SERVER_QUIC_PORT}
CertsPath = /tmp/quictun-certs
SNI = example.com

[Peer]
PeerCertSHA256 = HASH_1
WgEndpoint =
""",
            expect_substring="config parse error:",
        ),
        Case(
            name="Only QuicEndpoint",
            config_text=f"""\
[Interface]
QuicEndpoint = 127.0.0.1:{CLIENT_QUIC_PORT}
CertsPath = /tmp/quictun-certs
SNI = example.com
""",
            expect_substring="Choose exactly one mode:",
        ),
        Case(
            name="Only WgListen",
            config_text=f"""\
[Interface]
WgListen = 127.0.0.1:{CLIENT_WG_PORT}
CertsPath = /tmp/quictun-certs
SNI = example.com
""",
            expect_substring="Choose exactly one mode:",
        ),
        Case(
            name="Negative port",
            config_text="""\
[Interface]
QuicEndpoint = 127.0.0.1:-1
WgListen = 127.0.0.1:16000
CertsPath = /tmp/quictun-certs
SNI = example.com
""",
            expect_substring="config parse error:",
        ),
        Case(
            name="Garbage after port",
            config_text="""\
[Interface]
QuicEndpoint = 127.0.0.1:18443 abc
WgListen = 127.0.0.1:16000
CertsPath = /tmp/quictun-certs
SNI = example.com
""",
            expect_substring="config parse error:",
        ),
        Case(
            name="Empty key",
            config_text="""\
[Interface]
= value
CertsPath = /tmp/quictun-certs
SNI = example.com
""",
            expect_substring="config parse error:",
        ),
        Case(
            name="Duplicate SNI",
            config_text=f"""\
[Interface]
QuicEndpoint = 127.0.0.1:{CLIENT_QUIC_PORT}
WgListen = 127.0.0.1:{CLIENT_WG_PORT}
CertsPath = /tmp/quictun-certs
SNI = first.example.com
SNI = second.example.com
""",
            expect_substring="duplicate key or section",
        ),
        Case(
            name="Duplicate PeerCertSHA256 in same peer",
            config_text=f"""\
[Interface]
QuicListen = 127.0.0.1:{SERVER_QUIC_PORT}
CertsPath = /tmp/quictun-certs
SNI = example.com

[Peer]
PeerCertSHA256 = HASH_1
PeerCertSHA256 = HASH_2
WgEndpoint = 127.0.0.1:{SERVER_WG_PORT_BASE}
""",
            expect_substring="duplicate key or section",
        ),
        Case(
            name="Duplicate WgEndpoint in same peer",
            config_text=f"""\
[Interface]
QuicListen = 127.0.0.1:{SERVER_QUIC_PORT}
CertsPath = /tmp/quictun-certs
SNI = example.com

[Peer]
PeerCertSHA256 = HASH_1
WgEndpoint = 127.0.0.1:{SERVER_WG_PORT_BASE}
WgEndpoint = 127.0.0.1:{SERVER_WG_PORT_BASE + 1}
""",
            expect_substring="duplicate key or section",
        ),
        Case(
            name="Duplicate QuicListen",
            config_text=f"""\
[Interface]
QuicListen = 127.0.0.1:{SERVER_QUIC_PORT}
QuicListen = 127.0.0.1:{SERVER_QUIC_PORT + 1}
CertsPath = /tmp/quictun-certs
SNI = example.com

[Peer]
PeerCertSHA256 = HASH_1
WgEndpoint = 127.0.0.1:{SERVER_WG_PORT_BASE}
""",
            expect_substring="duplicate key or section",
        ),
        Case(
            name="Duplicate QuicEndpoint",
            config_text=f"""\
[Interface]
QuicEndpoint = 127.0.0.1:{CLIENT_QUIC_PORT}
QuicEndpoint = 127.0.0.1:{CLIENT_QUIC_PORT + 1}
WgListen = 127.0.0.1:{CLIENT_WG_PORT}
CertsPath = /tmp/quictun-certs
SNI = example.com
""",
            expect_substring="duplicate key or section",
        ),
        Case(
            name="Duplicate WgListen",
            config_text=f"""\
[Interface]
QuicEndpoint = 127.0.0.1:{CLIENT_QUIC_PORT}
WgListen = 127.0.0.1:{CLIENT_WG_PORT}
WgListen = 127.0.0.1:{CLIENT_WG_PORT + 1}
CertsPath = /tmp/quictun-certs
SNI = example.com
""",
            expect_substring="duplicate key or section",
        ),
        Case(
            name="Duplicate CertsPath",
            config_text=f"""\
[Interface]
QuicEndpoint = 127.0.0.1:{CLIENT_QUIC_PORT}
WgListen = 127.0.0.1:{CLIENT_WG_PORT}
CertsPath = /tmp/quictun-certs
CertsPath = /tmp/other-certs
SNI = example.com
""",
            expect_substring="duplicate key or section",
        ),
        Case(
            name="Duplicate LogPath",
            config_text=f"""\
[Interface]
QuicEndpoint = 127.0.0.1:{CLIENT_QUIC_PORT}
WgListen = 127.0.0.1:{CLIENT_WG_PORT}
CertsPath = /tmp/quictun-certs
SNI = example.com
LogPath = /tmp/a.log
LogPath = /tmp/b.log
""",
            expect_substring="duplicate key or section",
        ),
        Case(
            name="Duplicate StatPath",
            config_text=f"""\
[Interface]
QuicEndpoint = 127.0.0.1:{CLIENT_QUIC_PORT}
WgListen = 127.0.0.1:{CLIENT_WG_PORT}
CertsPath = /tmp/quictun-certs
SNI = example.com
StatPath = /tmp/a.stat
StatPath = /tmp/b.stat
""",
            expect_substring="duplicate key or section",
        ),
        Case(
            name="Multiple Interface sections",
            config_text=f"""\
[Interface]
QuicEndpoint = 127.0.0.1:{CLIENT_QUIC_PORT}
WgListen = 127.0.0.1:{CLIENT_WG_PORT}
CertsPath = /tmp/quictun-certs
SNI = first.example.com

[Interface]
SNI = second.example.com
""",
            expect_substring="duplicate key or section",
        ),
    ]

    passed = 0
    failed = 0

    print(f"Using binary: {bin_path}")
    print(f"Configs directory: {TEST_DIR.resolve()}")
    print("")

    for idx, case in enumerate(cases, start=1):
        ok, output = run_case(bin_path, case, idx)

        if ok:
            passed += 1
            print(f"[PASS] {idx:02d} {case.name}")
        else:
            failed += 1
            print(f"[FAIL] {idx:02d} {case.name}")
            print(f"       expected substring: {case.expect_substring!r}")
            if not case.no_args:
                if case.use_missing_file:
                    print(
                        f"       config path: {(TEST_DIR / 'missing.conf').resolve()}"
                    )
                else:
                    print(f"       config path: {(TEST_DIR / f'{idx}.conf').resolve()}")
            print("       output:")
            for line in output.splitlines():
                print(f"         {line}")
            if not output.strip():
                print("         <empty>")
            print("")

    print("")
    print(f"RESULT: passed={passed}, failed={failed}, total={len(cases)}")
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
