#!/usr/bin/env python3
"""QUICTun configuration regressions and authenticated QUIC/UDP E2E tests.

The load suite imports this module to share QUIC certificate/setup helpers.
"""

import json
import os
import re
import shutil
import signal
import socket
import subprocess
import sys
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Optional

# --- Configuration regression tests ---

CONFIG_DEFAULT_BIN = Path("./build/QUICTun")

CONFIG_CLIENT_QUIC_PORT = 18443
CONFIG_CLIENT_WG_PORT = 16000
CONFIG_SERVER_QUIC_PORT = 18443
CONFIG_SERVER_WG_PORT_BASE = 16000

CONFIG_TEST_DIR = Path("./test_config_validation")
CONFIG_CMD_TIMEOUT = 10


@dataclass
class ConfigCase:
    name: str
    config_text: Optional[str]
    expect_substring: str
    use_missing_file: bool = False
    no_args: bool = False
    certs_layout: Optional[str] = None
    occupy_port_field: Optional[str] = None


def config_run_cmd(argv: list[str]) -> subprocess.CompletedProcess:
    try:
        return subprocess.run(
            argv,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            timeout=CONFIG_CMD_TIMEOUT,
        )
    except subprocess.TimeoutExpired as exc:
        raise RuntimeError(
            f"configuration command timed out after {CONFIG_CMD_TIMEOUT}s: {argv!r}"
        ) from exc


def config_prepare_test_dir() -> None:
    CONFIG_TEST_DIR.mkdir(parents=True, exist_ok=True)

    for path in CONFIG_TEST_DIR.iterdir():
        if path.is_file():
            path.unlink()
        elif path.is_dir():
            shutil.rmtree(path)


def config_make_certs_dir(base: Path, layout: str) -> Path:
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


def config_run_case(bin_path: Path, case: ConfigCase, idx: int) -> tuple[bool, str]:
    if case.no_args:
        proc = config_run_cmd([str(bin_path)])
        output = proc.stdout + proc.stderr
        ok = proc.returncode != 0 and case.expect_substring in output
        return ok, output

    if case.use_missing_file:
        missing = CONFIG_TEST_DIR / "missing.conf"
        if missing.exists():
            missing.unlink()
        proc = config_run_cmd([str(bin_path), str(missing)])
        output = proc.stdout + proc.stderr
        ok = proc.returncode != 0 and case.expect_substring in output
        return ok, output

    assert case.config_text is not None

    conf_path = CONFIG_TEST_DIR / f"{idx}.conf"
    config_text = f"# {case.name}\n{case.config_text}"

    if case.certs_layout is not None:
        certs_dir = CONFIG_TEST_DIR / f"{idx}_certs"
        config_make_certs_dir(certs_dir, case.certs_layout)
        config_text = config_text.replace(
            "/tmp/quictun-certs", str(certs_dir.resolve())
        )

    conf_path.write_text(config_text, encoding="utf-8")

    occupied_sock = None
    if case.occupy_port_field is not None:
        occupied_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        occupied_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)

        if case.occupy_port_field == "QuicListen":
            occupied_sock.bind(("127.0.0.1", CONFIG_SERVER_QUIC_PORT))
        elif case.occupy_port_field == "WgListen":
            occupied_sock.bind(("127.0.0.1", CONFIG_CLIENT_WG_PORT))
        else:
            raise ValueError(f"unknown occupy_port_field: {case.occupy_port_field}")

    try:
        proc = config_run_cmd([str(bin_path), str(conf_path)])
    finally:
        if occupied_sock is not None:
            occupied_sock.close()

    output = proc.stdout + proc.stderr
    ok = proc.returncode != 0 and case.expect_substring in output
    return ok, output


def config_make_many_peers_config(count: int) -> str:
    lines = [
        "[Interface]",
        f"QuicListen = 127.0.0.1:{CONFIG_SERVER_QUIC_PORT}",
        "CertsPath = /tmp/quictun-certs",
        "SNI = example.com",
        "",
    ]
    for i in range(count):
        lines.extend(
            [
                "[Peer]",
                f"PeerCertSHA256 = HASH_{i}",
                f"WgEndpoint = 127.0.0.1:{CONFIG_SERVER_WG_PORT_BASE + i}",
                "",
            ]
        )
    return "\n".join(lines)


def config_main() -> int:
    bin_path = Path(os.environ.get("QUICTUN_BIN", str(CONFIG_DEFAULT_BIN)))

    if not bin_path.exists():
        print(f"ERROR: binary not found: {bin_path}")
        print("Build it first, for example:")
        print("  cmake -S . -B build -DCMAKE_BUILD_TYPE=Release")
        print("  cmake --build build -j 8")
        return 2

    config_prepare_test_dir()

    cases = [
        ConfigCase(
            name="No config argument",
            config_text=None,
            expect_substring="Usage",
            no_args=True,
        ),
        ConfigCase(
            name="Config file missing",
            config_text=None,
            expect_substring="Config parse failed",
            use_missing_file=True,
        ),
        ConfigCase(
            name="Malformed config syntax",
            config_text=f"""\
[Interface]
QuicEndpoint 127.0.0.1:{CONFIG_CLIENT_QUIC_PORT}
WgListen = 127.0.0.1:{CONFIG_CLIENT_WG_PORT}
CertsPath = /tmp/quictun-certs
SNI = example.com
""",
            expect_substring="config parse error:",
        ),
        ConfigCase(
            name="Invalid addr:port",
            config_text=f"""\
[Interface]
QuicEndpoint = not_an_ip:{CONFIG_CLIENT_QUIC_PORT}
WgListen = 127.0.0.1:{CONFIG_CLIENT_WG_PORT}
CertsPath = /tmp/quictun-certs
SNI = example.com
""",
            expect_substring="config parse error:",
        ),
        ConfigCase(
            name="IPv6 without brackets",
            config_text=f"""\
[Interface]
QuicEndpoint = 2001:db8::1:{CONFIG_CLIENT_QUIC_PORT}
WgListen = 127.0.0.1:{CONFIG_CLIENT_WG_PORT}
CertsPath = /tmp/quictun-certs
SNI = example.com
""",
            expect_substring="config parse error:",
        ),
        ConfigCase(
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
        ConfigCase(
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
        ConfigCase(
            name="QuicListen unspecified 0.0.0.0",
            config_text=f"""\
[Interface]
QuicListen = 0.0.0.0:{CONFIG_SERVER_QUIC_PORT}
CertsPath = /tmp/quictun-certs
SNI = example.com

[Peer]
PeerCertSHA256 = HASH_1
WgEndpoint = 127.0.0.1:{CONFIG_SERVER_WG_PORT_BASE}
""",
            expect_substring="config parse error:",
        ),
        ConfigCase(
            name="QuicListen unspecified [::]",
            config_text=f"""\
[Interface]
QuicListen = [::]:{CONFIG_SERVER_QUIC_PORT}
CertsPath = /tmp/quictun-certs
SNI = example.com

[Peer]
PeerCertSHA256 = HASH_1
WgEndpoint = 127.0.0.1:{CONFIG_SERVER_WG_PORT_BASE}
""",
            expect_substring="config parse error:",
        ),
        ConfigCase(
            name="QuicEndpoint unspecified 0.0.0.0",
            config_text=f"""\
[Interface]
QuicEndpoint = 0.0.0.0:{CONFIG_CLIENT_QUIC_PORT}
WgListen = 127.0.0.1:{CONFIG_CLIENT_WG_PORT}
CertsPath = /tmp/quictun-certs
SNI = example.com
""",
            expect_substring="config parse error:",
        ),
        ConfigCase(
            name="QuicEndpoint unspecified [::]",
            config_text=f"""\
[Interface]
QuicEndpoint = [::]:{CONFIG_CLIENT_QUIC_PORT}
WgListen = 127.0.0.1:{CONFIG_CLIENT_WG_PORT}
CertsPath = /tmp/quictun-certs
SNI = example.com
""",
            expect_substring="config parse error:",
        ),
        ConfigCase(
            name="WgListen unspecified 0.0.0.0",
            config_text=f"""\
[Interface]
QuicEndpoint = 127.0.0.1:{CONFIG_CLIENT_QUIC_PORT}
WgListen = 0.0.0.0:{CONFIG_CLIENT_WG_PORT}
CertsPath = /tmp/quictun-certs
SNI = example.com
""",
            expect_substring="config parse error:",
        ),
        ConfigCase(
            name="WgListen unspecified [::]",
            config_text=f"""\
[Interface]
QuicEndpoint = 127.0.0.1:{CONFIG_CLIENT_QUIC_PORT}
WgListen = [::]:{CONFIG_CLIENT_WG_PORT}
CertsPath = /tmp/quictun-certs
SNI = example.com
""",
            expect_substring="config parse error:",
        ),
        ConfigCase(
            name="WgEndpoint unspecified 0.0.0.0",
            config_text=f"""\
[Interface]
QuicListen = 127.0.0.1:{CONFIG_SERVER_QUIC_PORT}
CertsPath = /tmp/quictun-certs
SNI = example.com

[Peer]
PeerCertSHA256 = HASH_1
WgEndpoint = 0.0.0.0:{CONFIG_SERVER_WG_PORT_BASE}
""",
            expect_substring="config parse error:",
        ),
        ConfigCase(
            name="WgEndpoint unspecified [::]",
            config_text=f"""\
[Interface]
QuicListen = 127.0.0.1:{CONFIG_SERVER_QUIC_PORT}
CertsPath = /tmp/quictun-certs
SNI = example.com

[Peer]
PeerCertSHA256 = HASH_1
WgEndpoint = [::]:{CONFIG_SERVER_WG_PORT_BASE}
""",
            expect_substring="config parse error:",
        ),
        ConfigCase(
            name="Duplicate PeerCertSHA256",
            config_text=f"""\
[Interface]
QuicListen = 127.0.0.1:{CONFIG_SERVER_QUIC_PORT}
CertsPath = /tmp/quictun-certs
SNI = example.com

[Peer]
PeerCertSHA256 = SAME_HASH
WgEndpoint = 127.0.0.1:{CONFIG_SERVER_WG_PORT_BASE}

[Peer]
PeerCertSHA256 = SAME_HASH
WgEndpoint = 127.0.0.1:{CONFIG_SERVER_WG_PORT_BASE + 1}
""",
            expect_substring="duplicate key or section",
        ),
        ConfigCase(
            name="Peer without PeerCertSHA256",
            config_text=f"""\
[Interface]
QuicListen = 127.0.0.1:{CONFIG_SERVER_QUIC_PORT}
CertsPath = /tmp/quictun-certs
SNI = example.com

[Peer]
WgEndpoint = 127.0.0.1:{CONFIG_SERVER_WG_PORT_BASE}
""",
            expect_substring="config parse error:",
        ),
        ConfigCase(
            name="Peer without WgEndpoint",
            config_text=f"""\
[Interface]
QuicListen = 127.0.0.1:{CONFIG_SERVER_QUIC_PORT}
CertsPath = /tmp/quictun-certs
SNI = example.com

[Peer]
PeerCertSHA256 = HASH_1
""",
            expect_substring="config parse error:",
        ),
        ConfigCase(
            name="Missing CertsPath",
            config_text=f"""\
[Interface]
QuicEndpoint = 127.0.0.1:{CONFIG_CLIENT_QUIC_PORT}
WgListen = 127.0.0.1:{CONFIG_CLIENT_WG_PORT}
SNI = example.com
""",
            expect_substring="CertsPath is required",
        ),
        ConfigCase(
            name="Missing SNI",
            config_text=f"""\
[Interface]
QuicEndpoint = 127.0.0.1:{CONFIG_CLIENT_QUIC_PORT}
WgListen = 127.0.0.1:{CONFIG_CLIENT_WG_PORT}
CertsPath = /tmp/quictun-certs
""",
            expect_substring="SNI is required",
        ),
        ConfigCase(
            name="CertsPath directory exists but cert.pem is missing",
            config_text=f"""\
[Interface]
QuicEndpoint = 127.0.0.1:{CONFIG_CLIENT_QUIC_PORT}
WgListen = 127.0.0.1:{CONFIG_CLIENT_WG_PORT}
CertsPath = /tmp/quictun-certs
SNI = example.com
""",
            expect_substring="Picoquic create failed",
            certs_layout="missing_cert_pem",
        ),
        ConfigCase(
            name="CertsPath directory exists but cert.key is missing",
            config_text=f"""\
[Interface]
QuicEndpoint = 127.0.0.1:{CONFIG_CLIENT_QUIC_PORT}
WgListen = 127.0.0.1:{CONFIG_CLIENT_WG_PORT}
CertsPath = /tmp/quictun-certs
SNI = example.com
""",
            expect_substring="Picoquic create failed",
            certs_layout="missing_cert_key",
        ),
        ConfigCase(
            name="Server mode: ca.pem is missing",
            config_text=f"""\
[Interface]
QuicListen = 127.0.0.1:{CONFIG_SERVER_QUIC_PORT}
CertsPath = /tmp/quictun-certs
SNI = example.com

[Peer]
PeerCertSHA256 = HASH_1
WgEndpoint = 127.0.0.1:{CONFIG_SERVER_WG_PORT_BASE}
""",
            expect_substring="Picoquic create failed",
            certs_layout="missing_ca_pem",
        ),
        ConfigCase(
            name="Server mode: ca.pem is invalid",
            config_text=f"""\
[Interface]
QuicListen = 127.0.0.1:{CONFIG_SERVER_QUIC_PORT}
CertsPath = /tmp/quictun-certs
SNI = example.com

[Peer]
PeerCertSHA256 = HASH_1
WgEndpoint = 127.0.0.1:{CONFIG_SERVER_WG_PORT_BASE}
""",
            expect_substring="Picoquic create failed",
            certs_layout="invalid_ca_pem",
        ),
        ConfigCase(
            name="Occupied QuicListen port",
            config_text=f"""\
[Interface]
QuicListen = 127.0.0.1:{CONFIG_SERVER_QUIC_PORT}
CertsPath = /tmp/quictun-certs
SNI = example.com

[Peer]
PeerCertSHA256 = HASH_1
WgEndpoint = 127.0.0.1:{CONFIG_SERVER_WG_PORT_BASE}
""",
            expect_substring="Can't bind to quic listen",
            occupy_port_field="QuicListen",
        ),
        ConfigCase(
            name="Occupied WgListen port",
            config_text=f"""\
[Interface]
QuicEndpoint = 127.0.0.1:{CONFIG_CLIENT_QUIC_PORT}
WgListen = 127.0.0.1:{CONFIG_CLIENT_WG_PORT}
CertsPath = /tmp/quictun-certs
SNI = example.com
""",
            expect_substring="Can't bind to wg listen",
            occupy_port_field="WgListen",
        ),
        ConfigCase(
            name="Both client and server mode selected",
            config_text=f"""\
[Interface]
QuicListen = 127.0.0.1:{CONFIG_SERVER_QUIC_PORT}
QuicEndpoint = 127.0.0.1:{CONFIG_CLIENT_QUIC_PORT}
WgListen = 127.0.0.1:{CONFIG_CLIENT_WG_PORT}
CertsPath = /tmp/quictun-certs
SNI = example.com

[Peer]
PeerCertSHA256 = HASH_1
WgEndpoint = 127.0.0.1:{CONFIG_SERVER_WG_PORT_BASE}
""",
            expect_substring="Choose exactly one mode",
        ),
        ConfigCase(
            name="No mode selected",
            config_text="""\
[Interface]
CertsPath = /tmp/quictun-certs
SNI = example.com
""",
            expect_substring="Choose exactly one mode:",
        ),
        ConfigCase(
            name="Server mode without peers",
            config_text=f"""\
[Interface]
QuicListen = 127.0.0.1:{CONFIG_SERVER_QUIC_PORT}
CertsPath = /tmp/quictun-certs
SNI = example.com
""",
            expect_substring="Server mode requires at least one [Peer]",
        ),
        ConfigCase(
            name="Key outside section",
            config_text=f"""\
QuicListen = 127.0.0.1:{CONFIG_SERVER_QUIC_PORT}
CertsPath = /tmp/quictun-certs
SNI = example.com
""",
            expect_substring="config parse error:",
        ),
        ConfigCase(
            name="Unknown section",
            config_text="""\
[Foo]
Bar = baz
""",
            expect_substring="config parse error:",
        ),
        ConfigCase(
            name="Unknown key in Interface",
            config_text=f"""\
[Interface]
QuicEndpoint = 127.0.0.1:{CONFIG_CLIENT_QUIC_PORT}
WgListen = 127.0.0.1:{CONFIG_CLIENT_WG_PORT}
CertsPath = /tmp/quictun-certs
SNI = example.com
Foo = bar
""",
            expect_substring="config parse error:",
        ),
        ConfigCase(
            name="Unknown key in Peer",
            config_text=f"""\
[Interface]
QuicListen = 127.0.0.1:{CONFIG_SERVER_QUIC_PORT}
CertsPath = /tmp/quictun-certs
SNI = example.com

[Peer]
PeerCertSHA256 = HASH_1
WgEndpoint = 127.0.0.1:{CONFIG_SERVER_WG_PORT_BASE}
Foo = bar
""",
            expect_substring="config parse error:",
        ),
        ConfigCase(
            name="Too many peers",
            config_text=config_make_many_peers_config(33),
            expect_substring="config parse error:",
        ),
        ConfigCase(
            name="Empty CertsPath",
            config_text=f"""\
[Interface]
QuicEndpoint = 127.0.0.1:{CONFIG_CLIENT_QUIC_PORT}
WgListen = 127.0.0.1:{CONFIG_CLIENT_WG_PORT}
CertsPath =
SNI = example.com
""",
            expect_substring="config parse error:",
        ),
        ConfigCase(
            name="Empty SNI",
            config_text=f"""\
[Interface]
QuicEndpoint = 127.0.0.1:{CONFIG_CLIENT_QUIC_PORT}
WgListen = 127.0.0.1:{CONFIG_CLIENT_WG_PORT}
CertsPath = /tmp/quictun-certs
SNI =
""",
            expect_substring="config parse error:",
        ),
        ConfigCase(
            name="Empty PeerCertSHA256",
            config_text=f"""\
[Interface]
QuicListen = 127.0.0.1:{CONFIG_SERVER_QUIC_PORT}
CertsPath = /tmp/quictun-certs
SNI = example.com

[Peer]
PeerCertSHA256 =
WgEndpoint = 127.0.0.1:{CONFIG_SERVER_WG_PORT_BASE}
""",
            expect_substring="config parse error:",
        ),
        ConfigCase(
            name="Empty WgEndpoint",
            config_text=f"""\
[Interface]
QuicListen = 127.0.0.1:{CONFIG_SERVER_QUIC_PORT}
CertsPath = /tmp/quictun-certs
SNI = example.com

[Peer]
PeerCertSHA256 = HASH_1
WgEndpoint =
""",
            expect_substring="config parse error:",
        ),
        ConfigCase(
            name="Only QuicEndpoint",
            config_text=f"""\
[Interface]
QuicEndpoint = 127.0.0.1:{CONFIG_CLIENT_QUIC_PORT}
CertsPath = /tmp/quictun-certs
SNI = example.com
""",
            expect_substring="Choose exactly one mode:",
        ),
        ConfigCase(
            name="Only WgListen",
            config_text=f"""\
[Interface]
WgListen = 127.0.0.1:{CONFIG_CLIENT_WG_PORT}
CertsPath = /tmp/quictun-certs
SNI = example.com
""",
            expect_substring="Choose exactly one mode:",
        ),
        ConfigCase(
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
        ConfigCase(
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
        ConfigCase(
            name="Empty key",
            config_text="""\
[Interface]
= value
CertsPath = /tmp/quictun-certs
SNI = example.com
""",
            expect_substring="config parse error:",
        ),
        ConfigCase(
            name="Duplicate SNI",
            config_text=f"""\
[Interface]
QuicEndpoint = 127.0.0.1:{CONFIG_CLIENT_QUIC_PORT}
WgListen = 127.0.0.1:{CONFIG_CLIENT_WG_PORT}
CertsPath = /tmp/quictun-certs
SNI = first.example.com
SNI = second.example.com
""",
            expect_substring="duplicate key or section",
        ),
        ConfigCase(
            name="Duplicate PeerCertSHA256 in same peer",
            config_text=f"""\
[Interface]
QuicListen = 127.0.0.1:{CONFIG_SERVER_QUIC_PORT}
CertsPath = /tmp/quictun-certs
SNI = example.com

[Peer]
PeerCertSHA256 = HASH_1
PeerCertSHA256 = HASH_2
WgEndpoint = 127.0.0.1:{CONFIG_SERVER_WG_PORT_BASE}
""",
            expect_substring="duplicate key or section",
        ),
        ConfigCase(
            name="Duplicate WgEndpoint in same peer",
            config_text=f"""\
[Interface]
QuicListen = 127.0.0.1:{CONFIG_SERVER_QUIC_PORT}
CertsPath = /tmp/quictun-certs
SNI = example.com

[Peer]
PeerCertSHA256 = HASH_1
WgEndpoint = 127.0.0.1:{CONFIG_SERVER_WG_PORT_BASE}
WgEndpoint = 127.0.0.1:{CONFIG_SERVER_WG_PORT_BASE + 1}
""",
            expect_substring="duplicate key or section",
        ),
        ConfigCase(
            name="Duplicate QuicListen",
            config_text=f"""\
[Interface]
QuicListen = 127.0.0.1:{CONFIG_SERVER_QUIC_PORT}
QuicListen = 127.0.0.1:{CONFIG_SERVER_QUIC_PORT + 1}
CertsPath = /tmp/quictun-certs
SNI = example.com

[Peer]
PeerCertSHA256 = HASH_1
WgEndpoint = 127.0.0.1:{CONFIG_SERVER_WG_PORT_BASE}
""",
            expect_substring="duplicate key or section",
        ),
        ConfigCase(
            name="Duplicate QuicEndpoint",
            config_text=f"""\
[Interface]
QuicEndpoint = 127.0.0.1:{CONFIG_CLIENT_QUIC_PORT}
QuicEndpoint = 127.0.0.1:{CONFIG_CLIENT_QUIC_PORT + 1}
WgListen = 127.0.0.1:{CONFIG_CLIENT_WG_PORT}
CertsPath = /tmp/quictun-certs
SNI = example.com
""",
            expect_substring="duplicate key or section",
        ),
        ConfigCase(
            name="Duplicate WgListen",
            config_text=f"""\
[Interface]
QuicEndpoint = 127.0.0.1:{CONFIG_CLIENT_QUIC_PORT}
WgListen = 127.0.0.1:{CONFIG_CLIENT_WG_PORT}
WgListen = 127.0.0.1:{CONFIG_CLIENT_WG_PORT + 1}
CertsPath = /tmp/quictun-certs
SNI = example.com
""",
            expect_substring="duplicate key or section",
        ),
        ConfigCase(
            name="Duplicate CertsPath",
            config_text=f"""\
[Interface]
QuicEndpoint = 127.0.0.1:{CONFIG_CLIENT_QUIC_PORT}
WgListen = 127.0.0.1:{CONFIG_CLIENT_WG_PORT}
CertsPath = /tmp/quictun-certs
CertsPath = /tmp/other-certs
SNI = example.com
""",
            expect_substring="duplicate key or section",
        ),
        ConfigCase(
            name="Duplicate LogPath",
            config_text=f"""\
[Interface]
QuicEndpoint = 127.0.0.1:{CONFIG_CLIENT_QUIC_PORT}
WgListen = 127.0.0.1:{CONFIG_CLIENT_WG_PORT}
CertsPath = /tmp/quictun-certs
SNI = example.com
LogPath = /tmp/a.log
LogPath = /tmp/b.log
""",
            expect_substring="duplicate key or section",
        ),
        ConfigCase(
            name="Duplicate StatPath",
            config_text=f"""\
[Interface]
QuicEndpoint = 127.0.0.1:{CONFIG_CLIENT_QUIC_PORT}
WgListen = 127.0.0.1:{CONFIG_CLIENT_WG_PORT}
CertsPath = /tmp/quictun-certs
SNI = example.com
StatPath = /tmp/a.stat
StatPath = /tmp/b.stat
""",
            expect_substring="duplicate key or section",
        ),
        ConfigCase(
            name="Multiple Interface sections",
            config_text=f"""\
[Interface]
QuicEndpoint = 127.0.0.1:{CONFIG_CLIENT_QUIC_PORT}
WgListen = 127.0.0.1:{CONFIG_CLIENT_WG_PORT}
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
    print(f"Configs directory: {CONFIG_TEST_DIR.resolve()}")
    print("")

    for idx, case in enumerate(cases, start=1):
        ok, output = config_run_case(bin_path, case, idx)

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
                        f"       config path: {(CONFIG_TEST_DIR / 'missing.conf').resolve()}"
                    )
                else:
                    print(
                        f"       config path: {(CONFIG_TEST_DIR / f'{idx}.conf').resolve()}"
                    )
            print("       output:")
            for line in output.splitlines():
                print(f"         {line}")
            if not output.strip():
                print("         <empty>")
            print("")

    print("")
    print(f"RESULT: passed={passed}, failed={failed}, total={len(cases)}")
    return 1 if failed else 0


# --- QUIC/UDP end-to-end integration tests ---

DEFAULT_BIN = Path("./build/QUICTun")
TEST_DIR = Path("./test_client_cert_four_phases")

QUIC_SERVER_IP = "127.0.0.1"
QUIC_SERVER_PORT = 18443

CLIENT_WG_LISTEN_IP = "127.0.0.1"
CLIENT_WG_LISTEN_PORT = 16000

SERVER_WG_IP = "127.0.0.1"
SERVER_WG_PORT = 26000

CLIENT_SOURCE_IP = "127.0.0.1"
CLIENT_SOURCE_PORT = 26001

SNI = "example.com"
WRONG_SNI = "wrong.example.com"

SERVER_CA_CN = "Server Root CA"
OTHER_CA_CN = "Other Root CA"
SERVER_CN = "example.com"
CLIENT_CN = "client1"
DAYS = "3650"


def run_cmd(argv: list[str], *, check: bool = True) -> subprocess.CompletedProcess:
    proc = subprocess.run(
        argv,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
    )
    if check and proc.returncode != 0:
        raise RuntimeError(
            f"command failed: {' '.join(argv)}\n"
            f"exit={proc.returncode}\n"
            f"stdout:\n{proc.stdout}\n"
            f"stderr:\n{proc.stderr}"
        )
    return proc


def need_cmd(name: str) -> None:
    if shutil.which(name) is None:
        raise RuntimeError(f"command not found: {name}")


def prepare_test_dir() -> None:
    if TEST_DIR.exists():
        shutil.rmtree(TEST_DIR)

    (TEST_DIR / "certs").mkdir(parents=True, exist_ok=True)
    (TEST_DIR / "configs").mkdir(parents=True, exist_ok=True)
    (TEST_DIR / "logs").mkdir(parents=True, exist_ok=True)
    (TEST_DIR / "stats").mkdir(parents=True, exist_ok=True)
    (TEST_DIR / "baseline").mkdir(parents=True, exist_ok=True)


def clean_runtime_logs() -> None:
    for name in [
        "server.log",
        "client1.log",
        "server.stdout.txt",
        "server.stderr.txt",
        "client.stdout.txt",
        "client.stderr.txt",
    ]:
        p = TEST_DIR / "logs" / name
        if p.exists():
            p.unlink()

    for name in ["server.stat", "client1.stat"]:
        p = TEST_DIR / "stats" / name
        if p.exists():
            p.unlink()


def generate_ed25519_key(path: Path) -> None:
    run_cmd(["openssl", "genpkey", "-algorithm", "ED25519", "-out", str(path)])


def generate_ca(ca_dir: Path, cn: str) -> None:
    ca_dir.mkdir(parents=True, exist_ok=True)

    ca_key = ca_dir / "ca.key"
    ca_pem = ca_dir / "ca.pem"

    generate_ed25519_key(ca_key)

    run_cmd(
        [
            "openssl",
            "req",
            "-new",
            "-x509",
            "-key",
            str(ca_key),
            "-out",
            str(ca_pem),
            "-days",
            DAYS,
            "-subj",
            f"/CN={cn}",
        ]
    )


def generate_signed_cert(cert_dir: Path, cn: str, ca_dir: Path) -> None:
    cert_dir.mkdir(parents=True, exist_ok=True)

    cert_key = cert_dir / "cert.key"
    cert_csr = cert_dir / "cert.csr"
    cert_pem = cert_dir / "cert.pem"

    ca_key = ca_dir / "ca.key"
    ca_pem = ca_dir / "ca.pem"

    if cert_key.exists():
        cert_key.unlink()
    if cert_csr.exists():
        cert_csr.unlink()
    if cert_pem.exists():
        cert_pem.unlink()

    generate_ed25519_key(cert_key)

    run_cmd(
        [
            "openssl",
            "req",
            "-new",
            "-key",
            str(cert_key),
            "-out",
            str(cert_csr),
            "-subj",
            f"/CN={cn}",
        ]
    )

    run_cmd(
        [
            "openssl",
            "x509",
            "-req",
            "-in",
            str(cert_csr),
            "-CA",
            str(ca_pem),
            "-CAkey",
            str(ca_key),
            "-CAcreateserial",
            "-out",
            str(cert_pem),
            "-days",
            DAYS,
        ]
    )

    if cert_csr.exists():
        cert_csr.unlink()

    ca_srl = ca_dir / "ca.srl"
    if ca_srl.exists():
        ca_srl.unlink()


def cert_hash_b64(cert_path: Path) -> str:
    p1 = subprocess.Popen(
        ["openssl", "x509", "-in", str(cert_path), "-outform", "DER"],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=False,
    )
    assert p1.stdout is not None

    p2 = subprocess.Popen(
        ["openssl", "dgst", "-sha256", "-binary"],
        stdin=p1.stdout,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=False,
    )
    p1.stdout.close()
    assert p2.stdout is not None

    p3 = subprocess.Popen(
        ["openssl", "base64", "-A"],
        stdin=p2.stdout,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=False,
    )
    p2.stdout.close()

    out3, err3 = p3.communicate()
    _, err2 = p2.communicate()
    _, err1 = p1.communicate()

    if p1.returncode != 0 or p2.returncode != 0 or p3.returncode != 0:
        raise RuntimeError(
            "failed to calculate cert hash\n"
            f"openssl x509 stderr:\n{err1.decode(errors='replace')}\n"
            f"openssl dgst stderr:\n{err2.decode(errors='replace')}\n"
            f"openssl base64 stderr:\n{err3.decode(errors='replace')}"
        )

    return out3.decode("utf-8").strip()


def generate_initial_layout() -> tuple[Path, Path, str]:
    certs_dir = TEST_DIR / "certs"

    server_ca_dir = certs_dir / "server_ca"
    other_ca_dir = certs_dir / "other_ca"
    server_dir = certs_dir / "server"
    client1_dir = certs_dir / "client1"

    generate_ca(server_ca_dir, SERVER_CA_CN)
    generate_ca(other_ca_dir, OTHER_CA_CN)

    generate_signed_cert(server_dir, SERVER_CN, server_ca_dir)
    generate_signed_cert(client1_dir, CLIENT_CN, server_ca_dir)

    shutil.copy2(server_ca_dir / "ca.pem", client1_dir / "ca.pem")
    shutil.copy2(server_ca_dir / "ca.pem", server_dir / "ca.pem")

    client_hash = cert_hash_b64(client1_dir / "cert.pem")
    return server_dir, client1_dir, client_hash


def replace_client_cert_with_other_ca(client1_dir: Path) -> None:
    other_ca_dir = TEST_DIR / "certs" / "other_ca"
    generate_signed_cert(client1_dir, CLIENT_CN, other_ca_dir)


def save_baseline(
    server_certs: Path,
    client1_certs: Path,
    server_conf: Path,
    client_conf: Path,
) -> None:
    baseline_dir = TEST_DIR / "baseline"

    baseline_server_certs = baseline_dir / "server"
    baseline_client_certs = baseline_dir / "client1"
    baseline_server_conf = baseline_dir / "server.conf"
    baseline_client_conf = baseline_dir / "client1.conf"

    if baseline_server_certs.exists():
        shutil.rmtree(baseline_server_certs)
    if baseline_client_certs.exists():
        shutil.rmtree(baseline_client_certs)

    shutil.copytree(server_certs, baseline_server_certs)
    shutil.copytree(client1_certs, baseline_client_certs)
    shutil.copy2(server_conf, baseline_server_conf)
    shutil.copy2(client_conf, baseline_client_conf)


def restore_baseline() -> tuple[Path, Path, Path, Path]:
    baseline_dir = TEST_DIR / "baseline"

    server_certs = TEST_DIR / "certs" / "server"
    client1_certs = TEST_DIR / "certs" / "client1"
    server_conf = TEST_DIR / "configs" / "server.conf"
    client_conf = TEST_DIR / "configs" / "client1.conf"

    if server_certs.exists():
        shutil.rmtree(server_certs)
    if client1_certs.exists():
        shutil.rmtree(client1_certs)

    shutil.copytree(baseline_dir / "server", server_certs)
    shutil.copytree(baseline_dir / "client1", client1_certs)
    shutil.copy2(baseline_dir / "server.conf", server_conf)
    shutil.copy2(baseline_dir / "client1.conf", client_conf)

    return server_certs, client1_certs, server_conf, client_conf


def replace_client_sni(client_conf: Path, new_sni: str) -> None:
    text = client_conf.read_text(encoding="utf-8")
    lines = text.splitlines()
    replaced = False

    for i, line in enumerate(lines):
        if line.strip().startswith("SNI ="):
            lines[i] = f"SNI = {new_sni}"
            replaced = True
            break

    if not replaced:
        raise RuntimeError("SNI line not found in client config")

    client_conf.write_text("\n".join(lines) + "\n", encoding="utf-8")


def generate_configs(
    server_certs: Path,
    client1_certs: Path,
    peer_hash: str,
) -> tuple[Path, Path]:
    configs_dir = TEST_DIR / "configs"
    logs_dir = TEST_DIR / "logs"
    stats_dir = TEST_DIR / "stats"

    server_conf = configs_dir / "server.conf"
    client_conf = configs_dir / "client1.conf"

    server_conf.write_text(
        f"""# Four-phase E2E test
[Interface]
# Server QUIC listen
QuicListen = {QUIC_SERVER_IP}:{QUIC_SERVER_PORT}
# Server certs directory
CertsPath = {server_certs.resolve()}
# Server log path
LogPath = {(logs_dir / "server.log").resolve()}
# Server stat path
StatPath = {(stats_dir / "server.stat").resolve()}
# Server SNI
SNI = {SNI}

# client1
[Peer]
# Configured peer hash
PeerCertSHA256 = {peer_hash}
# Server-side WG endpoint
WgEndpoint = {SERVER_WG_IP}:{SERVER_WG_PORT}
""",
        encoding="utf-8",
    )

    client_conf.write_text(
        f"""# Four-phase E2E test
[Interface]
# Remote QUIC server endpoint
QuicEndpoint = {QUIC_SERVER_IP}:{QUIC_SERVER_PORT}
# Client-side WG listen
WgListen = {CLIENT_WG_LISTEN_IP}:{CLIENT_WG_LISTEN_PORT}
# Client certs directory
CertsPath = {client1_certs.resolve()}
# Client log path
LogPath = {(TEST_DIR / "logs" / "client1.log").resolve()}
# Client stat path
StatPath = {(TEST_DIR / "stats" / "client1.stat").resolve()}
# Client SNI
SNI = {SNI}
""",
        encoding="utf-8",
    )

    return server_conf, client_conf


def wait_for_file_contains(path: Path, needle: str, timeout_sec: float) -> bool:
    deadline = time.monotonic() + timeout_sec
    while time.monotonic() < deadline:
        if path.exists():
            try:
                text = path.read_text(encoding="utf-8", errors="replace")
            except OSError:
                text = ""
            if needle in text:
                return True
        time.sleep(0.05)
    return False


def wait_for_file_not_contains(
    path: Path,
    needle: str,
    timeout_sec: float,
) -> bool:
    deadline = time.monotonic() + timeout_sec
    while time.monotonic() < deadline:
        if path.exists():
            try:
                text = path.read_text(encoding="utf-8", errors="replace")
            except OSError:
                text = ""
        else:
            text = ""

        if needle in text:
            return False

        time.sleep(0.05)

    return True


def read_text_if_exists(path: Path) -> str:
    if not path.exists():
        return "<missing>"
    try:
        return path.read_text(encoding="utf-8", errors="replace")
    except OSError as exc:
        return f"<read error: {exc}>"


def terminate_proc(proc: subprocess.Popen | None, name: str) -> None:
    if proc is None or proc.poll() is not None:
        return

    try:
        proc.send_signal(signal.SIGTERM)
    except ProcessLookupError:
        return

    try:
        proc.wait(timeout=3)
        return
    except subprocess.TimeoutExpired:
        pass

    try:
        proc.kill()
    except ProcessLookupError:
        return

    try:
        proc.wait(timeout=3)
    except subprocess.TimeoutExpired:
        print(f"WARNING: failed to kill {name}", file=sys.stderr)


def dump_debug_logs(prefix: str) -> None:
    print(f"==== {prefix} ====")
    print("---- client1.log ----")
    print(read_text_if_exists(TEST_DIR / "logs" / "client1.log"))
    print("---- server.log ----")
    print(read_text_if_exists(TEST_DIR / "logs" / "server.log"))
    print("---- client stdout ----")
    print(read_text_if_exists(TEST_DIR / "logs" / "client.stdout.txt"))
    print("---- client stderr ----")
    print(read_text_if_exists(TEST_DIR / "logs" / "client.stderr.txt"))
    print("---- server stdout ----")
    print(read_text_if_exists(TEST_DIR / "logs" / "server.stdout.txt"))
    print("---- server stderr ----")
    print(read_text_if_exists(TEST_DIR / "logs" / "server.stderr.txt"))


def recv_expected_payload_sequence(
    server_receiver: socket.socket,
    phase_name: str,
    expected_payloads: list[bytes],
    timeout_sec: float,
) -> bool:
    deadline = time.monotonic() + timeout_sec
    seen_packets: list[tuple[bytes, object]] = []

    for expected in expected_payloads:
        while True:
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                print(f"ERROR: {phase_name}: timed out waiting for payload sequence")
                print(f"waiting_for: {expected!r}")
                print(f"expected_sequence: {expected_payloads!r}")
                print(f"seen_packets: {seen_packets!r}")
                dump_debug_logs(phase_name)
                return False

            server_receiver.settimeout(remaining)

            try:
                data, addr = server_receiver.recvfrom(65535)
            except socket.timeout:
                print(f"ERROR: {phase_name}: timed out waiting for payload sequence")
                print(f"waiting_for: {expected!r}")
                print(f"expected_sequence: {expected_payloads!r}")
                print(f"seen_packets: {seen_packets!r}")
                dump_debug_logs(phase_name)
                return False

            seen_packets.append((data, addr))

            if data == expected:
                break

            print(f"ERROR: {phase_name}: payload mismatch")
            print(f"expected_now: {expected!r}")
            print(f"received: {data!r}")
            print(f"from: {addr}")
            print(f"expected_sequence: {expected_payloads!r}")
            print(f"seen_packets: {seen_packets!r}")
            dump_debug_logs(phase_name)
            return False

    return True


def run_one_phase(
    *,
    bin_path: Path,
    server_conf: Path,
    client_conf: Path,
    phase_name: str,
    expect_success: bool = False,
    expected_client_hash: str | None = None,
    expect_unknown_cert_hash: str | None = None,
    expect_client_not_connected: bool = False,
) -> bool:
    server_stdout_path = TEST_DIR / "logs" / "server.stdout.txt"
    server_stderr_path = TEST_DIR / "logs" / "server.stderr.txt"
    client_stdout_path = TEST_DIR / "logs" / "client.stdout.txt"
    client_stderr_path = TEST_DIR / "logs" / "client.stderr.txt"

    server_stdout = open(server_stdout_path, "wb")
    server_stderr = open(server_stderr_path, "wb")
    client_stdout = open(client_stdout_path, "wb")
    client_stderr = open(client_stderr_path, "wb")

    server_proc = None
    client_proc = None
    server_receiver = None
    client_sender = None

    try:
        server_receiver = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        server_receiver.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        server_receiver.bind((SERVER_WG_IP, SERVER_WG_PORT))
        server_receiver.settimeout(3.0 if expect_success else 2.0)

        server_proc = subprocess.Popen(
            [str(bin_path), str(server_conf)],
            stdout=server_stdout,
            stderr=server_stderr,
        )
        time.sleep(0.3)

        if server_proc.poll() is not None:
            print(f"ERROR: {phase_name}: server exited too early")
            dump_debug_logs(phase_name)
            return False

        client_proc = subprocess.Popen(
            [str(bin_path), str(client_conf)],
            stdout=client_stdout,
            stderr=client_stderr,
        )
        time.sleep(0.3)

        if client_proc.poll() is not None:
            print(f"ERROR: {phase_name}: client exited too early")
            dump_debug_logs(phase_name)
            return False

        client_sender = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        client_sender.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        client_sender.bind((CLIENT_SOURCE_IP, CLIENT_SOURCE_PORT))

        activation_payload = f"{phase_name} activation packet".encode()
        test_payload = f"{phase_name} payload".encode()

        sent1 = client_sender.sendto(
            activation_payload,
            (CLIENT_WG_LISTEN_IP, CLIENT_WG_LISTEN_PORT),
        )
        if sent1 != len(activation_payload):
            print(f"ERROR: {phase_name}: failed to send activation packet")
            return False

        client_log = TEST_DIR / "logs" / "client1.log"
        server_log = TEST_DIR / "logs" / "server.log"

        if expect_success:
            assert expected_client_hash is not None

            client_ready = wait_for_file_contains(
                client_log,
                "Client connected",
                timeout_sec=10.0,
            )
            server_cert_matched = wait_for_file_contains(
                server_log,
                f"Cert matched peer_id=0 cert_hash={expected_client_hash}",
                timeout_sec=10.0,
            )
            server_bound = wait_for_file_contains(
                server_log,
                "Connection bound",
                timeout_sec=10.0,
            )
            server_ready = wait_for_file_contains(
                server_log,
                "Client connected",
                timeout_sec=10.0,
            )

            if not (
                client_ready and server_cert_matched and server_bound and server_ready
            ):
                print(f"ERROR: {phase_name}: expected successful connection")
                print(f"client_ready={client_ready}")
                print(f"server_cert_matched={server_cert_matched}")
                print(f"server_bound={server_bound}")
                print(f"server_ready={server_ready}")
                dump_debug_logs(phase_name)
                return False

            sent2 = client_sender.sendto(
                test_payload,
                (CLIENT_WG_LISTEN_IP, CLIENT_WG_LISTEN_PORT),
            )
            if sent2 != len(test_payload):
                print(f"ERROR: {phase_name}: failed to send second test packet")
                return False

            if not recv_expected_payload_sequence(
                server_receiver,
                phase_name,
                [activation_payload, test_payload],
                timeout_sec=3.0,
            ):
                return False

            # End-to-end payload-integrity and sustained traffic regression.
            # Send one packet at a time to avoid making the test depend on
            # kernel UDP receive buffer sizing under burst load.
            packet_count = int(os.environ.get("QUICTUN_E2E_PACKETS", "0"))
            if not 0 <= packet_count <= 10000:
                raise ValueError("QUICTUN_E2E_PACKETS must be between 0 and 10000")
            for index in range(packet_count):
                sizes = (16, 64, 512, 1200)
                size = sizes[index % len(sizes)]
                payload = index.to_bytes(4, "big") + bytes([index % 251]) * (size - 4)
                sent = client_sender.sendto(
                    payload, (CLIENT_WG_LISTEN_IP, CLIENT_WG_LISTEN_PORT)
                )
                if sent != size:
                    print(f"ERROR: {phase_name}: stress packet {index} send failed")
                    return False
                server_receiver.settimeout(3.0)
                try:
                    received, _ = server_receiver.recvfrom(65535)
                except socket.timeout:
                    print(f"ERROR: {phase_name}: stress packet {index} timed out")
                    dump_debug_logs(phase_name)
                    return False
                if received != payload:
                    print(f"ERROR: {phase_name}: stress packet {index} corrupted")
                    dump_debug_logs(phase_name)
                    return False
            if packet_count:
                print(f"[PASS] {phase_name}: {packet_count} additional UDP payloads ")
                print("       (16/64/512/1200 bytes, exact byte-for-byte integrity)")
            return True

        time.sleep(3.0)

        if expect_unknown_cert_hash is not None:
            terminate_proc(client_proc, "client")
            client_proc = None
            terminate_proc(server_proc, "server")
            server_proc = None

            server_stdout.close()
            server_stdout = None
            server_stderr.close()
            server_stderr = None
            client_stdout.close()
            client_stdout = None
            client_stderr.close()
            client_stderr = None

            server_log_text = read_text_if_exists(server_log)
            client_log_text = read_text_if_exists(client_log)

            expected_line = (
                "Cert verify failed: unknown cert_hash=" f"{expect_unknown_cert_hash}"
            )
            unknown_hash_logged = expected_line in server_log_text
            no_server_cert_matched = "Cert matched" not in server_log_text
            no_server_connection_bound = "Connection bound" not in server_log_text
            no_server_client_connected = "Client connected" not in server_log_text
            no_client_connected = "Client connected" not in client_log_text

            if not (
                unknown_hash_logged
                and no_server_cert_matched
                and no_server_connection_bound
                and no_server_client_connected
                and (not expect_client_not_connected or no_client_connected)
            ):
                print(f"ERROR: {phase_name}: expected unknown cert hash rejection")
                print(f"unknown_hash_logged={unknown_hash_logged}")
                print(f"no_server_cert_matched={no_server_cert_matched}")
                print(f"no_server_connection_bound={no_server_connection_bound}")
                print(f"no_server_client_connected={no_server_client_connected}")
                print(f"no_client_connected={no_client_connected}")
                dump_debug_logs(phase_name)
                return False

        else:
            no_server_cert_matched = wait_for_file_not_contains(
                server_log,
                "Cert matched",
                timeout_sec=1.0,
            )
            no_server_connection_bound = wait_for_file_not_contains(
                server_log,
                "Connection bound",
                timeout_sec=1.0,
            )
            no_server_client_connected = wait_for_file_not_contains(
                server_log,
                "Client connected",
                timeout_sec=1.0,
            )

            if expect_client_not_connected:
                no_client_connected = wait_for_file_not_contains(
                    client_log,
                    "Client connected",
                    timeout_sec=1.0,
                )
            else:
                no_client_connected = True

            if not (
                no_server_cert_matched
                and no_server_connection_bound
                and no_server_client_connected
                and no_client_connected
            ):
                print(f"ERROR: {phase_name}: server unexpectedly accepted client")
                print(f"no_server_cert_matched={no_server_cert_matched}")
                print(f"no_server_connection_bound={no_server_connection_bound}")
                print(f"no_server_client_connected={no_server_client_connected}")
                print(f"no_client_connected={no_client_connected}")
                dump_debug_logs(phase_name)
                return False

        sent2 = client_sender.sendto(
            test_payload,
            (CLIENT_WG_LISTEN_IP, CLIENT_WG_LISTEN_PORT),
        )
        if sent2 != len(test_payload):
            print(f"ERROR: {phase_name}: failed to send second test packet")
            return False

        try:
            data, addr = server_receiver.recvfrom(65535)
            print(f"ERROR: {phase_name}: server-side WG unexpectedly received payload")
            print(f"received: {data!r}")
            print(f"from: {addr}")
            dump_debug_logs(phase_name)
            return False
        except socket.timeout:
            return True

    finally:
        if client_sender is not None:
            client_sender.close()
        if server_receiver is not None:
            server_receiver.close()

        terminate_proc(client_proc, "client")
        terminate_proc(server_proc, "server")

        if server_stdout is not None:
            server_stdout.close()
        if server_stderr is not None:
            server_stderr.close()
        if client_stdout is not None:
            client_stdout.close()
        if client_stderr is not None:
            client_stderr.close()


def main() -> int:
    need_cmd("openssl")

    passed = 0
    failed = 0
    total = 4

    bin_path = Path(os.environ.get("QUICTUN_BIN", str(DEFAULT_BIN)))
    if not bin_path.exists():
        print(f"ERROR: binary not found: {bin_path}")
        print("Build it first, for example:")
        print("  cmake -S . -B build -DCMAKE_BUILD_TYPE=Release")
        print("  cmake --build build -j 8")
        return 2

    prepare_test_dir()

    server_certs, client1_certs, original_client_hash = generate_initial_layout()
    server_conf, client_conf = generate_configs(
        server_certs,
        client1_certs,
        original_client_hash,
    )

    print(f"Using binary: {bin_path.resolve()}")
    print(f"Test directory: {TEST_DIR.resolve()}")
    print(f"Server config: {server_conf.resolve()}")
    print(f"Client config: {client_conf.resolve()}")
    print(f"Original valid client hash in config: {original_client_hash}")
    print("")

    clean_runtime_logs()
    ok1 = run_one_phase(
        bin_path=bin_path,
        server_conf=server_conf,
        client_conf=client_conf,
        phase_name="phase1-valid-client-cert",
        expect_success=True,
        expected_client_hash=original_client_hash,
    )
    if ok1:
        passed += 1
        print("[PASS] phase 1: valid client certificate works")
    else:
        failed += 1
        print("[FAIL] phase 1: valid client certificate works")
        print(f"\nRESULT: passed={passed}, failed={failed}, total={total}")
        return 1

    save_baseline(server_certs, client1_certs, server_conf, client_conf)

    # Phase 2: restore baseline, replace only client cert with cert from other CA
    server_certs, client1_certs, server_conf, client_conf = restore_baseline()
    replace_client_cert_with_other_ca(client1_certs)
    replaced_client_hash = cert_hash_b64(client1_certs / "cert.pem")

    print(f"Replaced client cert hash: {replaced_client_hash}")
    print(
        "Phase 2 uses baseline, then replaces only client certificate with one "
        "signed by other CA"
    )
    print("")

    clean_runtime_logs()
    ok2 = run_one_phase(
        bin_path=bin_path,
        server_conf=server_conf,
        client_conf=client_conf,
        phase_name="phase2-client-cert-replaced-with-other-ca",
        expect_success=False,
        expect_client_not_connected=True,
    )
    if ok2:
        passed += 1
        print("[PASS] phase 2: replacing only client cert with other CA is rejected")
    else:
        failed += 1
        print("[FAIL] phase 2: replacing only client cert with other CA is rejected")
        print(f"\nRESULT: passed={passed}, failed={failed}, total={total}")
        return 1

    # Phase 3: restore baseline, keep valid cert, replace only peer hash on server
    server_certs, client1_certs, server_conf, client_conf = restore_baseline()
    restored_valid_hash = cert_hash_b64(client1_certs / "cert.pem")

    wrong_peer_hash = restored_valid_hash + "_WRONG"
    server_conf, client_conf = generate_configs(
        server_certs,
        client1_certs,
        wrong_peer_hash,
    )

    print(f"Restored valid client cert hash: {restored_valid_hash}")
    print("Phase 3 uses baseline, then replaces only peer hash on server")
    print("")

    clean_runtime_logs()
    ok3 = run_one_phase(
        bin_path=bin_path,
        server_conf=server_conf,
        client_conf=client_conf,
        phase_name="phase3-valid-client-cert-but-wrong-hash-on-server",
        expect_success=False,
        expect_unknown_cert_hash=restored_valid_hash,
        expect_client_not_connected=True,
    )
    if ok3:
        passed += 1
        print("[PASS] phase 3: valid client cert is rejected with unknown cert hash")
    else:
        failed += 1
        print("[FAIL] phase 3: valid client cert is rejected with unknown cert hash")
        print(f"\nRESULT: passed={passed}, failed={failed}, total={total}")
        return 1

    # Phase 4: restore baseline, keep cert/hash valid, replace only client SNI
    server_certs, client1_certs, server_conf, client_conf = restore_baseline()
    replace_client_sni(client_conf, WRONG_SNI)

    print(f"Wrong client SNI: {WRONG_SNI}")
    print("Phase 4 uses baseline, then replaces only client SNI in config")
    print("")

    clean_runtime_logs()
    ok4 = run_one_phase(
        bin_path=bin_path,
        server_conf=server_conf,
        client_conf=client_conf,
        phase_name="phase4-valid-cert-valid-hash-but-wrong-sni",
        expect_success=False,
        expect_client_not_connected=True,
    )
    if ok4:
        passed += 1
        print(
            "[PASS] phase 4: valid cert and valid hash are rejected when client SNI is wrong"
        )
    else:
        failed += 1
        print(
            "[FAIL] phase 4: valid cert and valid hash are rejected when client SNI is wrong"
        )
        print(f"\nRESULT: passed={passed}, failed={failed}, total={total}")
        return 1

    print(f"Artifacts saved in: {TEST_DIR.resolve()}")
    print(f"\nRESULT: passed={passed}, failed={failed}, total={total}")
    return 0


# --- Real Linux-network integration: isolated namespaces and WireGuard. ---

NET_SERVER = "qt-srv"
NET_CLIENT_A = "qt-a"
NET_CLIENT_B = "qt-b"
NET_BRIDGE = "qt-br0"
NET_PREFIX = "10.237.71"
NET_V6_PREFIX = "fd42:237:71"
NET_CLIENTS = (
    ("a", NET_CLIENT_A, 11, 26001, 26000, 1),
    ("b", NET_CLIENT_B, 12, 26003, 26002, 2),
)


def net_cmd(*argv: str, timeout: float = 15.0) -> subprocess.CompletedProcess:
    proc = subprocess.run(argv, text=True, capture_output=True, timeout=timeout)
    if proc.returncode != 0:
        raise RuntimeError(
            f"network command failed ({proc.returncode}): {' '.join(argv)}\n"
            f"stdout: {proc.stdout}\nstderr: {proc.stderr}"
        )
    return proc


def ns_cmd(namespace: str, *argv: str, timeout: float = 15.0):
    return net_cmd("ip", "netns", "exec", namespace, *argv, timeout=timeout)


class NetworkTest:
    """One Docker container, three isolated netns, real WireGuard/IP traffic."""

    def __init__(self, binary: Path, home: Path):
        self.binary = binary.resolve()
        self.home = home.resolve()
        self.children: dict[str, subprocess.Popen] = {}
        self.handles = []
        self.namespace_names: list[str] = []
        self.bridge_created = False
        self.server_cert = self.home / "certs/server"
        self.certs: dict[str, Path] = {}
        self.hashes: dict[str, str] = {}
        self.private_keys: dict[str, Path] = {}
        self.public_keys: dict[str, str] = {}
        self.active_family = "ipv4"

    def create_network(self):
        for command in ("ip", "wg", "ping", "iperf3", "tc", "openssl"):
            need_cmd(command)
        # These mounts require CAP_SYS_ADMIN in addition to CAP_NET_ADMIN.
        net_cmd("ip", "link", "add", NET_BRIDGE, "type", "bridge")
        self.bridge_created = True
        net_cmd("ip", "link", "set", NET_BRIDGE, "up")
        for role, namespace, host_id in (
            ("s", NET_SERVER, 10),
            ("a", NET_CLIENT_A, 11),
            ("b", NET_CLIENT_B, 12),
        ):
            root_veth = f"qt-v{role}"
            guest_veth = f"qt-n{role}"
            net_cmd("ip", "netns", "add", namespace)
            self.namespace_names.append(namespace)
            net_cmd(
                "ip",
                "link",
                "add",
                root_veth,
                "type",
                "veth",
                "peer",
                "name",
                guest_veth,
            )
            net_cmd("ip", "link", "set", root_veth, "master", NET_BRIDGE)
            net_cmd("ip", "link", "set", root_veth, "up")
            net_cmd("ip", "link", "set", guest_veth, "netns", namespace)
            net_cmd("ip", "-n", namespace, "link", "set", guest_veth, "name", "eth0")
            net_cmd("ip", "-n", namespace, "link", "set", "lo", "up")
            net_cmd(
                "ip",
                "-n",
                namespace,
                "addr",
                "add",
                f"{NET_PREFIX}.{host_id}/24",
                "dev",
                "eth0",
            )
            net_cmd(
                "ip",
                "-n",
                namespace,
                "-6",
                "addr",
                "add",
                f"{NET_V6_PREFIX}::{host_id}/64",
                "dev",
                "eth0",
            )
            net_cmd("ip", "-n", namespace, "link", "set", "eth0", "up")
        # Wait for IPv6 DAD to complete before testing the real underlay.
        for namespace in (NET_CLIENT_A, NET_CLIENT_B):
            for target, ipv6 in (
                (f"{NET_PREFIX}.10", False),
                (f"{NET_V6_PREFIX}::10", True),
            ):
                deadline = time.monotonic() + 8.0
                while True:
                    command = ["ip", "netns", "exec", namespace, "ping"]
                    if ipv6:
                        command.append("-6")
                    result = subprocess.run(
                        command + ["-n", "-c", "1", "-W", "1", target],
                        capture_output=True,
                        text=True,
                        timeout=4,
                    )
                    if result.returncode == 0:
                        break
                    if time.monotonic() >= deadline:
                        raise RuntimeError(
                            f"underlay {namespace} -> {target}: "
                            f"{result.stdout} {result.stderr}"
                        )
                    time.sleep(0.2)
        print(
            "[PASS] isolated IPv4/IPv6 underlay between network namespaces", flush=True
        )

    def create_certs(self):
        cert_root = self.home / "certs"
        ca = cert_root / "ca"
        generate_ca(ca, "QUICTun network test CA")
        generate_signed_cert(self.server_cert, SNI, ca)
        shutil.copy2(ca / "ca.pem", self.server_cert / "ca.pem")
        for label in ("a", "b"):
            directory = cert_root / label
            generate_signed_cert(directory, f"client-{label}", ca)
            shutil.copy2(ca / "ca.pem", directory / "ca.pem")
            self.certs[label] = directory
            self.hashes[label] = cert_hash_b64(directory / "cert.pem")

    def create_wireguard(self):
        for label in ("s1", "s2", "a", "b"):
            key = self.home / f"wg-{label}.key"
            key.write_text(net_cmd("wg", "genkey").stdout, encoding="ascii")
            key.chmod(0o600)
            self.private_keys[label] = key
            proc = subprocess.run(
                ["wg", "pubkey"],
                input=key.read_text(),
                capture_output=True,
                text=True,
                check=True,
            )
            self.public_keys[label] = proc.stdout.strip()

        for label, namespace, _, client_port, server_port, network_id in NET_CLIENTS:
            server_if = f"wg{network_id}"
            for target_ns, interface in ((NET_SERVER, server_if), (namespace, "wg0")):
                net_cmd(
                    "ip", "-n", target_ns, "link", "add", interface, "type", "wireguard"
                )
                net_cmd("ip", "-n", target_ns, "link", "set", interface, "mtu", "1280")

            ns_cmd(
                NET_SERVER,
                "wg",
                "set",
                server_if,
                "private-key",
                str(self.private_keys[f"s{network_id}"]),
                "listen-port",
                str(server_port),
                "peer",
                self.public_keys[label],
                "allowed-ips",
                f"10.88.{network_id}.1/32,{NET_V6_PREFIX}:{network_id}::1/128",
            )
            ns_cmd(
                namespace,
                "wg",
                "set",
                "wg0",
                "private-key",
                str(self.private_keys[label]),
                "listen-port",
                str(client_port),
                "peer",
                self.public_keys[f"s{network_id}"],
                "allowed-ips",
                f"10.88.{network_id}.2/32,{NET_V6_PREFIX}:{network_id}::2/128",
                "endpoint",
                "127.0.0.1:16000",
                "persistent-keepalive",
                "2",
            )

            for target_ns, interface, host_id in (
                (NET_SERVER, server_if, 2),
                (namespace, "wg0", 1),
            ):
                net_cmd(
                    "ip",
                    "-n",
                    target_ns,
                    "addr",
                    "add",
                    f"10.88.{network_id}.{host_id}/24",
                    "dev",
                    interface,
                )
                net_cmd(
                    "ip",
                    "-n",
                    target_ns,
                    "-6",
                    "addr",
                    "add",
                    f"{NET_V6_PREFIX}:{network_id}::{host_id}/64",
                    "dev",
                    interface,
                )
                net_cmd("ip", "-n", target_ns, "link", "set", interface, "up")

    def write_configs(self, family: str):
        self.active_family = family
        server_address = (
            f"{NET_PREFIX}.10" if family == "ipv4" else f"[{NET_V6_PREFIX}::10]"
        )
        lines = [
            "[Interface]",
            f"QuicListen = {server_address}:18443",
            f"CertsPath = {self.server_cert}",
            f"LogPath = {self.home / 'server.log'}",
            f"SNI = {SNI}",
            "",
        ]
        for label, _, _, _, server_port, _ in NET_CLIENTS:
            lines.extend(
                [
                    "[Peer]",
                    f"PeerCertSHA256 = {self.hashes[label]}",
                    f"WgEndpoint = 127.0.0.1:{server_port}",
                    "",
                ]
            )
        (self.home / "server.conf").write_text("\n".join(lines), encoding="utf-8")
        for label, _, _, _, _, _ in NET_CLIENTS:
            client_lines = [
                "[Interface]",
                f"QuicEndpoint = {server_address}:18443",
                "WgListen = 127.0.0.1:16000",
                f"CertsPath = {self.certs[label]}",
                f"LogPath = {self.home / f'client-{label}.log'}",
                f"SNI = {SNI}",
                "",
            ]
            (self.home / f"client-{label}.conf").write_text(
                "\n".join(client_lines), encoding="utf-8"
            )

    def start(self, role: str):
        namespace = {
            "server": NET_SERVER,
            "a": NET_CLIENT_A,
            "b": NET_CLIENT_B,
        }[role]
        config = self.home / (
            "server.conf" if role == "server" else f"client-{role}.conf"
        )
        logfile = self.home / f"{self.active_family}-{role}.stderr"
        handle = open(logfile, "ab")
        self.handles.append(handle)
        proc = subprocess.Popen(
            ["ip", "netns", "exec", namespace, str(self.binary), str(config)],
            stdout=handle,
            stderr=subprocess.STDOUT,
        )
        self.children[role] = proc
        time.sleep(0.2)
        if proc.poll() is not None:
            raise RuntimeError(f"QUICTun {role} exited early with {proc.returncode}")

    def stop(self, role: str):
        proc = self.children.pop(role, None)
        if proc is not None:
            if proc.poll() is None:
                proc.terminate()
                try:
                    proc.wait(timeout=4)
                except subprocess.TimeoutExpired:
                    proc.kill()
                    proc.wait(timeout=4)
            if proc.returncode not in (0, -signal.SIGTERM, -signal.SIGINT):
                raise RuntimeError(
                    f"QUICTun {role} terminated abnormally: {proc.returncode}"
                )

    def all_running(self):
        for name, proc in self.children.items():
            if proc.poll() is not None:
                raise RuntimeError(f"QUICTun {name} exited with {proc.returncode}")

    def ping_until(
        self,
        namespace: str,
        destination: str,
        ipv6: bool = False,
        seconds: float = 25.0,
    ):
        deadline = time.monotonic() + seconds
        last = ""
        while time.monotonic() < deadline:
            self.all_running()
            cmd = ["ip", "netns", "exec", namespace, "ping"]
            if ipv6:
                cmd.append("-6")
            cmd.extend(["-n", "-c", "1", "-W", "1", destination])
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=4)
            if result.returncode == 0:
                return
            last = (result.stdout + result.stderr)[-400:]
            time.sleep(0.2)
        raise AssertionError(f"{namespace} could not ping {destination}: {last}")

    def check_client(self, label: str, namespace: str, network_id: int):
        self.ping_until(namespace, f"10.88.{network_id}.2")
        self.ping_until(NET_SERVER, f"10.88.{network_id}.1")
        self.ping_until(namespace, f"{NET_V6_PREFIX}:{network_id}::2", ipv6=True)
        self.ping_until(NET_SERVER, f"{NET_V6_PREFIX}:{network_id}::1", ipv6=True)
        handshake = ns_cmd(namespace, "wg", "show", "wg0", "latest-handshakes").stdout
        if not any(int(field) > 0 for field in handshake.split()[1::2]):
            raise AssertionError(f"{label}: WireGuard never authenticated")

    def check_clients(self):
        for label, namespace, _, _, _, network_id in NET_CLIENTS:
            self.check_client(label, namespace, network_id)
        # Test simultaneous traffic, not just two sequentially passing clients.
        probes = []
        for _, namespace, _, _, _, network_id in NET_CLIENTS:
            probes.append(
                subprocess.Popen(
                    [
                        "ip",
                        "netns",
                        "exec",
                        namespace,
                        "ping",
                        "-n",
                        "-c",
                        "3",
                        "-i",
                        "0.3",
                        "-W",
                        "2",
                        f"10.88.{network_id}.2",
                    ],
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                    text=True,
                )
            )
        for proc in probes:
            try:
                out, err = proc.communicate(timeout=8)
            except subprocess.TimeoutExpired:
                proc.kill()
                proc.communicate()
                raise AssertionError("parallel peer ping timed out")
            if proc.returncode != 0:
                raise AssertionError(f"parallel peer ping failed: {out} {err}")
        print(
            f"[PASS] {self.active_family}: bidirectional IPv4/IPv6 inside WG, two peers",
            flush=True,
        )

    def throughput(self, udp: bool):
        test_port = 15300 if udp else 15301
        server_log = open(self.home / f"iperf-{test_port}.log", "wb")
        self.handles.append(server_log)
        server = subprocess.Popen(
            [
                "ip",
                "netns",
                "exec",
                NET_SERVER,
                "iperf3",
                "-s",
                "-1",
                "-B",
                "10.88.1.2",
                "-p",
                str(test_port),
            ],
            stdout=server_log,
            stderr=subprocess.STDOUT,
        )
        try:
            time.sleep(0.4)
            cmd = [
                "ip",
                "netns",
                "exec",
                NET_CLIENT_A,
                "iperf3",
                "-c",
                "10.88.1.2",
                "-p",
                str(test_port),
                "-t",
                "3",
                "-J",
            ]
            if udp:
                cmd.extend(["-u", "-b", "2M"])
            result = net_cmd(*cmd, timeout=20)
            report = json.loads(result.stdout)
            if report.get("error"):
                raise AssertionError(f"iperf3 error: {report['error']}")
            received = report.get("end", {}).get("sum_received", {})
            bps = received.get("bits_per_second", 0)
            if bps <= 0:
                raise AssertionError(
                    f"iperf3 reported no received data: {report['end']}"
                )
            if udp and received.get("lost_percent", 100) > 10:
                raise AssertionError(
                    f"iperf3 UDP loss too high: {received['lost_percent']}%"
                )
            server.wait(timeout=5)
            if server.returncode != 0:
                raise AssertionError(f"iperf3 server exit {server.returncode}")
            self.all_running()
            print(
                f"[PASS] WireGuard {('UDP' if udp else 'TCP')} iperf3 "
                f"{bps / 1_000_000:.2f} Mbit/s",
                flush=True,
            )
        finally:
            if server.poll() is None:
                server.terminate()
                try:
                    server.wait(timeout=3)
                except subprocess.TimeoutExpired:
                    server.kill()
                    server.wait()

    def netem(self):
        # Apply jitter/loss to physical underlay while testing encrypted WG IP.
        cmd = [
            "ip",
            "netns",
            "exec",
            NET_CLIENT_A,
            "tc",
            "qdisc",
            "add",
            "dev",
            "eth0",
            "root",
            "netem",
            "delay",
            "25ms",
            "5ms",
            "loss",
            "1%",
        ]
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=10)
        if result.returncode != 0:
            if os.environ.get("QUICTUN_REQUIRE_NETEM") == "1":
                raise RuntimeError(f"tc netem unavailable: {result.stderr}")
            known_missing = ("Unknown qdisc", "Specified qdisc kind", "No such file")
            if not any(marker in result.stderr for marker in known_missing):
                raise RuntimeError(f"tc netem setup failed: {result.stderr}")
            print(f"[SKIP] tc netem unavailable: {result.stderr.strip()}", flush=True)
            return
        try:
            command = [
                "ip",
                "netns",
                "exec",
                NET_CLIENT_A,
                "ping",
                "-n",
                "-c",
                "12",
                "-i",
                "0.25",
                "-W",
                "2",
                "10.88.1.2",
            ]
            result = subprocess.run(command, capture_output=True, text=True, timeout=16)
            match = re.search(r"12 packets transmitted, (\d+) received", result.stdout)
            if not match or int(match.group(1)) < 10:
                raise AssertionError(
                    f"WG ping under netem lost too many: {result.stdout}"
                )
            self.all_running()
            print("[PASS] 25ms jitter / 1% loss on QUIC underlay", flush=True)
        finally:
            ns_cmd(NET_CLIENT_A, "tc", "qdisc", "del", "dev", "eth0", "root")

    def run(self):
        self.create_network()
        self.create_certs()
        self.create_wireguard()
        self.write_configs("ipv4")
        for role in ("server", "a", "b"):
            self.start(role)
        self.check_clients()
        self.throughput(udp=False)
        self.throughput(udp=True)
        self.netem()

        # Verify B's tunnel remains functional while A is actually stopped.
        self.stop("a")
        self.check_client("b", NET_CLIENT_B, 2)
        print("[PASS] client B remains connected while client A is stopped", flush=True)
        self.start("a")
        self.check_clients()
        print("[PASS] client restart with second peer alive", flush=True)

        # Restart the authenticated QUIC server while WG interfaces remain up.
        self.stop("server")
        self.start("server")
        self.check_clients()
        print("[PASS] server restart and tunnel reconnection", flush=True)

        self.stop("a")
        self.stop("b")
        self.stop("server")
        self.write_configs("ipv6")
        for role in ("server", "a", "b"):
            self.start(role)
        self.check_clients()
        print("[PASS] QUIC control and data plane over IPv6 underlay", flush=True)

    def cleanup(self):
        for role in list(self.children):
            try:
                self.stop(role)
            except Exception as exc:
                print(f"cleanup: {exc}", file=sys.stderr)
        for namespace in reversed(self.namespace_names):
            subprocess.run(
                ["ip", "netns", "del", namespace],
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
            )
        if self.bridge_created:
            subprocess.run(
                ["ip", "link", "del", NET_BRIDGE],
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
            )
        for handle in self.handles:
            handle.close()

    def print_logs(self):
        for logfile in sorted(self.home.glob("*.stderr")):
            data = logfile.read_text(errors="replace")
            print(f"--- {logfile} ---\n{data[-30000:]}", file=sys.stderr)


def network_main() -> int:
    binary = Path(os.environ.get("QUICTUN_BIN", str(DEFAULT_BIN))).resolve()
    if not binary.is_file():
        raise RuntimeError(f"QUICTun binary not found: {binary}")
    home = Path("./test_network_e2e")
    if home.exists():
        shutil.rmtree(home)
    home.mkdir(parents=True)
    test = NetworkTest(binary, home)
    try:
        test.run()
        return 0
    except Exception:
        test.print_logs()
        raise
    finally:
        test.cleanup()


def run_all_tests() -> int:
    print("\n=== QUICTun configuration regressions ===", flush=True)
    result = config_main()
    if result != 0:
        return result
    print("\n=== QUICTun QUIC/UDP loopback E2E ===", flush=True)
    result = main()
    if result != 0:
        return result
    print("\n=== QUICTun isolated WireGuard network E2E ===", flush=True)
    return network_main()


if __name__ == "__main__":
    sys.exit(run_all_tests())
