#!/usr/bin/env python3
import os
import shutil
import signal
import socket
import subprocess
import sys
import time
from pathlib import Path

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


if __name__ == "__main__":
    sys.exit(main())
