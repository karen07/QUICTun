#!/usr/bin/env python3
"""Loopback QUIC-session-bound UDP data-plane load/stress regressions.

These tests use the real QUICTun client and server, a real TLS handshake,
and real local UDP sockets. Each received packet is checked byte-for-byte;
loss is reported explicitly instead of being silently ignored.
"""

import hashlib
import os
from pathlib import Path
import select
import socket
import subprocess
import sys
import threading
import time

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "integration"))
import test_quictun as e2e  # Reuse the established certificate/E2E setup.


def option_int(name: str, default: int, lo: int, hi: int) -> int:
    value = int(os.environ.get(name, str(default)))
    if not lo <= value <= hi:
        raise ValueError(f"{name} must be in [{lo}, {hi}]")
    return value


def payload_for(case_id: int, seq: int, length: int) -> bytes:
    header = case_id.to_bytes(4, "big") + seq.to_bytes(4, "big")
    digest = hashlib.blake2s(header, digest_size=32).digest()
    return header + (digest * ((length - 8 + 31) // 32))[: length - 8]


def run_traffic(
    label: str,
    case_id: int,
    count: int,
    pps: int,
    sizes: tuple[int, ...],
    required: float,
    src: socket.socket,
    dst: socket.socket,
) -> None:
    print(
        f"\n=== LOAD: {label}: packets={count}, target_pps={pps}, "
        f"min_delivery={required:.1%} ===",
        flush=True,
    )
    received: set[int] = set()
    received_bytes = 0
    errors: list[str] = []
    completed = threading.Event()
    send_errors: list[str] = []
    t_start = time.monotonic()

    # Receive concurrently with the sender, avoiding a false fail caused by
    # not draining the userspace UDP socket while emitting a burst.
    def receiver() -> None:
        nonlocal received_bytes
        last_rx = time.monotonic()
        # A heavily loaded host may send slower than the requested rate.
        # Do not stop after receiving the expected unique packet count:
        # duplicates may arrive late. Drain for two seconds after sending
        # and after the last received packet, whichever is later.
        while True:
            if completed.is_set() and time.monotonic() - max(last_rx, t_send_end) > 2.0:
                break
            ready, _, _ = select.select([dst], [], [], 0.1)
            if not ready:
                continue
            try:
                data, _ = dst.recvfrom(65535)
            except OSError as exc:
                errors.append(f"recvfrom failed: {exc}")
                return
            last_rx = time.monotonic()
            if len(data) < 8:
                errors.append(f"packet shorter than 8 bytes ({len(data)})")
                continue
            found_case = int.from_bytes(data[:4], "big")
            seq = int.from_bytes(data[4:8], "big")
            if found_case != case_id or seq >= count:
                errors.append(f"unexpected packet (case={found_case}, seq={seq})")
                continue
            if seq in received:
                errors.append(f"duplicate packet seq={seq}")
                continue
            expected = payload_for(case_id, seq, sizes[seq % len(sizes)])
            if data != expected:
                errors.append(f"corrupted packet seq={seq} len={len(data)}")
                continue
            received.add(seq)
            received_bytes += len(data)

    reader = threading.Thread(target=receiver, name=f"receiver-{case_id}", daemon=True)
    reader.start()
    try:
        for seq in range(count):
            data = payload_for(case_id, seq, sizes[seq % len(sizes)])
            try:
                sent = src.sendto(
                    data, (e2e.CLIENT_WG_LISTEN_IP, e2e.CLIENT_WG_LISTEN_PORT)
                )
                if sent != len(data):
                    send_errors.append(f"short send seq={seq}: {sent}")
            except OSError as exc:
                send_errors.append(f"send seq={seq}: {exc}")
            # Monotonic scheduled send pacing: prevents accidental giant
            # bursts when the test host is briefly rescheduled.
            until = t_start + (seq + 1) / pps
            delay = until - time.monotonic()
            if delay > 0:
                time.sleep(delay)
    finally:
        t_send_end = time.monotonic()
        completed.set()
        reader.join(timeout=15)
    seconds = time.monotonic() - t_start
    sending_seconds = t_send_end - t_start
    if reader.is_alive():
        raise AssertionError(f"{label}: receiver thread did not finish")
    delivered = len(received)
    lost = count - delivered
    actual_rate = delivered / seconds if seconds > 0 else 0
    mbps = (received_bytes * 8 / seconds / 1_000_000) if seconds > 0 else 0
    offered_pps = count / sending_seconds if sending_seconds > 0 else 0
    print(
        f"sent={count}, received={delivered}, lost={lost} ({lost/count:.2%}), "
        f"send_elapsed={sending_seconds:.2f}s, total_elapsed={seconds:.2f}s, "
        f"offered_pps={offered_pps:.1f}, delivered_pps={actual_rate:.1f}, "
        f"payload_Mbps={mbps:.2f}",
        flush=True,
    )
    if errors:
        raise AssertionError(f"{label}: integrity/duplicate errors: {errors[:5]}")
    if send_errors:
        raise AssertionError(f"{label}: send errors: {send_errors[:5]}")
    if delivered / count < required:
        raise AssertionError(
            f"{label}: delivery {delivered/count:.2%} < {required:.2%}"
        )
    print(f"[PASS] {label} (integrity OK, delivery >= {required:.1%})", flush=True)


def main() -> int:
    e2e.need_cmd("openssl")
    binary = Path(os.environ.get("QUICTUN_BIN", "build/QUICTun")).resolve()
    if not binary.is_file():
        raise RuntimeError(f"QUICTun binary not found: {binary}")
    scale = option_int("QUICTUN_STRESS_SCALE", 1, 1, 10)
    e2e.TEST_DIR = Path("./test_load_stress")
    e2e.prepare_test_dir()
    server_certs, client_certs, client_hash = e2e.generate_initial_layout()
    server_conf, client_conf = e2e.generate_configs(
        server_certs, client_certs, client_hash
    )

    processes: list[subprocess.Popen] = []
    handles = []
    rx = None
    tx = None
    try:
        rx = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        rx.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, 4 * 1024 * 1024)
        rx.bind((e2e.SERVER_WG_IP, e2e.SERVER_WG_PORT))
        rx.settimeout(15)
        tx = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        tx.bind((e2e.CLIENT_SOURCE_IP, e2e.CLIENT_SOURCE_PORT))

        def start(cfg: Path, role: str) -> subprocess.Popen:
            out = open(e2e.TEST_DIR / "logs" / f"{role}.stdout.txt", "wb")
            err = open(e2e.TEST_DIR / "logs" / f"{role}.stderr.txt", "wb")
            handles.extend([out, err])
            p = subprocess.Popen([str(binary), str(cfg)], stdout=out, stderr=err)
            processes.append(p)
            return p

        server = start(server_conf, "server")
        time.sleep(0.3)
        if server.poll() is not None:
            raise RuntimeError("server exited before handshake")
        client = start(client_conf, "client")
        time.sleep(0.3)
        if client.poll() is not None:
            raise RuntimeError("client exited before handshake")
        activation = b"QUICTun-load-activation-packet"
        tx.sendto(activation, (e2e.CLIENT_WG_LISTEN_IP, e2e.CLIENT_WG_LISTEN_PORT))
        if not e2e.wait_for_file_contains(
            e2e.TEST_DIR / "logs" / "client1.log", "Client connected", 15
        ):
            raise AssertionError("client QUIC handshake did not complete")
        if not e2e.wait_for_file_contains(
            e2e.TEST_DIR / "logs" / "server.log",
            f"Cert matched peer_id=0 cert_hash={client_hash}",
            15,
        ):
            raise AssertionError("server did not authenticate client")
        data, _ = rx.recvfrom(65535)
        if data != activation:
            raise AssertionError(f"handshake activation payload corrupted: {data!r}")
        print("[PASS] authenticated QUIC handshake and tunnel activation", flush=True)

        # Integrity-first baseline, then sustained traffic, an intentionally
        # aggressive burst, and post-idle recovery. Loss thresholds for burst
        # are not confused with cryptographic integrity (which must be exact).
        run_traffic(
            "mixed sizes, lossless",
            1,
            1000 * scale,
            500,
            (16, 64, 512, 1200),
            1.0,
            tx,
            rx,
        )
        run_traffic(
            "sustained 1200-byte traffic", 2, 3000 * scale, 800, (1200,), 0.995, tx, rx
        )
        run_traffic(
            "paced high-rate burst",
            3,
            4000 * scale,
            2000,
            (64, 512, 1200),
            0.98,
            tx,
            rx,
        )
        time.sleep(2)
        run_traffic("post-idle recovery", 4, 500 * scale, 500, (64, 512), 1.0, tx, rx)

        # Optional long-duration run. 100k-500k packets can be requested
        # without making the everyday three-compiler regression prohibitively slow.
        long_packets = option_int("QUICTUN_LONG_STRESS_PACKETS", 0, 0, 500000)
        if long_packets:
            long_pps = option_int("QUICTUN_LONG_STRESS_PPS", 4000, 1, 30000)
            run_traffic(
                "long-duration stress",
                5,
                long_packets,
                long_pps,
                (64, 512, 1200),
                0.98,
                tx,
                rx,
            )

        for p in processes:
            if p.poll() is not None:
                raise AssertionError(
                    f"QUICTun process unexpectedly exited: {p.returncode}"
                )
        print("\nALL QUICTun LOAD/STRESS SCENARIOS PASSED", flush=True)
        return 0
    except Exception:
        e2e.dump_debug_logs("load/stress")
        raise
    finally:
        for p in reversed(processes):
            e2e.terminate_proc(p, "load/stress QUICTun")
        if rx is not None:
            rx.close()
        if tx is not None:
            tx.close()
        for f in handles:
            f.close()


if __name__ == "__main__":
    try:
        sys.exit(main())
    except (AssertionError, RuntimeError, OSError, ValueError) as exc:
        print(f"[FAIL] load/stress: {exc}", file=sys.stderr)
        sys.exit(1)
