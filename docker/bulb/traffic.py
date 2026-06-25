#!/usr/bin/env python3
"""Simulated smart-bulb traffic generator.

This module emulates a normal smart light bulb that sends periodic
HTTP-like status pings to the camera node (172.20.0.10:80).  Packets
are sent every **60 seconds** with a randomised payload size between
10 and 30 bytes, reflecting the extremely lightweight heartbeat
traffic produced by a real smart bulb.

Designed to run inside a Docker container on the ``iot_network``
bridge (172.20.0.0/24).
"""

import random
import sys
import time

from scapy.all import IP, UDP, Raw, send  # type: ignore[import-untyped]

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------
DESTINATION_IP: str = "172.20.0.10"
DESTINATION_PORT: int = 80
SEND_INTERVAL_SECONDS: float = 60.0
MIN_PAYLOAD_BYTES: int = 10
MAX_PAYLOAD_BYTES: int = 30

# Possible bulb states reported in the ping payload
BULB_STATES: list[str] = ["ON", "OFF", "DIM25", "DIM50", "DIM75"]


def build_http_like_payload(size: int) -> bytes:
    """Create a pseudo-HTTP status-ping payload of the requested *size*.

    The payload starts with a compact ``GET /status`` line, followed by
    the current bulb state and random padding bytes.

    Args:
        size: Total payload length in bytes.

    Returns:
        A ``bytes`` object of exactly *size* bytes.
    """
    state = random.choice(BULB_STATES)
    stub = f"GET /status?s={state} HTTP/1.0\r\n".encode()
    if size <= len(stub):
        return stub[:size]
    remaining = size - len(stub)
    return stub + bytes(random.randint(0, 255) for _ in range(remaining))


def send_bulb_packet() -> None:
    """Construct and transmit a single HTTP-like UDP ping packet.

    The destination is ``DESTINATION_IP:DESTINATION_PORT``.  The payload
    size is chosen uniformly at random from the configured range.

    Raises:
        Exception: Any low-level scapy / socket error is caught, logged,
            and **not** re-raised so the main loop can continue.
    """
    payload_size = random.randint(MIN_PAYLOAD_BYTES, MAX_PAYLOAD_BYTES)
    payload = build_http_like_payload(payload_size)

    packet = (
        IP(dst=DESTINATION_IP)
        / UDP(dport=DESTINATION_PORT)
        / Raw(load=payload)
    )

    try:
        send(packet, verbose=False)
        print(
            f"[BULB] Sent HTTP-like status ping -> "
            f"{DESTINATION_IP}:{DESTINATION_PORT}  "
            f"({payload_size} bytes)",
            flush=True,
        )
    except PermissionError as exc:
        print(
            f"[BULB][ERROR] Permission denied when sending packet: {exc}",
            file=sys.stderr,
            flush=True,
        )
    except OSError as exc:
        print(
            f"[BULB][ERROR] OS/network error: {exc}",
            file=sys.stderr,
            flush=True,
        )
    except Exception as exc:  # noqa: BLE001
        print(
            f"[BULB][ERROR] Unexpected error sending packet: {exc}",
            file=sys.stderr,
            flush=True,
        )


def main() -> None:
    """Entry-point: periodically send HTTP-like status pings.

    The function runs an infinite loop, sleeping
    ``SEND_INTERVAL_SECONDS`` between transmissions.  It catches
    ``KeyboardInterrupt`` for a graceful shutdown.
    """
    print(
        f"[BULB] Starting smart-bulb traffic generator  "
        f"-> {DESTINATION_IP}:{DESTINATION_PORT}  "
        f"interval={SEND_INTERVAL_SECONDS}s  "
        f"payload={MIN_PAYLOAD_BYTES}-{MAX_PAYLOAD_BYTES} bytes",
        flush=True,
    )

    try:
        while True:
            send_bulb_packet()
            time.sleep(SEND_INTERVAL_SECONDS)
    except KeyboardInterrupt:
        print("\n[BULB] Shutting down gracefully.", flush=True)
    except Exception as exc:  # noqa: BLE001
        print(
            f"[BULB][FATAL] Unrecoverable error in main loop: {exc}",
            file=sys.stderr,
            flush=True,
        )
        sys.exit(1)


if __name__ == "__main__":
    main()
