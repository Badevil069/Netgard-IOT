#!/usr/bin/env python3
"""Simulated IP-camera traffic generator.

This module emulates a normal IP camera that continuously streams
RTSP-like UDP packets to the thermostat node (172.20.0.11:554).
Packets are sent every **2 seconds** with a randomised payload size
between 50 and 200 bytes, mimicking the bursty nature of a real
video stream.

Designed to run inside a Docker container on the ``iot_network``
bridge (172.20.0.0/24).
"""

import os
import random
import sys
import time

from scapy.all import IP, UDP, Raw, send  # type: ignore[import-untyped]

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------
DESTINATION_IP: str = "172.20.0.11"
DESTINATION_PORT: int = 554
SEND_INTERVAL_SECONDS: float = 2.0
MIN_PAYLOAD_BYTES: int = 50
MAX_PAYLOAD_BYTES: int = 200


def build_rtsp_like_payload(size: int) -> bytes:
    """Create a pseudo-RTSP payload of the requested *size*.

    The payload starts with a human-readable RTSP header stub so that
    packet captures are easy to identify visually, followed by random
    bytes representing a video-frame fragment.

    Args:
        size: Total payload length in bytes.

    Returns:
        A ``bytes`` object of exactly *size* bytes.
    """
    header = b"RTSP/1.0 200 OK\r\n"
    if size <= len(header):
        return header[:size]
    remaining = size - len(header)
    return header + os.urandom(remaining)


def send_camera_packet() -> None:
    """Construct and transmit a single RTSP-like UDP packet.

    The destination is ``DESTINATION_IP:DESTINATION_PORT``.  The payload
    size is chosen uniformly at random from the configured range.

    Raises:
        Exception: Any low-level scapy / socket error is caught, logged,
            and **not** re-raised so the main loop can continue.
    """
    payload_size = random.randint(MIN_PAYLOAD_BYTES, MAX_PAYLOAD_BYTES)
    payload = build_rtsp_like_payload(payload_size)

    packet = (
        IP(dst=DESTINATION_IP)
        / UDP(dport=DESTINATION_PORT)
        / Raw(load=payload)
    )

    try:
        send(packet, verbose=False)
        print(
            f"[CAMERA] Sent RTSP-like UDP packet -> "
            f"{DESTINATION_IP}:{DESTINATION_PORT}  "
            f"({payload_size} bytes)",
            flush=True,
        )
    except PermissionError as exc:
        print(
            f"[CAMERA][ERROR] Permission denied when sending packet: {exc}",
            file=sys.stderr,
            flush=True,
        )
    except OSError as exc:
        print(
            f"[CAMERA][ERROR] OS/network error: {exc}",
            file=sys.stderr,
            flush=True,
        )
    except Exception as exc:  # noqa: BLE001
        print(
            f"[CAMERA][ERROR] Unexpected error sending packet: {exc}",
            file=sys.stderr,
            flush=True,
        )


def main() -> None:
    """Entry-point: continuously stream RTSP-like packets.

    The function runs an infinite loop, sleeping
    ``SEND_INTERVAL_SECONDS`` between transmissions.  It catches
    ``KeyboardInterrupt`` for a graceful shutdown.
    """
    print(
        f"[CAMERA] Starting camera traffic generator  "
        f"-> {DESTINATION_IP}:{DESTINATION_PORT}  "
        f"interval={SEND_INTERVAL_SECONDS}s  "
        f"payload={MIN_PAYLOAD_BYTES}-{MAX_PAYLOAD_BYTES} bytes",
        flush=True,
    )

    try:
        while True:
            send_camera_packet()
            time.sleep(SEND_INTERVAL_SECONDS)
    except KeyboardInterrupt:
        print("\n[CAMERA] Shutting down gracefully.", flush=True)
    except Exception as exc:  # noqa: BLE001
        print(
            f"[CAMERA][FATAL] Unrecoverable error in main loop: {exc}",
            file=sys.stderr,
            flush=True,
        )
        sys.exit(1)


if __name__ == "__main__":
    main()
