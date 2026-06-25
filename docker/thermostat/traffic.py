#!/usr/bin/env python3
"""Simulated thermostat traffic generator.

This module emulates a normal smart thermostat that periodically
publishes MQTT-like temperature readings to the camera node
(172.20.0.10:1883).  Packets are sent every **30 seconds** with a
randomised payload size between 20 and 50 bytes, reflecting the
compact nature of IoT sensor telemetry.

Designed to run inside a Docker container on the ``iot_network``
bridge (172.20.0.0/24).
"""

import random
import struct
import sys
import time

from scapy.all import IP, UDP, Raw, send  # type: ignore[import-untyped]

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------
DESTINATION_IP: str = "172.20.0.10"
DESTINATION_PORT: int = 1883
SEND_INTERVAL_SECONDS: float = 30.0
MIN_PAYLOAD_BYTES: int = 20
MAX_PAYLOAD_BYTES: int = 50


def build_mqtt_like_payload(size: int) -> bytes:
    """Create a pseudo-MQTT payload of the requested *size*.

    The payload begins with a recognisable MQTT PUBLISH stub (fixed
    header byte ``0x30``, topic ``temp``), followed by a 4-byte
    floating-point temperature reading and random padding to reach
    the target length.

    Args:
        size: Total payload length in bytes.

    Returns:
        A ``bytes`` object of exactly *size* bytes.
    """
    # Minimal MQTT-style header: PUBLISH type (0x30), topic "temp"
    mqtt_stub = b"\x30\x00\x04temp"
    temperature = random.uniform(18.0, 30.0)
    temp_bytes = struct.pack("!f", temperature)

    core = mqtt_stub + temp_bytes  # 10 bytes
    if size <= len(core):
        return core[:size]
    padding = bytes(random.randint(0, 255) for _ in range(size - len(core)))
    return core + padding


def send_thermostat_packet() -> None:
    """Construct and transmit a single MQTT-like UDP packet.

    The destination is ``DESTINATION_IP:DESTINATION_PORT``.  The payload
    size is chosen uniformly at random from the configured range.

    Raises:
        Exception: Any low-level scapy / socket error is caught, logged,
            and **not** re-raised so the main loop can continue.
    """
    payload_size = random.randint(MIN_PAYLOAD_BYTES, MAX_PAYLOAD_BYTES)
    payload = build_mqtt_like_payload(payload_size)

    # Decode the temperature float from bytes 8-12 for display
    try:
        temperature = struct.unpack("!f", payload[8:12])[0]
        temp_str = f"{temperature:.1f}°C"
    except (struct.error, IndexError):
        temp_str = "N/A"

    packet = (
        IP(dst=DESTINATION_IP)
        / UDP(dport=DESTINATION_PORT)
        / Raw(load=payload)
    )

    try:
        send(packet, verbose=False)
        print(
            f"[THERMOSTAT] Sent MQTT-like UDP packet -> "
            f"{DESTINATION_IP}:{DESTINATION_PORT}  "
            f"({payload_size} bytes, temp={temp_str})",
            flush=True,
        )
    except PermissionError as exc:
        print(
            f"[THERMOSTAT][ERROR] Permission denied when sending packet: {exc}",
            file=sys.stderr,
            flush=True,
        )
    except OSError as exc:
        print(
            f"[THERMOSTAT][ERROR] OS/network error: {exc}",
            file=sys.stderr,
            flush=True,
        )
    except Exception as exc:  # noqa: BLE001
        print(
            f"[THERMOSTAT][ERROR] Unexpected error sending packet: {exc}",
            file=sys.stderr,
            flush=True,
        )


def main() -> None:
    """Entry-point: periodically publish temperature telemetry.

    The function runs an infinite loop, sleeping
    ``SEND_INTERVAL_SECONDS`` between transmissions.  It catches
    ``KeyboardInterrupt`` for a graceful shutdown.
    """
    print(
        f"[THERMOSTAT] Starting thermostat traffic generator  "
        f"-> {DESTINATION_IP}:{DESTINATION_PORT}  "
        f"interval={SEND_INTERVAL_SECONDS}s  "
        f"payload={MIN_PAYLOAD_BYTES}-{MAX_PAYLOAD_BYTES} bytes",
        flush=True,
    )

    try:
        while True:
            send_thermostat_packet()
            time.sleep(SEND_INTERVAL_SECONDS)
    except KeyboardInterrupt:
        print("\n[THERMOSTAT] Shutting down gracefully.", flush=True)
    except Exception as exc:  # noqa: BLE001
        print(
            f"[THERMOSTAT][FATAL] Unrecoverable error in main loop: {exc}",
            file=sys.stderr,
            flush=True,
        )
        sys.exit(1)


if __name__ == "__main__":
    main()
