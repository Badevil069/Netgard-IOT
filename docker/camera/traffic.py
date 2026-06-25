import os
import random
import sys
import time
from scapy.all import IP, UDP, Raw, send
DESTINATION_IP: str = '172.20.0.11'
DESTINATION_PORT: int = 554
SEND_INTERVAL_SECONDS: float = 2.0
MIN_PAYLOAD_BYTES: int = 50
MAX_PAYLOAD_BYTES: int = 200

def build_rtsp_like_payload(size: int) -> bytes:
    header = b'RTSP/1.0 200 OK\r\n'
    if size <= len(header):
        return header[:size]
    remaining = size - len(header)
    return header + os.urandom(remaining)

def send_camera_packet() -> None:
    payload_size = random.randint(MIN_PAYLOAD_BYTES, MAX_PAYLOAD_BYTES)
    payload = build_rtsp_like_payload(payload_size)
    packet = IP(dst=DESTINATION_IP) / UDP(dport=DESTINATION_PORT) / Raw(load=payload)
    try:
        send(packet, verbose=False)
        print(f'[CAMERA] Sent RTSP-like UDP packet -> {DESTINATION_IP}:{DESTINATION_PORT}  ({payload_size} bytes)', flush=True)
    except PermissionError as exc:
        print(f'[CAMERA][ERROR] Permission denied when sending packet: {exc}', file=sys.stderr, flush=True)
    except OSError as exc:
        print(f'[CAMERA][ERROR] OS/network error: {exc}', file=sys.stderr, flush=True)
    except Exception as exc:
        print(f'[CAMERA][ERROR] Unexpected error sending packet: {exc}', file=sys.stderr, flush=True)

def main() -> None:
    print(f'[CAMERA] Starting camera traffic generator  -> {DESTINATION_IP}:{DESTINATION_PORT}  interval={SEND_INTERVAL_SECONDS}s  payload={MIN_PAYLOAD_BYTES}-{MAX_PAYLOAD_BYTES} bytes', flush=True)
    try:
        while True:
            send_camera_packet()
            time.sleep(SEND_INTERVAL_SECONDS)
    except KeyboardInterrupt:
        print('\n[CAMERA] Shutting down gracefully.', flush=True)
    except Exception as exc:
        print(f'[CAMERA][FATAL] Unrecoverable error in main loop: {exc}', file=sys.stderr, flush=True)
        sys.exit(1)
if __name__ == '__main__':
    main()