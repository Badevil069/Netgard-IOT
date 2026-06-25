import random
import sys
import time
from scapy.all import IP, UDP, Raw, send
DESTINATION_IP: str = '172.20.0.10'
DESTINATION_PORT: int = 80
SEND_INTERVAL_SECONDS: float = 60.0
MIN_PAYLOAD_BYTES: int = 10
MAX_PAYLOAD_BYTES: int = 30
BULB_STATES: list[str] = ['ON', 'OFF', 'DIM25', 'DIM50', 'DIM75']

def build_http_like_payload(size: int) -> bytes:
    state = random.choice(BULB_STATES)
    stub = f'GET /status?s={state} HTTP/1.0\r\n'.encode()
    if size <= len(stub):
        return stub[:size]
    remaining = size - len(stub)
    return stub + bytes((random.randint(0, 255) for _ in range(remaining)))

def send_bulb_packet() -> None:
    payload_size = random.randint(MIN_PAYLOAD_BYTES, MAX_PAYLOAD_BYTES)
    payload = build_http_like_payload(payload_size)
    packet = IP(dst=DESTINATION_IP) / UDP(dport=DESTINATION_PORT) / Raw(load=payload)
    try:
        send(packet, verbose=False)
        print(f'[BULB] Sent HTTP-like status ping -> {DESTINATION_IP}:{DESTINATION_PORT}  ({payload_size} bytes)', flush=True)
    except PermissionError as exc:
        print(f'[BULB][ERROR] Permission denied when sending packet: {exc}', file=sys.stderr, flush=True)
    except OSError as exc:
        print(f'[BULB][ERROR] OS/network error: {exc}', file=sys.stderr, flush=True)
    except Exception as exc:
        print(f'[BULB][ERROR] Unexpected error sending packet: {exc}', file=sys.stderr, flush=True)

def main() -> None:
    print(f'[BULB] Starting smart-bulb traffic generator  -> {DESTINATION_IP}:{DESTINATION_PORT}  interval={SEND_INTERVAL_SECONDS}s  payload={MIN_PAYLOAD_BYTES}-{MAX_PAYLOAD_BYTES} bytes', flush=True)
    try:
        while True:
            send_bulb_packet()
            time.sleep(SEND_INTERVAL_SECONDS)
    except KeyboardInterrupt:
        print('\n[BULB] Shutting down gracefully.', flush=True)
    except Exception as exc:
        print(f'[BULB][FATAL] Unrecoverable error in main loop: {exc}', file=sys.stderr, flush=True)
        sys.exit(1)
if __name__ == '__main__':
    main()