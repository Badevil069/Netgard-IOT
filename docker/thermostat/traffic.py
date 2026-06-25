import random
import struct
import sys
import time
from scapy.all import IP, UDP, Raw, send
DESTINATION_IP: str = '172.20.0.10'
DESTINATION_PORT: int = 1883
SEND_INTERVAL_SECONDS: float = 30.0
MIN_PAYLOAD_BYTES: int = 20
MAX_PAYLOAD_BYTES: int = 50

def build_mqtt_like_payload(size: int) -> bytes:
    mqtt_stub = b'0\x00\x04temp'
    temperature = random.uniform(18.0, 30.0)
    temp_bytes = struct.pack('!f', temperature)
    core = mqtt_stub + temp_bytes
    if size <= len(core):
        return core[:size]
    padding = bytes((random.randint(0, 255) for _ in range(size - len(core))))
    return core + padding

def send_thermostat_packet() -> None:
    payload_size = random.randint(MIN_PAYLOAD_BYTES, MAX_PAYLOAD_BYTES)
    payload = build_mqtt_like_payload(payload_size)
    try:
        temperature = struct.unpack('!f', payload[8:12])[0]
        temp_str = f'{temperature:.1f}°C'
    except (struct.error, IndexError):
        temp_str = 'N/A'
    packet = IP(dst=DESTINATION_IP) / UDP(dport=DESTINATION_PORT) / Raw(load=payload)
    try:
        send(packet, verbose=False)
        print(f'[THERMOSTAT] Sent MQTT-like UDP packet -> {DESTINATION_IP}:{DESTINATION_PORT}  ({payload_size} bytes, temp={temp_str})', flush=True)
    except PermissionError as exc:
        print(f'[THERMOSTAT][ERROR] Permission denied when sending packet: {exc}', file=sys.stderr, flush=True)
    except OSError as exc:
        print(f'[THERMOSTAT][ERROR] OS/network error: {exc}', file=sys.stderr, flush=True)
    except Exception as exc:
        print(f'[THERMOSTAT][ERROR] Unexpected error sending packet: {exc}', file=sys.stderr, flush=True)

def main() -> None:
    print(f'[THERMOSTAT] Starting thermostat traffic generator  -> {DESTINATION_IP}:{DESTINATION_PORT}  interval={SEND_INTERVAL_SECONDS}s  payload={MIN_PAYLOAD_BYTES}-{MAX_PAYLOAD_BYTES} bytes', flush=True)
    try:
        while True:
            send_thermostat_packet()
            time.sleep(SEND_INTERVAL_SECONDS)
    except KeyboardInterrupt:
        print('\n[THERMOSTAT] Shutting down gracefully.', flush=True)
    except Exception as exc:
        print(f'[THERMOSTAT][FATAL] Unrecoverable error in main loop: {exc}', file=sys.stderr, flush=True)
        sys.exit(1)
if __name__ == '__main__':
    main()