import os
import csv
import time
import socket
from datetime import datetime, timezone
from scapy.all import sniff, IP, TCP, UDP, ICMP, conf
DATA_DIR = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), 'data')
CSV_PATH = os.path.join(DATA_DIR, 'live_traffic.csv')
CSV_HEADERS = ['timestamp', 'src_ip', 'dst_ip', 'protocol', 'packet_size', 'src_port', 'dst_port']
FLUSH_INTERVAL = 10
_packet_buffer: list[dict] = []

def detect_docker_interface():
    try:
        for iface in conf.ifaces.values():
            ip = getattr(iface, 'ip', '')
            if ip and ip.startswith('172.20.0.'):
                name = getattr(iface, 'name', '')
                print(f'[capture] Detected Docker bridge interface by IP subnet: {name} ({ip})')
                return iface
        for iface in conf.ifaces.values():
            name = getattr(iface, 'name', '')
            if name.startswith('br-'):
                desc = getattr(iface, 'description', '')
                print(f'[capture] Detected custom Docker bridge interface: {name} ({desc})')
                return iface
        for iface in conf.ifaces.values():
            name = getattr(iface, 'name', '')
            desc = getattr(iface, 'description', '')
            iface_str = f'{name} {desc}'.lower()
            if 'docker' in iface_str or name.startswith('br-') or desc.startswith('br-'):
                print(f'[capture] Detected Docker bridge interface: {name} ({desc})')
                return iface
            if 'vethernet' in iface_str or 'wsl' in iface_str or 'hyper-v' in iface_str:
                print(f'[capture] Detected Windows virtual interface (Npcap): {name} ({desc})')
                return iface
        available_iface_names = [getattr(i, 'name', '') for i in conf.ifaces.values()]
        common_names = ['docker0', 'br-docker', 'bridge0']
        for name in common_names:
            if name in available_iface_names:
                print(f'[capture] Using common Docker interface: {name}')
                for i in conf.ifaces.values():
                    if getattr(i, 'name', '') == name:
                        return i
                return name
        default = conf.iface
        print(f'[capture] No Docker bridge found — falling back to default interface: {default}')
        return default
    except Exception as exc:
        default = str(conf.iface)
        print(f'[capture] Error detecting interface ({exc}) — using default: {default}')
        return default

def _protocol_name(proto_num: int) -> str:
    mapping = {1: 'ICMP', 6: 'TCP', 17: 'UDP'}
    return mapping.get(proto_num, str(proto_num))

def parse_packet(packet) -> dict | None:
    try:
        if not packet.haslayer(IP):
            return None
        ip_layer = packet[IP]
        src_port = 0
        dst_port = 0
        protocol = _protocol_name(ip_layer.proto)
        if packet.haslayer(TCP):
            src_port = packet[TCP].sport
            dst_port = packet[TCP].dport
        elif packet.haslayer(UDP):
            src_port = packet[UDP].sport
            dst_port = packet[UDP].dport
        return {'timestamp': datetime.now(timezone.utc).isoformat(), 'src_ip': ip_layer.src, 'dst_ip': ip_layer.dst, 'protocol': protocol, 'packet_size': len(packet), 'src_port': src_port, 'dst_port': dst_port}
    except Exception as exc:
        print(f'[capture] Error parsing packet: {exc}')
        return None

def _ensure_csv() -> None:
    os.makedirs(DATA_DIR, exist_ok=True)
    if not os.path.isfile(CSV_PATH):
        try:
            with open(CSV_PATH, 'w', newline='', encoding='utf-8') as fh:
                writer = csv.DictWriter(fh, fieldnames=CSV_HEADERS)
                writer.writeheader()
            print(f'[capture] Created new CSV file: {CSV_PATH}')
        except OSError as exc:
            print(f'[capture] Failed to create CSV: {exc}')

def _prune_csv() -> None:
    if not os.path.isfile(CSV_PATH):
        return
    try:
        with open(CSV_PATH, 'r', encoding='utf-8') as f:
            lines = f.readlines()
        if len(lines) > 5000:
            header = lines[0]
            trimmed = [header] + lines[-2000:]
            with open(CSV_PATH, 'w', newline='', encoding='utf-8') as f:
                f.writelines(trimmed)
            print(f'[capture] Trimmed CSV file to the last 2000 lines to prevent bloat')
    except Exception as exc:
        print(f'[capture] Error pruning CSV: {exc}')

def flush_buffer() -> None:
    global _packet_buffer
    if not _packet_buffer:
        return
    try:
        _ensure_csv()
        with open(CSV_PATH, 'a', newline='', encoding='utf-8') as fh:
            writer = csv.DictWriter(fh, fieldnames=CSV_HEADERS)
            for row in _packet_buffer:
                writer.writerow(row)
        print(f'[capture] Flushed {len(_packet_buffer)} packets to {CSV_PATH}')
        _packet_buffer = []
        _prune_csv()
    except OSError as exc:
        print(f'[capture] Error writing CSV: {exc}')

def packet_callback(packet) -> None:
    parsed = parse_packet(packet)
    if parsed is None:
        return
    print(f"[capture] {parsed['src_ip']}:{parsed['src_port']} -> {parsed['dst_ip']}:{parsed['dst_port']} | {parsed['protocol']} | {parsed['packet_size']}B")
    _packet_buffer.append(parsed)
    if len(_packet_buffer) >= FLUSH_INTERVAL:
        flush_buffer()

def start_capture(interface: str | None=None, packet_count: int=0) -> None:
    _ensure_csv()
    iface = interface or detect_docker_interface()
    print(f'[capture] Starting packet capture on interface: {iface}')
    print(f'[capture] Saving to: {CSV_PATH}')
    print(f'[capture] Flushing every {FLUSH_INTERVAL} packets')
    print('[capture] Press Ctrl+C to stop.\n')
    try:
        sniff(iface=iface, prn=packet_callback, count=packet_count if packet_count > 0 else 0, store=False)
    except PermissionError:
        print('[capture] ERROR: Permission denied. Run with elevated privileges (sudo / Administrator).')
    except KeyboardInterrupt:
        print('\n[capture] Capture interrupted by user.')
    except Exception as exc:
        print(f'[capture] Unexpected error during capture: {exc}')
    finally:
        flush_buffer()
        print('[capture] Capture stopped.')
if __name__ == '__main__':
    start_capture()