"""
capture.py - Live packet capture module for rogue IoT device detection.

Uses Scapy to sniff packets on the Docker bridge network interface,
extracts key network features from each packet, and saves captured
data to a CSV file for downstream analysis and prediction.

Auto-detects the correct Docker bridge interface by scanning available
network interfaces for names containing 'docker' or 'br-'.
"""

import os
import csv
import time
import socket
from datetime import datetime, timezone

from scapy.all import sniff, IP, TCP, UDP, ICMP, conf


# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

DATA_DIR = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "data")
CSV_PATH = os.path.join(DATA_DIR, "live_traffic.csv")
CSV_HEADERS = [
    "timestamp",
    "src_ip",
    "dst_ip",
    "protocol",
    "packet_size",
    "src_port",
    "dst_port",
]
FLUSH_INTERVAL = 10  # write to disk every N packets


# ---------------------------------------------------------------------------
# Module-level packet buffer
# ---------------------------------------------------------------------------

_packet_buffer: list[dict] = []


# ---------------------------------------------------------------------------
# Interface detection
# ---------------------------------------------------------------------------

def detect_docker_interface():
    """Detect the Docker bridge network interface or Windows virtual interface.

    Scans all available network interfaces and returns the detected interface.
    Falls back to the default Scapy interface if none is found.
    """
    try:
        # 1. Prioritize interface with the matching subnet IP (172.20.0.x)
        for iface in conf.ifaces.values():
            ip = getattr(iface, "ip", "")
            if ip and ip.startswith("172.20.0."):
                name = getattr(iface, "name", "")
                print(f"[capture] Detected Docker bridge interface by IP subnet: {name} ({ip})")
                return iface

        # 2. Look for custom bridge interfaces (br-*)
        for iface in conf.ifaces.values():
            name = getattr(iface, "name", "")
            if name.startswith("br-"):
                desc = getattr(iface, "description", "")
                print(f"[capture] Detected custom Docker bridge interface: {name} ({desc})")
                return iface

        # 3. Check Scapy interface objects for common names
        for iface in conf.ifaces.values():
            name = getattr(iface, "name", "")
            desc = getattr(iface, "description", "")
            
            # Combine name and description to check
            iface_str = f"{name} {desc}".lower()
            
            # Linux bridge detection
            if "docker" in iface_str or name.startswith("br-") or desc.startswith("br-"):
                print(f"[capture] Detected Docker bridge interface: {name} ({desc})")
                return iface
                
            # Windows Virtual / Hyper-V adapter detection for Npcap
            if "vethernet" in iface_str or "wsl" in iface_str or "hyper-v" in iface_str:
                print(f"[capture] Detected Windows virtual interface (Npcap): {name} ({desc})")
                return iface

        # Fallback: try common default names
        available_iface_names = [getattr(i, "name", "") for i in conf.ifaces.values()]
        common_names = ["docker0", "br-docker", "bridge0"]
        for name in common_names:
            if name in available_iface_names:
                print(f"[capture] Using common Docker interface: {name}")
                for i in conf.ifaces.values():
                    if getattr(i, "name", "") == name:
                        return i
                return name

        default = conf.iface
        print(f"[capture] No Docker bridge found — falling back to default interface: {default}")
        return default

    except Exception as exc:
        default = str(conf.iface)
        print(f"[capture] Error detecting interface ({exc}) — using default: {default}")
        return default


# ---------------------------------------------------------------------------
# Packet parsing
# ---------------------------------------------------------------------------

def _protocol_name(proto_num: int) -> str:
    """Convert an IP protocol number to a human-readable name.

    Args:
        proto_num: Integer IP protocol number (e.g. 6 for TCP).

    Returns:
        str: Protocol name such as 'TCP', 'UDP', 'ICMP', or the raw number.
    """
    mapping = {1: "ICMP", 6: "TCP", 17: "UDP"}
    return mapping.get(proto_num, str(proto_num))


def parse_packet(packet) -> dict | None:
    """Extract relevant fields from a Scapy packet.

    Args:
        packet: A Scapy packet object captured by ``sniff()``.

    Returns:
        dict | None: Dictionary with extracted fields, or ``None`` if
        the packet does not contain an IP layer.
    """
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

        return {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "src_ip": ip_layer.src,
            "dst_ip": ip_layer.dst,
            "protocol": protocol,
            "packet_size": len(packet),
            "src_port": src_port,
            "dst_port": dst_port,
        }
    except Exception as exc:
        print(f"[capture] Error parsing packet: {exc}")
        return None


# ---------------------------------------------------------------------------
# CSV persistence
# ---------------------------------------------------------------------------

def _ensure_csv() -> None:
    """Create the data directory and CSV file with headers if they do not exist."""
    os.makedirs(DATA_DIR, exist_ok=True)
    if not os.path.isfile(CSV_PATH):
        try:
            with open(CSV_PATH, "w", newline="", encoding="utf-8") as fh:
                writer = csv.DictWriter(fh, fieldnames=CSV_HEADERS)
                writer.writeheader()
            print(f"[capture] Created new CSV file: {CSV_PATH}")
        except OSError as exc:
            print(f"[capture] Failed to create CSV: {exc}")


def _prune_csv() -> None:
    """Keep only the last 2000 lines of the CSV file if it exceeds 5000 lines.

    This prevents file bloat, excessive reading times, and sharing violations/locks.
    """
    if not os.path.isfile(CSV_PATH):
        return
    try:
        with open(CSV_PATH, "r", encoding="utf-8") as f:
            lines = f.readlines()
        if len(lines) > 5000:
            header = lines[0]
            trimmed = [header] + lines[-2000:]
            with open(CSV_PATH, "w", newline="", encoding="utf-8") as f:
                f.writelines(trimmed)
            print(f"[capture] Trimmed CSV file to the last 2000 lines to prevent bloat")
    except Exception as exc:
        print(f"[capture] Error pruning CSV: {exc}")


def flush_buffer() -> None:
    """Write buffered packets to the CSV file and clear the buffer."""
    global _packet_buffer
    if not _packet_buffer:
        return
    try:
        _ensure_csv()
        with open(CSV_PATH, "a", newline="", encoding="utf-8") as fh:
            writer = csv.DictWriter(fh, fieldnames=CSV_HEADERS)
            for row in _packet_buffer:
                writer.writerow(row)
        print(f"[capture] Flushed {len(_packet_buffer)} packets to {CSV_PATH}")
        _packet_buffer = []
        # Prune to prevent unbounded growth and locking/sharing violations
        _prune_csv()
    except OSError as exc:
        print(f"[capture] Error writing CSV: {exc}")


# ---------------------------------------------------------------------------
# Sniff callback
# ---------------------------------------------------------------------------

def packet_callback(packet) -> None:
    """Callback invoked by Scapy for every captured packet.

    Parses the packet, prints a summary to the console, appends it to
    the in-memory buffer, and flushes to CSV every ``FLUSH_INTERVAL``
    packets.

    Args:
        packet: Raw Scapy packet object.
    """
    parsed = parse_packet(packet)
    if parsed is None:
        return

    # Console output for live demo feedback
    print(
        f"[capture] {parsed['src_ip']}:{parsed['src_port']} -> "
        f"{parsed['dst_ip']}:{parsed['dst_port']} | "
        f"{parsed['protocol']} | {parsed['packet_size']}B"
    )

    _packet_buffer.append(parsed)

    if len(_packet_buffer) >= FLUSH_INTERVAL:
        flush_buffer()


# ---------------------------------------------------------------------------
# Main entry point
# ---------------------------------------------------------------------------

def start_capture(interface: str | None = None, packet_count: int = 0) -> None:
    """Start live packet capture on the specified or auto-detected interface.

    Args:
        interface: Network interface name.  If ``None``, the Docker
            bridge interface is auto-detected.
        packet_count: Number of packets to capture.  ``0`` means
            capture indefinitely until interrupted.
    """
    _ensure_csv()
    iface = interface or detect_docker_interface()

    print(f"[capture] Starting packet capture on interface: {iface}")
    print(f"[capture] Saving to: {CSV_PATH}")
    print(f"[capture] Flushing every {FLUSH_INTERVAL} packets")
    print("[capture] Press Ctrl+C to stop.\n")

    try:
        sniff(
            iface=iface,
            prn=packet_callback,
            count=packet_count if packet_count > 0 else 0,
            store=False,
        )
    except PermissionError:
        print(
            "[capture] ERROR: Permission denied. "
            "Run with elevated privileges (sudo / Administrator)."
        )
    except KeyboardInterrupt:
        print("\n[capture] Capture interrupted by user.")
    except Exception as exc:
        print(f"[capture] Unexpected error during capture: {exc}")
    finally:
        # Flush any remaining packets on exit
        flush_buffer()
        print("[capture] Capture stopped.")


if __name__ == "__main__":
    start_capture()
