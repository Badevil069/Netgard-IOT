"""
quarantine.py - Control Layer: Rogue IoT Device Quarantine Module

Provides automated network quarantine for rogue IoT devices by pushing
Cisco IOS commands via Netmiko to isolate suspicious devices into VLAN 999.
Falls back to simulated quarantine when no real/GNS3 switch is available.
"""

import datetime
from typing import Dict, List, Optional

try:
    from netmiko import ConnectHandler
    NETMIKO_AVAILABLE = True
except ImportError:
    NETMIKO_AVAILABLE = False
    print("[WARN] netmiko is not installed. All quarantine actions will be simulated.")

# ---------------------------------------------------------------------------
# Module-level quarantine log — stores every quarantine action taken
# ---------------------------------------------------------------------------
quarantine_log: List[Dict] = []

# ---------------------------------------------------------------------------
# Cisco IOS command template used for quarantine
# ---------------------------------------------------------------------------
QUARANTINE_VLAN = 999
QUARANTINE_INTERFACE = "GigabitEthernet0/1"

SIMULATED_SWITCH = {
    "device_type": "cisco_ios",
    "host": "127.0.0.1",
    "port": 5000,
    "username": "admin",
    "password": "admin",
    "secret": "admin",
    "timeout": 10,
}


def _build_quarantine_commands() -> List[str]:
    """Build the ordered list of Cisco IOS commands to quarantine a device.

    Returns:
        List[str]: Cisco IOS CLI commands that move the target interface
                   to VLAN 999 and administratively shut it down.
    """
    return [
        "enable",
        "configure terminal",
        f"interface {QUARANTINE_INTERFACE}",
        "switchport mode access",
        f"switchport access vlan {QUARANTINE_VLAN}",
        "shutdown",
        "end",
    ]


import subprocess

IP_TO_CONTAINER = {
    "172.20.0.10": "iot_camera",
    "172.20.0.11": "iot_thermostat",
    "172.20.0.12": "iot_bulb",
    "172.20.0.99": "iot_rogue",
}


def _stop_docker_container(ip: str) -> None:
    container_name = IP_TO_CONTAINER.get(ip)
    if not container_name:
        return
    try:
        print(f"[QUARANTINE] Stopping Docker container: {container_name}")
        subprocess.run(["docker", "stop", container_name], capture_output=True, text=True, check=True)
    except Exception as exc:
        print(f"[QUARANTINE] Failed to stop container {container_name}: {exc}")


def _pause_docker_container(ip: str) -> None:
    container_name = IP_TO_CONTAINER.get(ip)
    if not container_name:
        return
    try:
        print(f"[QUARANTINE] Pausing Docker container: {container_name}")
        subprocess.run(["docker", "pause", container_name], capture_output=True, text=True, check=True)
    except Exception as exc:
        print(f"[QUARANTINE] Failed to pause container {container_name}: {exc}")


def quarantine_device(ip: str, mac: str = "unknown") -> Dict:
    """Quarantine a rogue IoT device by isolating it into VLAN 999.

    Attempts to connect to a Cisco IOS switch (real or GNS3) via Netmiko
    and push quarantine commands.  If the connection fails - typically
    because no GNS3 lab or physical switch is reachable on 127.0.0.1:5000 -
    the function falls back to *simulated* quarantine: it logs the action,
    records the exact commands that would have been sent, and prints them
    to the console.

    Args:
        ip:  IP address of the rogue device to quarantine.
        mac: MAC address of the rogue device (default ``"unknown"``).

    Returns:
        dict: A result dictionary containing:
            - **ip** (*str*): Target device IP.
            - **mac** (*str*): Target device MAC.
            - **action** (*str*): ``"quarantine"``.
            - **vlan** (*int*): Destination VLAN (999).
            - **timestamp** (*str*): ISO-8601 timestamp of the action.
            - **success** (*bool*): ``True`` if commands were pushed to a
              real switch; ``False`` if simulated.
            - **note** (*str*): Human-readable status message.
            - **commands_sent** (*list[str]*): Exact Cisco IOS commands.
    """
    timestamp = datetime.datetime.now().isoformat()
    commands = _build_quarantine_commands()

    result: Dict = {
        "ip": ip,
        "mac": mac,
        "action": "quarantine",
        "vlan": QUARANTINE_VLAN,
        "timestamp": timestamp,
        "success": False,
        "note": "",
        "commands_sent": commands,
    }

    # ------------------------------------------------------------------
    # Attempt real Netmiko connection to the simulated (GNS3) switch
    # ------------------------------------------------------------------
    if NETMIKO_AVAILABLE:
        try:
            print(f"[QUARANTINE] Connecting to switch at "
                  f"{SIMULATED_SWITCH['host']}:{SIMULATED_SWITCH['port']} ...")
            connection = ConnectHandler(**SIMULATED_SWITCH)

            # Enter enable mode
            connection.enable()

            # Send configuration commands (skip 'enable' and 'end' — Netmiko
            # handles those via .enable() and .exit_config_mode())
            config_commands = [
                f"interface {QUARANTINE_INTERFACE}",
                "switchport mode access",
                f"switchport access vlan {QUARANTINE_VLAN}",
                "shutdown",
            ]
            output = connection.send_config_set(config_commands)
            connection.disconnect()

            result["success"] = True
            result["note"] = (
                f"Device {ip} (MAC {mac}) quarantined to VLAN {QUARANTINE_VLAN} "
                f"via live switch connection. Switch output: {output}"
            )

            print(f"[QUARANTINE] SUCCESS - {ip} moved to VLAN {QUARANTINE_VLAN}")

        except Exception as exc:
            # Connection failed - fall through to simulation
            print(f"[QUARANTINE] Live switch unavailable ({exc}). "
                  f"Falling back to simulated quarantine.")
            _simulate_quarantine(result, ip, mac, commands, timestamp)
    else:
        # Netmiko not installed at all
        print("[QUARANTINE] Netmiko not available. Running simulated quarantine.")
        _simulate_quarantine(result, ip, mac, commands, timestamp)

    # ------------------------------------------------------------------
    # Persist to the module-level quarantine log regardless of mode
    # ------------------------------------------------------------------
    _pause_docker_container(ip)
    quarantine_log.append(result)
    return result


def _simulate_quarantine(
    result: Dict,
    ip: str,
    mac: str,
    commands: List[str],
    timestamp: str,
) -> None:
    """Simulate quarantine when no live switch is reachable.

    Populates *result* in-place with simulation details and prints the
    exact Cisco IOS commands that would have been executed.

    Args:
        result:    The mutable result dict to update.
        ip:        Target device IP address.
        mac:       Target device MAC address.
        commands:  List of Cisco IOS commands.
        timestamp: ISO-8601 timestamp string.
    """
    result["success"] = False
    result["note"] = (
        f"[SIMULATED] Device {ip} (MAC {mac}) would be quarantined to "
        f"VLAN {QUARANTINE_VLAN}. No live switch connection - commands logged."
    )

    print("=" * 65)
    print(f"  SIMULATED QUARANTINE - {timestamp}")
    print(f"  Target IP : {ip}")
    print(f"  Target MAC: {mac}")
    print(f"  Dest VLAN : {QUARANTINE_VLAN}")
    print("-" * 65)
    print("  Cisco IOS commands that would be executed:")
    print()
    for cmd in commands:
        print(f"    switch# {cmd}")
    print()
    print("=" * 65)


def get_quarantine_log() -> List[Dict]:
    """Return the full quarantine log.

    Returns:
        list[dict]: A list of result dictionaries, one per quarantine
        action taken during this process's lifetime.  Each dict has the
        same schema as the return value of :func:`quarantine_device`.
    """
    return quarantine_log


# -----------------------------------------------------------------------
# Quick self-test when run directly
# -----------------------------------------------------------------------
if __name__ == "__main__":
    print("Running quarantine self-test ...\n")

    test_result = quarantine_device(ip="192.168.1.200", mac="aa:bb:cc:dd:ee:ff")

    print("\n--- Quarantine result dict ---")
    for key, value in test_result.items():
        print(f"  {key}: {value}")

    print(f"\nQuarantine log length: {len(get_quarantine_log())}")
    print("Self-test complete.")
