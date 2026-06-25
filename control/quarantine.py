import datetime
from typing import Dict, List, Optional
try:
    from netmiko import ConnectHandler
    NETMIKO_AVAILABLE = True
except ImportError:
    NETMIKO_AVAILABLE = False
    print('[WARN] netmiko is not installed. All quarantine actions will be simulated.')
quarantine_log: List[Dict] = []
QUARANTINE_VLAN = 999
QUARANTINE_INTERFACE = 'GigabitEthernet0/1'
SIMULATED_SWITCH = {'device_type': 'cisco_ios', 'host': '127.0.0.1', 'port': 5000, 'username': 'admin', 'password': 'admin', 'secret': 'admin', 'timeout': 10}

def _build_quarantine_commands() -> List[str]:
    return ['enable', 'configure terminal', f'interface {QUARANTINE_INTERFACE}', 'switchport mode access', f'switchport access vlan {QUARANTINE_VLAN}', 'shutdown', 'end']
import subprocess
IP_TO_CONTAINER = {'172.20.0.10': 'iot_camera', '172.20.0.11': 'iot_thermostat', '172.20.0.12': 'iot_bulb', '172.20.0.99': 'iot_rogue'}

def _stop_docker_container(ip: str) -> None:
    container_name = IP_TO_CONTAINER.get(ip)
    if not container_name:
        return
    try:
        print(f'[QUARANTINE] Stopping Docker container: {container_name}')
        subprocess.run(['docker', 'stop', container_name], capture_output=True, text=True, check=True)
    except Exception as exc:
        print(f'[QUARANTINE] Failed to stop container {container_name}: {exc}')

def _pause_docker_container(ip: str) -> None:
    container_name = IP_TO_CONTAINER.get(ip)
    if not container_name:
        return
    try:
        print(f'[QUARANTINE] Pausing Docker container: {container_name}')
        subprocess.run(['docker', 'pause', container_name], capture_output=True, text=True, check=True)
    except Exception as exc:
        print(f'[QUARANTINE] Failed to pause container {container_name}: {exc}')

def quarantine_device(ip: str, mac: str='unknown') -> Dict:
    timestamp = datetime.datetime.now().isoformat()
    commands = _build_quarantine_commands()
    result: Dict = {'ip': ip, 'mac': mac, 'action': 'quarantine', 'vlan': QUARANTINE_VLAN, 'timestamp': timestamp, 'success': False, 'note': '', 'commands_sent': commands}
    if NETMIKO_AVAILABLE:
        try:
            print(f"[QUARANTINE] Connecting to switch at {SIMULATED_SWITCH['host']}:{SIMULATED_SWITCH['port']} ...")
            connection = ConnectHandler(**SIMULATED_SWITCH)
            connection.enable()
            config_commands = [f'interface {QUARANTINE_INTERFACE}', 'switchport mode access', f'switchport access vlan {QUARANTINE_VLAN}', 'shutdown']
            output = connection.send_config_set(config_commands)
            connection.disconnect()
            result['success'] = True
            result['note'] = f'Device {ip} (MAC {mac}) quarantined to VLAN {QUARANTINE_VLAN} via live switch connection. Switch output: {output}'
            print(f'[QUARANTINE] SUCCESS - {ip} moved to VLAN {QUARANTINE_VLAN}')
        except Exception as exc:
            print(f'[QUARANTINE] Live switch unavailable ({exc}). Falling back to simulated quarantine.')
            _simulate_quarantine(result, ip, mac, commands, timestamp)
    else:
        print('[QUARANTINE] Netmiko not available. Running simulated quarantine.')
        _simulate_quarantine(result, ip, mac, commands, timestamp)
    _pause_docker_container(ip)
    quarantine_log.append(result)
    return result

def _simulate_quarantine(result: Dict, ip: str, mac: str, commands: List[str], timestamp: str) -> None:
    result['success'] = False
    result['note'] = f'[SIMULATED] Device {ip} (MAC {mac}) would be quarantined to VLAN {QUARANTINE_VLAN}. No live switch connection - commands logged.'
    print('=' * 65)
    print(f'  SIMULATED QUARANTINE - {timestamp}')
    print(f'  Target IP : {ip}')
    print(f'  Target MAC: {mac}')
    print(f'  Dest VLAN : {QUARANTINE_VLAN}')
    print('-' * 65)
    print('  Cisco IOS commands that would be executed:')
    print()
    for cmd in commands:
        print(f'    switch# {cmd}')
    print()
    print('=' * 65)

def get_quarantine_log() -> List[Dict]:
    return quarantine_log
if __name__ == '__main__':
    print('Running quarantine self-test ...\n')
    test_result = quarantine_device(ip='192.168.1.200', mac='aa:bb:cc:dd:ee:ff')
    print('\n--- Quarantine result dict ---')
    for key, value in test_result.items():
        print(f'  {key}: {value}')
    print(f'\nQuarantine log length: {len(get_quarantine_log())}')
    print('Self-test complete.')