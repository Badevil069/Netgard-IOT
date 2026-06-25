import json
import requests
OLLAMA_URL = 'http://127.0.0.1:11434/api/generate'
OLLAMA_MODEL = 'llama3'
REQUEST_TIMEOUT = 90

def _build_prompt(device_info: dict) -> str:
    ip = device_info.get('ip', 'unknown')
    status = device_info.get('status', 'unknown')
    confidence = device_info.get('confidence', 0.0)
    pps = device_info.get('pps', device_info.get('packets_per_sec', 0.0))
    ports = device_info.get('unique_ports', 0)
    prompt = f'You are a network security analyst. A device at IP {ip} has been flagged as {status} by an anomaly detection system.\n\nDevice statistics:\n- Packets per second: {pps}\n- Unique destination ports contacted: {ports}\n- Anomaly confidence score: {confidence}\n\nExplain in plain English (2-3 sentences) what this means from a security perspective. Include what the device might be doing and what action a network administrator should take.'
    return prompt

def _build_fallback(device_info: dict) -> str:
    ip = device_info.get('ip', 'unknown')
    status = device_info.get('status', 'UNKNOWN')
    pps = device_info.get('pps', device_info.get('packets_per_sec', 0.0))
    ports = device_info.get('unique_ports', 0)
    reasons: list[str] = []
    if pps > 10:
        reasons.append('high packet rate')
    if ports > 10:
        reasons.append('port scanning activity')
    if status == 'ROGUE':
        reasons.append('anomalous traffic patterns')
    if not reasons:
        reasons.append('unusual network behaviour')
    reason_str = ', '.join(reasons)
    return f'AI analysis unavailable - Ollama not running. Device {ip} shows anomalous behavior based on: {reason_str}.'

def explain_threat(device_info: dict) -> str:
    prompt = _build_prompt(device_info)
    print(f"[explainer] Requesting AI explanation for {device_info.get('ip', '?')} ...")
    payload = {'model': OLLAMA_MODEL, 'prompt': prompt, 'stream': True}
    try:
        response = requests.post(OLLAMA_URL, json=payload, timeout=REQUEST_TIMEOUT, stream=True)
        response.raise_for_status()
        explanation_parts: list[str] = []
        for line in response.iter_lines(decode_unicode=True):
            if not line:
                continue
            try:
                chunk = json.loads(line)
                token = chunk.get('response', '')
                explanation_parts.append(token)
                print(token, end='', flush=True)
                if chunk.get('done', False):
                    break
            except json.JSONDecodeError:
                continue
        print()
        explanation = ''.join(explanation_parts).strip()
        if not explanation:
            print('[explainer] WARNING: Empty response from Ollama - using fallback.')
            return _build_fallback(device_info)
        print(f'[explainer] AI explanation received ({len(explanation)} chars).')
        return explanation
    except requests.exceptions.ConnectionError:
        print('[explainer] WARNING: Cannot connect to Ollama - is it running?')
        return _build_fallback(device_info)
    except requests.exceptions.Timeout:
        print(f'[explainer] WARNING: Ollama request timed out after {REQUEST_TIMEOUT}s.')
        return _build_fallback(device_info)
    except requests.exceptions.HTTPError as exc:
        print(f'[explainer] WARNING: Ollama returned HTTP error - {exc}')
        return _build_fallback(device_info)
    except Exception as exc:
        print(f'[explainer] ERROR: Unexpected error - {exc}')
        return _build_fallback(device_info)
if __name__ == '__main__':
    sample_device = {'ip': '192.168.1.99', 'status': 'ROGUE', 'confidence': -0.42, 'packets_per_sec': 150.0, 'unique_ports': 500}
    print('[explainer] Running demo with sample device data...\n')
    result = explain_threat(sample_device)
    print(f'\n--- Explanation ---\n{result}\n')