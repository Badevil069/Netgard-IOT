import os
import pickle
import time
from collections import defaultdict
import numpy as np
PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
MODEL_PATH = os.path.join(PROJECT_ROOT, 'models', 'isolation_forest.pkl')
_ip_stats: dict[str, dict] = defaultdict(lambda: {'packet_count': 0, 'first_seen': None, 'last_seen': None, 'total_packet_size': 0, 'dst_ports': set(), 'protocols': set(), 'timestamps': []})
_model = None

def _load_model():
    global _model
    if _model is not None:
        return _model
    if not os.path.isfile(MODEL_PATH):
        print(f'[predict] ERROR: Model not found at {MODEL_PATH}')
        print('[predict] Run train_model.py first to create the model.')
        return None
    try:
        with open(MODEL_PATH, 'rb') as fh:
            _model = pickle.load(fh)
        print(f'[predict] Model loaded from {MODEL_PATH}')
        return _model
    except (pickle.UnpicklingError, EOFError, OSError) as exc:
        print(f'[predict] ERROR: Failed to load model: {exc}')
        return None
    except Exception as exc:
        print(f'[predict] ERROR: Unexpected error loading model: {exc}')
        return None

def _compute_features(stats: dict) -> np.ndarray:
    packet_count = stats['packet_count']
    if stats['first_seen'] is not None and stats['last_seen'] is not None:
        duration = stats['last_seen'] - stats['first_seen']
        packets_per_sec = packet_count / duration if duration > 0 else float(packet_count)
    else:
        packets_per_sec = float(packet_count)
    avg_packet_size = stats['total_packet_size'] / packet_count if packet_count > 0 else 0.0
    unique_dst_ports = float(len(stats['dst_ports']))
    protocol_diversity = float(len(stats['protocols']))
    burst_score = 0.0
    if len(stats['timestamps']) >= 2:
        ts_sorted = sorted(stats['timestamps'])
        deltas = [ts_sorted[i + 1] - ts_sorted[i] for i in range(len(ts_sorted) - 1)]
        if deltas:
            burst_score = float(np.std(deltas))
    return np.array([[packets_per_sec, avg_packet_size, unique_dst_ports, protocol_diversity, burst_score]])

def predict_device(ip: str, packet_size: int, dst_port: int, protocol: str, timestamp: float | None=None, run_prediction: bool=True) -> dict:
    now = timestamp if timestamp is not None else time.time()
    stats = _ip_stats[ip]
    stats['packet_count'] += 1
    stats['total_packet_size'] += packet_size
    stats['dst_ports'].add(dst_port)
    stats['protocols'].add(protocol)
    stats['timestamps'].append(now)
    if stats['first_seen'] is None:
        stats['first_seen'] = now
    stats['last_seen'] = now
    if not run_prediction:
        return {'ip': ip, 'status': 'NORMAL', 'confidence': 0.0, 'packets_per_sec': 0.0, 'unique_ports': 0}
    features = _compute_features(stats)
    packets_per_sec = features[0, 0]
    unique_ports = int(features[0, 2])
    model = _load_model()
    if model is None:
        result = {'ip': ip, 'status': 'UNKNOWN', 'confidence': 0.0, 'packets_per_sec': round(packets_per_sec, 4), 'unique_ports': unique_ports}
        print(f'[predict] {ip} : UNKNOWN (model unavailable)')
        return result
    try:
        prediction = model.predict(features)[0]
        score = model.decision_function(features)[0]
        status = 'ROGUE' if prediction == -1 else 'NORMAL'
        confidence = round(float(score), 6)
        result = {'ip': ip, 'status': status, 'confidence': confidence, 'packets_per_sec': round(packets_per_sec, 4), 'unique_ports': unique_ports}
        status_label = '[ALERT]' if status == 'ROGUE' else '[ OK  ]'
        print(f'[predict] {status_label} {ip} : {status} (confidence={confidence:.4f}, pps={packets_per_sec:.2f}, ports={unique_ports})')
        return result
    except Exception as exc:
        print(f'[predict] ERROR: Prediction failed for {ip}: {exc}')
        return {'ip': ip, 'status': 'ERROR', 'confidence': 0.0, 'packets_per_sec': round(packets_per_sec, 4), 'unique_ports': unique_ports}

def reset_stats(ip: str | None=None) -> None:
    if ip is None:
        _ip_stats.clear()
        print('[predict] All IP statistics cleared.')
    elif ip in _ip_stats:
        del _ip_stats[ip]
        print(f'[predict] Statistics cleared for {ip}.')
    else:
        print(f'[predict] No statistics found for {ip}.')
if __name__ == '__main__':
    print('[predict] Running quick prediction demo...\n')
    for i in range(5):
        predict_device('192.168.1.10', packet_size=120, dst_port=80, protocol='TCP')
    print()
    for port in range(1, 51):
        predict_device('192.168.1.99', packet_size=40, dst_port=port, protocol='TCP')
        predict_device('192.168.1.99', packet_size=35, dst_port=port + 1000, protocol='UDP')
    print('\n[predict] Demo complete.')