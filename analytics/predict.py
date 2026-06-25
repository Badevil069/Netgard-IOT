"""
predict.py - Real-time rogue IoT device prediction module.

Loads the trained IsolationForest model from ``models/isolation_forest.pkl``
and exposes a ``predict_device()`` function that maintains running per-IP
statistics in memory.  Each call updates the statistics for the given IP
and returns a classification result (``ROGUE`` or ``NORMAL``) along with
a confidence score.
"""

import os
import pickle
import time
from collections import defaultdict

import numpy as np


# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
MODEL_PATH = os.path.join(PROJECT_ROOT, "models", "isolation_forest.pkl")


# ---------------------------------------------------------------------------
# In-memory per-IP statistics
# ---------------------------------------------------------------------------

_ip_stats: dict[str, dict] = defaultdict(lambda: {
    "packet_count": 0,
    "first_seen": None,
    "last_seen": None,
    "total_packet_size": 0,
    "dst_ports": set(),
    "protocols": set(),
    "timestamps": [],
})


# ---------------------------------------------------------------------------
# Model loading
# ---------------------------------------------------------------------------

_model = None


def _load_model():
    """Load the trained IsolationForest model from disk.

    Caches the model in the module-level ``_model`` variable so that
    subsequent calls are instant.

    Returns:
        IsolationForest | None: The loaded model, or ``None`` if the
        model file cannot be found or loaded.
    """
    global _model
    if _model is not None:
        return _model

    if not os.path.isfile(MODEL_PATH):
        print(f"[predict] ERROR: Model not found at {MODEL_PATH}")
        print("[predict] Run train_model.py first to create the model.")
        return None

    try:
        with open(MODEL_PATH, "rb") as fh:
            _model = pickle.load(fh)
        print(f"[predict] Model loaded from {MODEL_PATH}")
        return _model
    except (pickle.UnpicklingError, EOFError, OSError) as exc:
        print(f"[predict] ERROR: Failed to load model: {exc}")
        return None
    except Exception as exc:
        print(f"[predict] ERROR: Unexpected error loading model: {exc}")
        return None


# ---------------------------------------------------------------------------
# Feature computation from running stats
# ---------------------------------------------------------------------------

def _compute_features(stats: dict) -> np.ndarray:
    """Compute the 5-feature vector from accumulated per-IP statistics.

    Args:
        stats: Dictionary of running statistics for a single IP address.

    Returns:
        np.ndarray: Feature vector of shape ``(1, 5)`` containing
        ``[packets_per_sec, avg_packet_size, unique_dst_ports,
        protocol_diversity, burst_score]``.
    """
    packet_count = stats["packet_count"]

    # Packets per second
    if stats["first_seen"] is not None and stats["last_seen"] is not None:
        duration = stats["last_seen"] - stats["first_seen"]
        packets_per_sec = packet_count / duration if duration > 0 else float(packet_count)
    else:
        packets_per_sec = float(packet_count)

    # Average packet size
    avg_packet_size = stats["total_packet_size"] / packet_count if packet_count > 0 else 0.0

    # Unique destination ports
    unique_dst_ports = float(len(stats["dst_ports"]))

    # Protocol diversity
    protocol_diversity = float(len(stats["protocols"]))

    # Burst score (std dev of inter-packet timing)
    burst_score = 0.0
    if len(stats["timestamps"]) >= 2:
        ts_sorted = sorted(stats["timestamps"])
        deltas = [ts_sorted[i + 1] - ts_sorted[i] for i in range(len(ts_sorted) - 1)]
        if deltas:
            burst_score = float(np.std(deltas))

    return np.array([[
        packets_per_sec,
        avg_packet_size,
        unique_dst_ports,
        protocol_diversity,
        burst_score,
    ]])


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def predict_device(ip: str, packet_size: int, dst_port: int, protocol: str, timestamp: float | None = None, run_prediction: bool = True) -> dict:
    """Classify a device as ROGUE or NORMAL based on accumulated traffic.

    Updates the running statistics for the given IP address, computes
    behavioural features, and runs the IsolationForest model to produce
    a classification.

    Args:
        ip: Source IP address of the device.
        packet_size: Size of the current packet in bytes.
        dst_port: Destination port of the current packet.
        protocol: Protocol name (e.g. ``'TCP'``, ``'UDP'``).
        timestamp: Optional unix timestamp of the packet.
        run_prediction: If True, execute full feature calculation and model prediction.

    Returns:
        dict: Prediction result containing:
            - ``ip`` (str): The device IP address.
            - ``status`` (str): ``'ROGUE'`` or ``'NORMAL'``.
            - ``confidence`` (float): Anomaly score (more negative = more
              anomalous).
            - ``packets_per_sec`` (float): Observed packet rate.
            - ``unique_ports`` (int): Number of distinct destination ports.
    """
    now = timestamp if timestamp is not None else time.time()
    stats = _ip_stats[ip]

    # Update running statistics
    stats["packet_count"] += 1
    stats["total_packet_size"] += packet_size
    stats["dst_ports"].add(dst_port)
    stats["protocols"].add(protocol)
    stats["timestamps"].append(now)

    if stats["first_seen"] is None:
        stats["first_seen"] = now
    stats["last_seen"] = now

    if not run_prediction:
        return {
            "ip": ip,
            "status": "NORMAL",
            "confidence": 0.0,
            "packets_per_sec": 0.0,
            "unique_ports": 0,
        }

    # Compute features
    features = _compute_features(stats)
    packets_per_sec = features[0, 0]
    unique_ports = int(features[0, 2])

    # Load model and predict
    model = _load_model()
    if model is None:
        result = {
            "ip": ip,
            "status": "UNKNOWN",
            "confidence": 0.0,
            "packets_per_sec": round(packets_per_sec, 4),
            "unique_ports": unique_ports,
        }
        print(f"[predict] {ip} : UNKNOWN (model unavailable)")
        return result

    try:
        prediction = model.predict(features)[0]
        score = model.decision_function(features)[0]

        status = "ROGUE" if prediction == -1 else "NORMAL"
        confidence = round(float(score), 6)

        result = {
            "ip": ip,
            "status": status,
            "confidence": confidence,
            "packets_per_sec": round(packets_per_sec, 4),
            "unique_ports": unique_ports,
        }

        status_label = "[ALERT]" if status == "ROGUE" else "[ OK  ]"
        print(
            f"[predict] {status_label} {ip} : {status} "
            f"(confidence={confidence:.4f}, pps={packets_per_sec:.2f}, "
            f"ports={unique_ports})"
        )

        return result

    except Exception as exc:
        print(f"[predict] ERROR: Prediction failed for {ip}: {exc}")
        return {
            "ip": ip,
            "status": "ERROR",
            "confidence": 0.0,
            "packets_per_sec": round(packets_per_sec, 4),
            "unique_ports": unique_ports,
        }


def reset_stats(ip: str | None = None) -> None:
    """Reset accumulated statistics for one or all IP addresses.

    Args:
        ip: IP address to reset.  If ``None``, all IP statistics are
            cleared.
    """
    if ip is None:
        _ip_stats.clear()
        print("[predict] All IP statistics cleared.")
    elif ip in _ip_stats:
        del _ip_stats[ip]
        print(f"[predict] Statistics cleared for {ip}.")
    else:
        print(f"[predict] No statistics found for {ip}.")


# ---------------------------------------------------------------------------
# Main — quick demo
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    print("[predict] Running quick prediction demo...\n")

    # Simulate normal device
    for i in range(5):
        predict_device("192.168.1.10", packet_size=120, dst_port=80, protocol="TCP")

    print()

    # Simulate rogue device — many ports, high rate
    for port in range(1, 51):
        predict_device("192.168.1.99", packet_size=40, dst_port=port, protocol="TCP")
        predict_device("192.168.1.99", packet_size=35, dst_port=port + 1000, protocol="UDP")

    print("\n[predict] Demo complete.")
