"""FastAPI backend for NetGuard IoT.

The application reads ``data/live_traffic.csv`` on every request, rebuilds
device summaries from the live packet capture, and exposes JSON endpoints for
the Next.js dashboard.
"""

from __future__ import annotations

import datetime as dt
import glob
import hashlib
import contextlib
import io
import threading
from pathlib import Path
from typing import Any

import numpy as np
import pandas as pd
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel

from analytics import predict
from analytics.explainer import explain_threat
from control.quarantine import get_quarantine_log, quarantine_device


PROJECT_ROOT = Path(__file__).resolve().parents[1]
CSV_PATH = PROJECT_ROOT / "data" / "live_traffic.csv"
INCIDENT_DIR = PROJECT_ROOT / "data" / "incidents"

DEVICE_CATALOG: dict[str, dict[str, str]] = {
    "172.20.0.10": {"name": "IP Camera", "mac": "0e:75:0e:1a:02:9f", "icon": "camera"},
    "172.20.0.11": {"name": "Thermostat", "mac": "76:2d:b4:87:f4:28", "icon": "thermometer"},
    "172.20.0.12": {"name": "Smart Bulb", "mac": "92:4d:cd:1f:66:02", "icon": "lightbulb"},
    "172.20.0.99": {"name": "UNKNOWN", "mac": "6a:62:94:dd:96:f4", "icon": "shield-alert"},
}

_PREDICTION_LOCK = threading.Lock()

app = FastAPI(title="NetGuard IoT API", version="1.0.0")


@app.on_event("startup")
def startup_event():
    import subprocess
    print("[STARTUP] Resetting simulators by unpausing all containers...")
    for container in ["iot_camera", "iot_thermostat", "iot_bulb", "iot_rogue"]:
        try:
            subprocess.run(["docker", "unpause", container], capture_output=True)
        except Exception:
            pass


app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:3000", "http://127.0.0.1:3000"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


class IncidentPayload(BaseModel):
    id: str
    device: str
    threat: str
    type: str
    affected: str
    action: str
    timestamp: str


def _count_lines(file_path: Path) -> int:
    try:
        with open(file_path, "rb") as f:
            return max(0, sum(1 for _ in f) - 1)
    except Exception:
        return 0


def _load_csv() -> pd.DataFrame:
    if not CSV_PATH.exists():
        return pd.DataFrame(columns=["timestamp", "src_ip", "dst_ip", "protocol", "packet_size", "src_port", "dst_port"])

    try:
        file_size = CSV_PATH.stat().st_size
        chunk_size = 500 * 1024  # 500 KB

        with open(CSV_PATH, "r", encoding="utf-8") as f:
            header = f.readline()

        if file_size > chunk_size:
            with open(CSV_PATH, "rb") as f:
                f.seek(file_size - chunk_size)
                content = f.read().decode("utf-8", errors="ignore")
                lines = content.splitlines()[1:]
            csv_data = header + "\n".join(lines)
            frame = pd.read_csv(io.StringIO(csv_data))
        else:
            frame = pd.read_csv(CSV_PATH)
    except Exception as e:
        print(f"[API] Error optimized-reading CSV: {e}")
        try:
            frame = pd.read_csv(CSV_PATH)
        except Exception:
            return pd.DataFrame(columns=["timestamp", "src_ip", "dst_ip", "protocol", "packet_size", "src_port", "dst_port"])

    expected_columns = ["timestamp", "src_ip", "dst_ip", "protocol", "packet_size", "src_port", "dst_port"]
    for column in expected_columns:
        if column not in frame.columns:
            frame[column] = None

    frame = frame[expected_columns].copy()
    frame["timestamp"] = pd.to_datetime(frame["timestamp"], utc=True, errors="coerce")
    frame["packet_size"] = pd.to_numeric(frame["packet_size"], errors="coerce").fillna(0).astype(int)
    frame["src_port"] = pd.to_numeric(frame["src_port"], errors="coerce").fillna(0).astype(int)
    frame["dst_port"] = pd.to_numeric(frame["dst_port"], errors="coerce").fillna(0).astype(int)
    frame = frame.dropna(subset=["timestamp", "src_ip", "dst_ip", "protocol"])

    # Filter to only the last 120 seconds of real-time traffic.
    # To prevent host-container clock drift from filtering out packets,
    # we use the latest packet's timestamp as the reference 'now'.
    if not frame.empty:
        now = frame["timestamp"].max()
        if pd.isna(now):
            now = dt.datetime.now(dt.timezone.utc)
    else:
        now = dt.datetime.now(dt.timezone.utc)

    cutoff = now - dt.timedelta(seconds=120)
    frame = frame[frame["timestamp"] >= cutoff]

    return frame.sort_values("timestamp").reset_index(drop=True)


def _device_catalog_entry(ip: str) -> dict[str, str]:
    if ip in DEVICE_CATALOG:
        return DEVICE_CATALOG[ip]

    digest = hashlib.md5(ip.encode("utf-8")).hexdigest()
    synthetic_mac = ":".join(digest[i : i + 2] for i in range(0, 12, 2))
    return {"name": "UNKNOWN", "mac": synthetic_mac, "icon": "device"}


def _threat_confidence(score: float) -> float:
    return round(float(100.0 / (1.0 + np.exp(score * 8.0))), 1)


def _format_timestamp(value: pd.Timestamp | None) -> str:
    if value is None or pd.isna(value):
        return dt.datetime.now(dt.timezone.utc).isoformat()
    return value.to_pydatetime().isoformat()


def _detection_reasons(pps: float, unique_ports: int, raw_score: float, name: str, quarantined: bool) -> list[str]:
    reasons: list[str] = []
    if unique_ports > 50:
        reasons.append(f"Port scan detected: {unique_ports} unique ports")
    if pps > 20:
        reasons.append(f"Packet rate anomaly: {pps:.2f} pps")
    if name == "UNKNOWN":
        reasons.append("Unknown MAC vendor")
    if raw_score < 0:
        reasons.append(f"Isolation Forest anomaly score: {raw_score:.2f}")
    if quarantined:
        reasons.append("Device already contained")
    return reasons


def _run_prediction_for_group(group: pd.DataFrame) -> dict[str, Any]:
    ip = str(group["src_ip"].iloc[0])
    rows = group.sort_values("timestamp")
    packet_count = len(rows)

    if packet_count > 0:
        observed_pps = packet_count / 120.0
        avg_packet_size = round(float(rows["packet_size"].mean()), 2)
        unique_ports = int(rows["dst_port"].nunique())

        with contextlib.redirect_stdout(io.StringIO()):
            predict.reset_stats(ip)
            last_result = {}
            total_rows = len(rows)
            for idx, (_, row) in enumerate(rows.iterrows()):
                is_last = (idx == total_rows - 1)
                ts_float = row["timestamp"].timestamp()
                last_result = predict.predict_device(
                    ip=ip,
                    packet_size=int(row["packet_size"]),
                    dst_port=int(row["dst_port"]),
                    protocol=str(row["protocol"]),
                    timestamp=ts_float,
                    run_prediction=is_last,
                )

        score = float(last_result.get("confidence", 0.0))
        status = str(last_result.get("status", "UNKNOWN"))
        # Match rules threshold to simulation parameters:
        # Rogue scans at 10 PPS (sends ~1200 packets in 120s) and scans up to 1000 ports.
        if unique_ports > 10 or observed_pps > 5.0:
            status = "ROGUE"
    else:
        observed_pps = 0.0
        avg_packet_size = 0.0
        unique_ports = 0
        score = 0.0
        status = "NORMAL"

    latest_seen = rows["timestamp"].max() if packet_count > 0 else dt.datetime.now(dt.timezone.utc)
    catalog = _device_catalog_entry(ip)
    quarantined = any(entry.get("ip") == ip for entry in get_quarantine_log())
    confidence = _threat_confidence(score)
    if status == "ROGUE":
        confidence = max(confidence, 90.0 if unique_ports > 50 else 80.0)

    return {
        "name": catalog["name"],
        "ip": ip,
        "mac": catalog["mac"],
        "status": "QUARANTINED" if quarantined else status,
        "pps": round(observed_pps, 2),
        "unique_ports": unique_ports,
        "avg_packet_size": avg_packet_size,
        "confidence": confidence,
        "quarantined": quarantined,
        "last_seen": _format_timestamp(latest_seen),
        "detection_reasons": _detection_reasons(observed_pps, unique_ports, score, catalog["name"], quarantined),
        "raw_score": round(score, 4),
    }


def _build_devices() -> list[dict[str, Any]]:
    frame = _load_csv()
    if frame.empty:
        return []

    source_ips = frame["src_ip"].astype(str)
    local_frame = frame[source_ips.str.startswith("172.20.0.")].copy()
    if local_frame.empty:
        local_frame = frame[source_ips.str.startswith("172.")].copy()
    if local_frame.empty:
        local_frame = frame.copy()

    devices: list[dict[str, Any]] = []
    with _PREDICTION_LOCK:
        for _, group in local_frame.groupby("src_ip", sort=False):
            devices.append(_run_prediction_for_group(group))

    devices.sort(key=lambda item: (item["status"] != "ROGUE", item["status"] != "QUARANTINED", item["ip"]))
    return devices


def _packets_to_json(frame: pd.DataFrame, limit: int = 50) -> list[dict[str, Any]]:
    tail = frame.tail(limit).copy()
    packets: list[dict[str, Any]] = []
    for row in tail.to_dict(orient="records"):
        timestamp = row.get("timestamp")
        if pd.notna(timestamp):
            timestamp_value = timestamp.to_pydatetime().isoformat()
        else:
            timestamp_value = ""
        packets.append({
            "timestamp": timestamp_value,
            "src_ip": str(row.get("src_ip", "")),
            "dst_ip": str(row.get("dst_ip", "")),
            "src_port": int(row.get("src_port", 0) or 0),
            "dst_port": int(row.get("dst_port", 0) or 0),
            "protocol": str(row.get("protocol", "")),
            "packet_size": int(row.get("packet_size", 0) or 0),
        })
    return packets


def _read_incident_reports() -> list[dict[str, Any]]:
    if not INCIDENT_DIR.exists():
        return []

    reports: list[dict[str, Any]] = []
    for path in sorted(glob.glob(str(INCIDENT_DIR / "*.txt")), reverse=True):
        content = Path(path).read_text(encoding="utf-8", errors="ignore").strip()
        parsed: dict[str, str] = {}
        for line in content.splitlines():
            if ":" not in line:
                continue
            key, value = line.split(":", 1)
            parsed[key.strip().lower()] = value.strip()

        reports.append({
            "id": parsed.get("id", Path(path).stem),
            "device": parsed.get("device", "unknown"),
            "threat": parsed.get("threat", "unknown"),
            "type": parsed.get("type", "unknown"),
            "affected": parsed.get("affected", "unknown"),
            "action": parsed.get("action", "unknown"),
            "timestamp": parsed.get("timestamp", "unknown"),
            "raw": content,
            "path": Path(path).name,
        })
    return reports


def _summary_stats(devices: list[dict[str, Any]], packets: pd.DataFrame, incidents: list[dict[str, Any]]) -> dict[str, Any]:
    total_devices = len(devices)
    rogue_devices = sum(1 for device in devices if device["status"] == "ROGUE")
    quarantined_devices = sum(1 for device in devices if device["status"] == "QUARANTINED" or device["quarantined"])
    normal_devices = max(0, total_devices - rogue_devices - quarantined_devices)
    total_packets = _count_lines(CSV_PATH)

    if rogue_devices > 0:
        threat_level = "RED"
    elif quarantined_devices > 0:
        threat_level = "YELLOW"
    else:
        threat_level = "GREEN"

    return {
        "total_devices": total_devices,
        "normal_devices": normal_devices,
        "rogue_devices": rogue_devices,
        "quarantined_devices": quarantined_devices,
        "total_packets": total_packets,
        "incident_count": len(incidents),
        "threat_level": threat_level,
        "system_status": "ONLINE",
        "timestamp": dt.datetime.now(dt.timezone.utc).isoformat(),
    }


def _device_by_ip(ip: str) -> dict[str, Any]:
    devices = _build_devices()
    for device in devices:
        if device["ip"] == ip:
            return device

    catalog = _device_catalog_entry(ip)
    return {
        "name": catalog["name"],
        "ip": ip,
        "mac": catalog["mac"],
        "status": "NORMAL",
        "pps": 0.0,
        "unique_ports": 0,
        "avg_packet_size": 0.0,
        "confidence": 0.0,
        "quarantined": any(entry.get("ip") == ip for entry in get_quarantine_log()),
        "last_seen": dt.datetime.now(dt.timezone.utc).isoformat(),
        "detection_reasons": [],
        "raw_score": 0.0,
    }


@app.get("/api/devices")
def get_devices() -> dict[str, Any]:
    devices = _build_devices()
    return {"devices": devices, "timestamp": dt.datetime.now(dt.timezone.utc).isoformat()}


@app.get("/api/packets")
def get_packets() -> dict[str, Any]:
    frame = _load_csv()
    total_packets = _count_lines(CSV_PATH)
    return {
        "packets": _packets_to_json(frame, limit=50),
        "total_packets": total_packets,
        "timestamp": dt.datetime.now(dt.timezone.utc).isoformat()
    }


@app.get("/api/quarantine")
def get_quarantine() -> dict[str, Any]:
    return {"actions": get_quarantine_log(), "timestamp": dt.datetime.now(dt.timezone.utc).isoformat()}


@app.post("/api/quarantine/{ip}")
def post_quarantine(ip: str) -> dict[str, Any]:
    device = _device_by_ip(ip)
    result = quarantine_device(ip=ip, mac=str(device.get("mac", "unknown")))
    return {"result": result, "device": device, "timestamp": dt.datetime.now(dt.timezone.utc).isoformat()}


@app.get("/api/incidents")
def get_incidents() -> dict[str, Any]:
    return {"incidents": _read_incident_reports(), "timestamp": dt.datetime.now(dt.timezone.utc).isoformat()}


@app.post("/api/incidents")
def post_incident(payload: IncidentPayload) -> dict[str, Any]:
    INCIDENT_DIR.mkdir(parents=True, exist_ok=True)
    file_path = INCIDENT_DIR / f"{payload.id}.txt"
    content = f"""ID: {payload.id}
Device: {payload.device}
Threat: {payload.threat}
Type: {payload.type}
Affected: {payload.affected}
Action: {payload.action}
Timestamp: {payload.timestamp}
"""
    file_path.write_text(content, encoding="utf-8")
    return {"status": "success", "id": payload.id, "timestamp": dt.datetime.now(dt.timezone.utc).isoformat()}


@app.get("/api/stats")
def get_stats() -> dict[str, Any]:
    frame = _load_csv()
    devices = _build_devices()
    incidents = _read_incident_reports()
    return {"stats": _summary_stats(devices, frame, incidents), "timestamp": dt.datetime.now(dt.timezone.utc).isoformat()}


@app.get("/api/ai/explain/{ip}")
def get_ai_explanation(ip: str) -> dict[str, Any]:
    device = _device_by_ip(ip)
    explanation = explain_threat(device)
    return {"ip": ip, "explanation": explanation, "device": device, "timestamp": dt.datetime.now(dt.timezone.utc).isoformat()}


@app.get("/health")
def healthcheck() -> dict[str, str]:
    return {"status": "ok"}


if __name__ == "__main__":
    import uvicorn

    uvicorn.run("api.main:app", host="0.0.0.0", port=8000, reload=True)
