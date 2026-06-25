# 🛡️ Rogue IoT Detector — AI-Driven Rogue IoT Device Detection & Quarantine System

## Project Overview

Rogue IoT Detector is an end-to-end cybersecurity system that **detects unauthorized IoT devices** on a network, **classifies them as threats using machine learning**, and **automatically quarantines them** by pushing Cisco IOS commands to a network switch. It combines real-time packet capture with Isolation Forest anomaly detection, LLaMA 3 natural-language threat explanations, and a Streamlit dashboard for live monitoring — all designed to run as a convincing 2-minute live demo.

---

## Architecture

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                        ROGUE IoT DETECTOR — ARCHITECTURE                    │
├─────────────────────────────────────────────────────────────────────────────┤
│                                                                             │
│  ┌───────────────────┐     ┌──────────────────────┐                        │
│  │   EDGE LAYER      │     │   ANALYTICS LAYER    │                        │
│  │                   │     │                      │                        │
│  │  Docker IoT       │────▶│  Scapy Packet        │                        │
│  │  Simulators       │     │  Capture             │                        │
│  │                   │     │         │             │                        │
│  │  • Normal Devices │     │         ▼             │                        │
│  │  • Rogue Device   │     │  Isolation Forest     │                        │
│  │  • DHCP/ARP/DNS   │     │  Anomaly Detection    │                        │
│  └───────────────────┘     │         │             │                        │
│                            │         ▼             │                        │
│                            │  LLaMA 3 Threat       │                        │
│                            │  Explanation (Ollama)  │                        │
│                            └──────────┬─────────────┘                       │
│                                       │                                     │
│                                       ▼                                     │
│  ┌───────────────────┐     ┌──────────────────────┐                        │
│  │  DASHBOARD LAYER  │     │  CONTROL LAYER       │                        │
│  │                   │     │                      │                        │
│  │  Streamlit UI     │◀───▶│  Netmiko Quarantine  │                        │
│  │                   │     │                      │                        │
│  │  • Device Table   │     │  • Cisco IOS CLI     │                        │
│  │  • Risk Scores    │     │  • VLAN 999 Isolation │                        │
│  │  • Threat Explain │     │  • GNS3 / Simulated  │                        │
│  │  • Quarantine Log │     │  • Audit Logging     │                        │
│  └───────────────────┘     └──────────────────────┘                        │
│                                                                             │
│  DATA FLOW:                                                                │
│  Docker Containers ──▶ Scapy Capture ──▶ Isolation Forest ──▶ Quarantine   │
│                                              │                              │
│                                              ▼                              │
│                                         Streamlit Dashboard                 │
└─────────────────────────────────────────────────────────────────────────────┘
```

---

## Features

| | Feature | Description |
|---|---|---|
| 📡 | **Live Packet Capture** | Scapy sniffs DHCP, ARP, and DNS traffic from Docker bridge |
| 🤖 | **ML Anomaly Detection** | Isolation Forest flags devices with abnormal network behavior |
| 🧠 | **AI Threat Explanation** | LLaMA 3 (via Ollama) generates plain-English threat analysis |
| 🔒 | **Auto-Quarantine** | Netmiko pushes Cisco IOS commands to isolate rogues in VLAN 999 |
| 📊 | **Real-Time Dashboard** | Streamlit UI with color-coded device table and risk scores |
| 🐳 | **Dockerized IoT Sims** | Lightweight containers simulate normal + rogue IoT devices |
| 📝 | **Audit Logging** | Every quarantine action is timestamped and logged |
| 🎯 | **Interview-Ready Demo** | Designed for a compelling 2-minute live walkthrough |

---

## Tech Stack

| Component | Technology | Purpose |
|---|---|---|
| Packet Capture | **Scapy** | Sniff and parse raw network packets from Docker bridge |
| Anomaly Detection | **scikit-learn** (Isolation Forest) | Unsupervised ML to flag rogue devices |
| Threat Explanation | **LLaMA 3** via **Ollama** | Natural-language threat analysis |
| Network Quarantine | **Netmiko** + **Paramiko** | Push Cisco IOS commands to switches (real or GNS3) |
| Dashboard | **Streamlit** | Interactive web UI with auto-refresh |
| IoT Simulation | **Docker** + **docker-compose** | Simulate normal and rogue IoT network traffic |
| Data Processing | **Pandas** + **NumPy** | Feature extraction and data manipulation |
| HTTP Client | **Requests** | Ollama API communication |
| Configuration | **python-dotenv** | Environment variable management |

---

## Prerequisites

- **Python 3.9+**
- **Docker** and **Docker Compose**
- **Ollama** (for LLaMA 3 threat explanations)
- **pip** (Python package manager)
- **Root/Admin access** (required for raw packet capture with Scapy)

---

## Installation

### 1. Clone and install Python dependencies

```bash
git clone <your-repo-url> rogue-iot-detector
cd rogue-iot-detector
pip install -r requirements.txt
```

### 2. Set up Docker IoT simulators

```bash
docker-compose -f docker/docker-compose.yml build
```

### 3. Install and start Ollama with LLaMA 3

```bash
# Install Ollama (see https://ollama.com for your OS)
ollama pull llama3
ollama serve
```

---

## How to Run

Open **four terminal windows** and run the following commands in order:

### Terminal 1 — Train the anomaly detection model

```bash
python analytics/train_model.py
```

### Terminal 2 — Start the Docker IoT simulators

```bash
docker-compose -f docker/docker-compose.yml up -d
```

### Terminal 3 — Start live packet capture (runs in Docker or natively with root)

Via Docker Compose (cross-platform, recommended):
```bash
docker-compose -f docker/docker-compose.yml up -d capture
```

Or natively (requires root/Administrator privileges on the host):
```bash
sudo python analytics/capture.py
```

### Terminal 4 — Launch the Streamlit dashboard

```bash
streamlit run dashboard/app.py
```

### Optional: Launch the Next.js SOC dashboard

Terminal 1 - Python FastAPI backend:

```bash
pip install -r requirements.txt
uvicorn api.main:app --reload --port 8000
```

Terminal 2 - Docker containers:

```bash
docker compose -f docker/docker-compose.yml up -d --build
```

Terminal 3 - Next.js frontend:

```bash
cd netguard-dashboard
npm install
npm run dev
```

Open http://localhost:3000.

---

## Demo Script for Interview

> A step-by-step 2-minute walkthrough designed for live technical interviews.

### Minute 0:00 — Baseline: Normal Network

- Dashboard shows **3 normal IoT devices** (smart bulb, thermostat, camera).
- All rows are **green** — no anomalies detected.
- Isolation Forest confidence scores are near 0 (normal).
- Point out: "These are Docker containers simulating real IoT traffic patterns."

### Minute 0:30 — Rogue Device Appears

- A **4th device** appears in the device table — the rogue IoT simulator.
- Its row turns **red** as the Isolation Forest flags it as anomalous.
- Anomaly score jumps above the threshold.
- Point out: "The rogue device is sending unusual packet patterns — high broadcast rate, abnormal DHCP requests."

### Minute 1:00 — AI Explains the Threat

- The **AI confidence score** is displayed next to the rogue device.
- Click to expand the **LLaMA 3 threat explanation** panel.
- LLaMA provides a plain-English analysis: what makes this device suspicious, potential attack vectors, and recommended actions.
- Point out: "This is LLaMA 3 running locally via Ollama — no cloud API needed."

### Minute 1:30 — Auto-Quarantine Triggers

- The system automatically triggers **quarantine** for the rogue device.
- Dashboard shows **VLAN 999** assignment.
- The exact Cisco IOS commands are displayed:
  ```
  enable
  configure terminal
  interface GigabitEthernet0/1
  switchport mode access
  switchport access vlan 999
  shutdown
  end
  ```
- Point out: "In production, Netmiko pushes these to a real switch. Here we simulate it with full command logging."

### Minute 2:00 — Quarantine Log Review

- Scroll to the **Quarantine Log** at the bottom of the dashboard.
- Each entry shows: IP, MAC, timestamp, VLAN, success status, and commands sent.
- Point out: "Full audit trail — every quarantine action is logged with timestamps for compliance."

---

## Project Structure

```
rogue-iot-detector/
│
├── analytics/               # ANALYTICS LAYER
│   ├── __init__.py
│   ├── capture.py           # Live packet capture with Scapy
│   ├── feature_extraction.py# Extract ML features from packets
│   └── train_model.py       # Train Isolation Forest model
│
├── control/                 # CONTROL LAYER
│   ├── __init__.py
│   └── quarantine.py        # Netmiko quarantine + simulation
│
├── dashboard/               # DASHBOARD LAYER
│   ├── __init__.py
│   └── app.py               # Streamlit web UI
│
├── docker/                  # EDGE LAYER
│   ├── docker-compose.yml   # Orchestrate IoT simulators
│   ├── normal_device/       # Normal IoT device simulator
│   │   ├── Dockerfile
│   │   └── simulate.py
│   └── rogue_device/        # Rogue IoT device simulator
│       ├── Dockerfile
│       └── simulate.py
│
├── models/                  # Saved ML models
│   └── isolation_forest.pkl
│
├── data/                    # Captured data and logs
│   └── device_profiles.csv
│
├── requirements.txt         # Python dependencies
└── README.md                # This file
```

---

## AI Components

### Isolation Forest (Anomaly Detection)

The system uses **scikit-learn's Isolation Forest** algorithm for unsupervised anomaly detection. Isolation Forest works by randomly partitioning data — anomalies require fewer partitions to isolate, yielding higher anomaly scores. Features extracted from network traffic include:

- **Packet rate** — packets per second per device
- **Protocol distribution** — ratio of DHCP / ARP / DNS / other traffic
- **Broadcast ratio** — fraction of broadcast vs. unicast packets
- **Payload entropy** — Shannon entropy of packet payloads
- **Request frequency** — rate of DHCP DISCOVER and ARP requests

Devices with anomaly scores above the configured threshold are flagged as rogue.

### LLaMA 3 (Threat Explanation)

Once a device is flagged, its feature profile is sent to **LLaMA 3** running locally via **Ollama**. The model generates a natural-language explanation covering:

- **Why** the device is suspicious (specific anomalous features)
- **What** the potential threat vectors are (e.g., ARP spoofing, DHCP exhaustion)
- **Recommended** response actions

This provides SOC analysts with instant, human-readable context — no manual log analysis required.

---

## License

This project is licensed under the **MIT License**.

```
MIT License

Copyright (c) 2025 Rogue IoT Detector

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.
```
