# Dockerfile — live capture agent
# ==============================
# Sniffs packets on the Docker bridge network interface using Scapy
# and writes features to the mounted live_traffic.csv.

FROM python:3.11-slim

LABEL maintainer="rogue-iot-detector"
LABEL description="Live packet capture agent"

# Install scapy (the only runtime dependency)
RUN pip install --no-cache-dir scapy==2.5.0

# Set working directory to /app
WORKDIR /app

# Run the capture agent
CMD ["python", "-u", "analytics/capture.py"]
