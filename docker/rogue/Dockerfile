# Dockerfile — simulated rogue device
# ======================================
# Lightweight Python image with scapy for port scanning and UDP
# flooding on the iot_network Docker bridge.
#
# IMPORTANT: This container requires the NET_ADMIN capability to
# craft raw packets.  The capability is granted in docker-compose.yml
# via `cap_add: [NET_ADMIN]`.

FROM python:3.11-slim

LABEL maintainer="rogue-iot-detector"
LABEL description="Simulated rogue device performing port scans and UDP floods"

# Install scapy (the only runtime dependency)
RUN pip install --no-cache-dir scapy==2.5.0

# Copy the attack script into the container
WORKDIR /app
COPY attack.py .

# Run the attack script on container start
CMD ["python", "-u", "attack.py"]
