# Dockerfile — simulated smart bulb
# ====================================
# Lightweight Python image with scapy for crafting HTTP-like UDP
# status pings on the iot_network Docker bridge.

FROM python:3.11-slim

LABEL maintainer="rogue-iot-detector"
LABEL description="Simulated smart bulb generating HTTP-like UDP pings"

# Install scapy (the only runtime dependency)
RUN pip install --no-cache-dir scapy==2.5.0

# Copy the traffic generator into the container
WORKDIR /app
COPY traffic.py .

# Run the traffic generator on container start
CMD ["python", "-u", "traffic.py"]
