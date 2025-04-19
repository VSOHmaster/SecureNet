FROM python:3.9-slim

RUN apt-get update && apt-get install -y --no-install-recommends \
    libpcap-dev \
    tcpdump \
 && rm -rf /var/lib/apt/lists/*

WORKDIR /app/agent

COPY agent/requirements.txt .
RUN pip install --no-cache-dir --upgrade pip && \
    pip install --no-cache-dir -r requirements.txt

COPY agent/ /app/agent/

ENTRYPOINT ["python", "scapy_agent.py"]
CMD ["YOUR_API_KEY_HERE", "http://localhost:8000", "192.168.1.0/24"]
