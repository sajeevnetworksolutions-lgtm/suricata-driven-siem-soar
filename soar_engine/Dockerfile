FROM python:3.11-slim

WORKDIR /app

# Install system dependencies including iptables, iproute2, e2fsprogs (chattr), and curl
RUN apt-get update && apt-get install -y --no-install-recommends \
    curl \
    iptables \
    iproute2 \
    e2fsprogs \
    && rm -rf /var/lib/apt/lists/*

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY . .

EXPOSE 8000

CMD ["python", "app.py"]
