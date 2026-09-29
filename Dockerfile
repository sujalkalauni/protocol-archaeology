# Protocol Archaeology Tool - Container Definition
FROM python:3.10-slim

# Install system utilities and libpcap if needed
RUN apt-get update && apt-get install -y --no-install-recommends \
    libpcap-dev \
    tcpdump \
    build-essential \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

# Install Python backend dependencies
COPY backend/requirements.txt /app/requirements.txt
RUN pip install --no-cache-dir -r requirements.txt

# Copy backend codebase
COPY backend/ /app/backend/

# Expose FastAPI default port
EXPOSE 8000

# Set environment
ENV PYTHONUNBUFFERED=1
ENV PYTHONPATH=/app

# Start ASGI Web Server
CMD ["uvicorn", "backend.app:app", "--host", "0.0.0.0", "--port", "8000"]
