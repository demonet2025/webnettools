# NetHub Webnettools - Python Version
FROM python:3.11-slim

# Install system dependencies
RUN apt-get update && apt-get install -y \
    curl \
    dnsutils \
    iputils-ping \
    traceroute \
    nmap \
    mtr-tiny \
    testssl.sh \
    && rm -rf /var/lib/apt/lists/*

# Set working directory
WORKDIR /app

# Copy requirements and install Python dependencies
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy application files
COPY app.py .
# COPY app_new.py .
COPY routes/ routes/
COPY modules/ modules/
COPY templates/ templates/
COPY static/ static/

# Create static directory if it doesn't exist
RUN mkdir -p static

# Expose port
EXPOSE 8080

# Health check
HEALTHCHECK --interval=30s --timeout=10s --start-period=5s --retries=3 \
    CMD curl -f http://localhost:8080/ || exit 1

# Run the application
CMD ["python", "app.py"]
