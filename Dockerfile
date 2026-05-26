# ─────────────────────────────────────────────────────────
#  ThreatGuard — Production Dockerfile
#  Base: python:3.12-slim (~160MB final image)
# ─────────────────────────────────────────────────────────
FROM python:3.12-slim

WORKDIR /app

# System deps required by ReportLab (PDF export) and WeasyPrint
RUN apt-get update && apt-get install -y --no-install-recommends \
    libfreetype6 \
    libjpeg62-turbo \
    libpango-1.0-0 \
    libpangoft2-1.0-0 \
    curl \
    && rm -rf /var/lib/apt/lists/*

# Install Python dependencies (cached layer — changes only on requirements.txt edit)
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy application source
COPY . .

# Create persistent data directories
RUN mkdir -p /app/data /app/uploads

# Bind to 0.0.0.0 so Docker can route traffic in
ENV HOST=0.0.0.0 \
    PORT=8000 \
    PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1

# Health check — hits /api/health every 30s
HEALTHCHECK --interval=30s --timeout=10s --start-period=15s --retries=3 \
  CMD curl -sf http://localhost:8000/api/health || exit 1

EXPOSE 8000

CMD ["python", "app.py"]
