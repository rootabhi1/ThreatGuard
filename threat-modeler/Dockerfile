FROM python:3.12-slim

WORKDIR /app

# System deps for ReportLab
RUN apt-get update && apt-get install -y --no-install-recommends \
    libfreetype6 libjpeg62-turbo \
    && rm -rf /var/lib/apt/lists/*

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY . .

# In containers we always want to bind 0.0.0.0 so the orchestrator can route to us.
ENV HOST=0.0.0.0 \
    PORT=8000

EXPOSE 8000

CMD ["python", "app.py"]
