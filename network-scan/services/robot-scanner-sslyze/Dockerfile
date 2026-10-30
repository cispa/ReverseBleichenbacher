FROM python:3.11-slim

WORKDIR /app

# Install dependencies
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy worker
COPY worker.py .
RUN chmod +x worker.py

CMD ["python", "/app/worker.py"]
