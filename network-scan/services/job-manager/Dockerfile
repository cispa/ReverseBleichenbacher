FROM python:3.11-alpine

WORKDIR /app

COPY requirements.txt /app/requirements.txt
RUN pip install --no-cache-dir -r /app/requirements.txt

COPY job_manager.py /app/job_manager.py

CMD ["python", "/app/job_manager.py"]
