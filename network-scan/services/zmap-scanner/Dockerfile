FROM python:3.11-alpine

RUN apk add --no-cache bash zmap ca-certificates

WORKDIR /app

COPY requirements.txt /app/requirements.txt
RUN pip install --no-cache-dir -r /app/requirements.txt

COPY entrypoint.sh push_to_redis.py /app/

RUN chmod +x /app/entrypoint.sh /app/push_to_redis.py

ENTRYPOINT ["/app/entrypoint.sh"]
