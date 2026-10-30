FROM golang:1.24-alpine AS zgrab-builder

RUN apk add --no-cache git make gcc musl-dev

WORKDIR /build
ARG ZGRAB2_TAG=v0.2.0
RUN git clone https://github.com/zmap/zgrab2.git && \
    cd zgrab2 && \
    git checkout "${ZGRAB2_TAG}"
WORKDIR /build/zgrab2
RUN make

FROM python:3.11-alpine

RUN apk add --no-cache bash zmap ca-certificates

RUN mkdir -p /root/.config/zgrab2

WORKDIR /app

COPY requirements.txt /app/requirements.txt
RUN pip install --no-cache-dir -r /app/requirements.txt

COPY --from=zgrab-builder /build/zgrab2/cmd/zgrab2/zgrab2 /usr/local/bin/zgrab2
COPY --from=zgrab-builder /build/zgrab2/conf/blocklist.conf /root/.config/zgrab2/blocklist.conf
COPY worker.py /app/worker.py

CMD ["python", "/app/worker.py"]
