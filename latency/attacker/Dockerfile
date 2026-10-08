FROM ubuntu:noble-20250404
RUN apt-get update && apt-get install -y \
    curl \
    iptables \
    tcpdump \
    unzip \
    zip \
    bsdmainutils \
    bind9-host \
    python3 \
    python3-venv \
    python3-gmpy2 \
    git \
    && rm -rf /var/lib/apt/lists/*

RUN curl -LsSf https://astral.sh/uv/install.sh | sh

# Setup venv
ENV PATH="/root/.local/bin:$PATH"
ENV VENV=/opt/venv
RUN python3 -m venv ${VENV} --system-site-packages
ENV PATH="$VENV/bin:$PATH"

RUN uv pip install -U setuptools wheel
RUN uv pip install cryptography pycryptodome==3.23.0 ipython tqdm==4.67.1 pyshark numpy gmpy2 ecdsa>=0.18.0b1 

# # Keep the container running
WORKDIR /attacker/
EXPOSE 443 
CMD ["bash", "/attacker/start.sh"]
