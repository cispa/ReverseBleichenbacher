FROM python:3.11-slim

# Install dependencies for robot-detect
RUN apt-get update && apt-get install -y \
    gcc \
    make \
    git \
    libgmp-dev \
    libmpfr-dev \
    libmpc-dev \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

# Clone robot-detect at pinned commit (no tags published upstream)
# ARG ROBOT_DETECT_COMMIT=60fcbd4f7437c6e59357ee56528a8a067fa6d3c7
# RUN git clone https://github.com/robotattackorg/robot-detect.git && \
#     cd robot-detect && \
#     git checkout "${ROBOT_DETECT_COMMIT}" && \
#     chmod +x robot-detect

# Install Python dependencies from requirements file
COPY requirements.txt /app/requirements.txt
RUN pip install --no-cache-dir -r /app/requirements.txt

# Copy robot-detect code
COPY robot-detect /app/robot-detect/robot-detect
COPY robot-detect-fast.py /app/robot-detect/robot-detect-fast.py
RUN chmod +x /app/robot-detect/robot-detect
RUN chmod +x /app/robot-detect/robot-detect-fast.py

# Copy worker script
COPY worker.py /app/worker.py
RUN chmod +x /app/worker.py

WORKDIR /app/robot-detect

CMD ["python3", "/app/worker.py"]
