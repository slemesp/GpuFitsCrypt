ARG CUDA_VERSION=12.0.1
ARG OS_VERSION=ubuntu22.04
FROM nvidia/cuda:${CUDA_VERSION}-devel-${OS_VERSION}

LABEL maintainer="samuel@lightbridges.es"
LABEL description="Benchmark and reproducibility environment for GpuFitsCrypt"

ENV DEBIAN_FRONTEND=noninteractive

# Install system dependencies
RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential g++ make git wget libcfitsio-dev python3 python3-pip python3-venv sudo \
    && rm -rf /var/lib/apt/lists/*

COPY requirements.txt /tmp/requirements.txt
RUN python3 -m pip install --no-cache-dir -r /tmp/requirements.txt tabulate pynvml nvtx

# --- User Management for Permission Fix ---
ARG USER_ID=1000
ARG GROUP_ID=1000

RUN groupadd -g ${GROUP_ID} appuser && \
    useradd -m -u ${USER_ID} -g appuser -s /bin/bash appuser && \
    echo "appuser ALL=(ALL) NOPASSWD:ALL" >> /etc/sudoers

# Create working directory and set permissions
WORKDIR /app/src
RUN chown -R appuser:appuser /app

# Switch to non-root user
USER appuser

# Env vars
ENV LD_LIBRARY_PATH=/app/src:${LD_LIBRARY_PATH}
ENV PATH="/home/appuser/.local/bin:${PATH}"

# Default entrypoint
ENTRYPOINT ["python3", "reproducibility/benchmarks/main_runner.py"]
