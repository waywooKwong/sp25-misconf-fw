FROM debian:stable-slim

ENV DEBIAN_FRONTEND=noninteractive \
    PIP_DISABLE_PIP_VERSION_CHECK=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1

RUN apt-get update -y && \
    apt-get install -y --no-install-recommends \
        python3 python3-pip python3-venv ca-certificates curl \
        zmap zgrab2 jq iproute2 && \
    rm -rf /var/lib/apt/lists/*

WORKDIR /app

COPY requirements.txt /app/requirements.txt
RUN pip3 install --no-cache-dir -r requirements.txt

COPY . /app

# 以 root 运行（ZMap 需要原始套接字能力）。请在 docker run 时仅添加最小必要能力。

ENTRYPOINT ["python3", "pipeline.py"] 