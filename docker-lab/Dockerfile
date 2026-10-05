FROM ubuntu:22.04

ENV DEBIAN_FRONTEND=noninteractive

RUN apt-get update && apt-get install -y --no-install-recommends \
    nmap \
    hping3 \
    hydra \
    dnsutils \
    netcat-openbsd \
    iputils-ping \
    curl \
    wget \
    net-tools \
    iproute2 \
    arping \
    tcpdump \
    python3 \
    python3-pip \
    && rm -rf /var/lib/apt/lists/*

RUN pip3 install requests --break-system-packages

WORKDIR /lab

COPY attack_simulator.sh /lab/attack_simulator.sh
RUN chmod +x /lab/attack_simulator.sh

CMD ["bash"]
