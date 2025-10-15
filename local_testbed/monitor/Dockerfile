FROM ubuntu:22.04

ENV DEBIAN_FRONTEND=noninteractive

# Pre-configure Wireshark to allow non-root users to capture packets
RUN echo "wireshark-common wireshark-common/install-setuid boolean true" | debconf-set-selections

RUN apt-get update && apt-get install -y \
    tcpdump \
    tshark \
    wireshark-common \
    aircrack-ng \
    iproute2 \
    iw \
    wireless-tools \
    python3 \
    python3-pip \
    vim \
    gettext-base \
    && apt-get clean \
    && rm -rf /var/lib/apt/lists/*

RUN pip3 install scapy pyshark

RUN mkdir -p /captures /scripts

COPY local_testbed/monitor/scripts/start-monitor.sh /scripts/

RUN chmod +x /scripts/start-monitor.sh

WORKDIR /captures