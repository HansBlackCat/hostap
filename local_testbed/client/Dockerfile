FROM ubuntu:22.04

ENV DEBIAN_FRONTEND=noninteractive

# Pre-configure Wireshark to allow non-root users to capture packets
RUN echo "wireshark-common wireshark-common/install-setuid boolean true" | debconf-set-selections

# Install build dependencies
RUN apt-get update && apt-get install -y \
    build-essential \
    pkg-config \
    libnl-3-dev \
    libnl-genl-3-dev \
    libnl-route-3-dev \
    libssl-dev \
    libdbus-1-dev \
    iproute2 \
    iw \
    wireless-tools \
    net-tools \
    iputils-ping \
    curl \
    wget \
    tcpdump \
    tshark \
    isc-dhcp-client \
    dnsutils \
    python3 \
    python3-pip \
    vim \
    gettext-base \
    git \
    && apt-get clean \
    && rm -rf /var/lib/apt/lists/*

RUN pip3 install requests scapy

# Copy hostap source code from parent directory
COPY . /hostap_build/

# Build and install wpa_supplicant from source
WORKDIR /hostap_build/wpa_supplicant
RUN cp defconfig .config && \
    make -j$(nproc) && \
    make install

RUN mkdir -p /etc/wireless /captures /scripts

COPY local_testbed/client/config/wpa_supplicant.conf /etc/wireless/
COPY local_testbed/client/scripts/start-client.sh /scripts/

RUN chmod +x /scripts/start-client.sh

WORKDIR /captures