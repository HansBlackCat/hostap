FROM ubuntu:22.04

ENV DEBIAN_FRONTEND=noninteractive

RUN echo "wireshark-common wireshark-common/install-setuid boolean true" | debconf-set-selections || true

# Install build dependencies
RUN apt-get update && apt-get install -y \
    build-essential \
    pkg-config \
    libnl-3-dev \
    libnl-genl-3-dev \
    libnl-route-3-dev \
    libssl-dev \
    libdbus-1-dev \
    dnsmasq \
    iptables \
    iproute2 \
    iw \
    wireless-tools \
    net-tools \
    bridge-utils \
    tcpdump \
    tshark \
    vim \
    iputils-ping \
    procps \
    kmod \
    gettext-base \
    git \
    && apt-get clean \
    && rm -rf /var/lib/apt/lists/*

# Copy hostap source code from parent directory
COPY . /hostap_build/

# Build and install hostapd from source
WORKDIR /hostap_build/hostapd
RUN cp defconfig .config && \
    make -j$(nproc) && \
    make install

RUN mkdir -p /etc/wireless /captures /scripts

COPY local_testbed/ap/config/hostapd.conf /etc/wireless/
COPY local_testbed/ap/config/dnsmasq.conf /etc/wireless/
COPY local_testbed/ap/scripts/start-ap.sh /scripts/

RUN chmod +x /scripts/start-ap.sh

WORKDIR /captures