#!/bin/bash
set -e

echo "Starting Access Point Setup..."

# Wait for interface to be available
echo "Waiting for ${WIRELESS_INTERFACE} to be available..."
MAX_WAIT=30
COUNT=0
while ! ip link show ${WIRELESS_INTERFACE} &>/dev/null; do
    if [ $COUNT -ge $MAX_WAIT ]; then
        echo "ERROR: Interface ${WIRELESS_INTERFACE} not found after ${MAX_WAIT} seconds"
        echo "Available interfaces:"
        ip link show
        exit 1
    fi
    echo "Interface ${WIRELESS_INTERFACE} not found, waiting... ($COUNT/$MAX_WAIT)"
    sleep 2
    COUNT=$((COUNT + 1))
done
echo "Interface ${WIRELESS_INTERFACE} found!"

# Show interface info
echo "Interface information:"
iw dev ${WIRELESS_INTERFACE} info || true
iw phy | grep -A 20 "$(iw dev ${WIRELESS_INTERFACE} info | grep wiphy | awk '{print $2}')" || true

# Configure wireless interface
echo "Configuring ${WIRELESS_INTERFACE}..."
ip link set ${WIRELESS_INTERFACE} up

# Substitute environment variables in config files
envsubst < /etc/wireless/hostapd.conf > /tmp/hostapd.conf
envsubst < /etc/wireless/dnsmasq.conf > /tmp/dnsmasq.conf

# Show generated config
echo "Generated hostapd configuration:"
cat /tmp/hostapd.conf

# Start services
echo "Starting hostapd..."
/usr/local/bin/hostapd -d -t /tmp/hostapd.conf &
HOSTAPD_PID=$!

sleep 3

# Check if hostapd is running
if ! ps -p $HOSTAPD_PID > /dev/null; then
    echo "ERROR: hostapd failed to start"
    echo "Checking hostapd logs..."
    cat /tmp/hostapd.conf
    exit 1
fi

# Wait for AP to be fully initialized
sleep 2

# Configure IP address after hostapd starts
echo "Configuring IP address..."
ip addr add 192.168.100.1/24 dev ${WIRELESS_INTERFACE} || true

echo "Starting dnsmasq..."
dnsmasq -C /tmp/dnsmasq.conf --no-daemon &
DNSMASQ_PID=$!

# Monitor processes
trap "kill $HOSTAPD_PID $DNSMASQ_PID 2>/dev/null" EXIT

echo "Access Point started successfully"
echo "SSID: ${SSID}"
echo "Channel: ${CHANNEL}"
echo "IP Range: ${IP_RANGE}"
echo "Interface: ${WIRELESS_INTERFACE}"

# Show AP status
echo "Checking AP status..."
iw dev ${WIRELESS_INTERFACE} info

# Keep container running
wait