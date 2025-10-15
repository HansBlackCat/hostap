#!/bin/bash
set -e

echo "Starting Wireless Client..."

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

# Show interface state
echo "Interface state after configuration:"
ip link show ${WIRELESS_INTERFACE}
ip addr show ${WIRELESS_INTERFACE}

# Substitute environment variables in wpa_supplicant config
envsubst < /etc/wireless/wpa_supplicant.conf > /tmp/wpa_supplicant.conf

# Show generated config
echo "Generated wpa_supplicant configuration:"
cat /tmp/wpa_supplicant.conf

# Start wpa_supplicant
echo "Connecting to AP: ${AP_SSID}..."
/usr/local/sbin/wpa_supplicant -B -i ${WIRELESS_INTERFACE} -c /tmp/wpa_supplicant.conf -D nl80211 -dd

# Wait for connection
echo "Waiting for wireless connection..."
MAX_CONN_WAIT=30
CONN_COUNT=0
while [ $CONN_COUNT -lt $MAX_CONN_WAIT ]; do
    if iw ${WIRELESS_INTERFACE} link | grep -q "Connected"; then
        echo "Wireless connection established!"
        break
    fi
    echo "Not connected yet, waiting... ($CONN_COUNT/$MAX_CONN_WAIT)"
    sleep 2
    CONN_COUNT=$((CONN_COUNT + 1))
done

# Show connection status
echo "Connection status:"
iw ${WIRELESS_INTERFACE} link

# Request IP via DHCP
if iw ${WIRELESS_INTERFACE} link | grep -q "Connected"; then
    echo "Requesting IP via DHCP..."
    dhclient -v ${WIRELESS_INTERFACE} || {
        echo "DHCP failed, setting static IP..."
        ip addr add 192.168.100.50/24 dev ${WIRELESS_INTERFACE}
        ip route add default via 192.168.100.1
        echo "nameserver 8.8.8.8" > /etc/resolv.conf
    }
else
    echo "Connection not established, setting static IP..."
    ip addr add 192.168.100.50/24 dev ${WIRELESS_INTERFACE}
    ip route add default via 192.168.100.1
    echo "nameserver 8.8.8.8" > /etc/resolv.conf
fi

# Show final configuration
echo "Final network configuration:"
ip addr show ${WIRELESS_INTERFACE}
ip route show

# Test connectivity
echo "Testing connectivity to AP..."
ping -c 4 -W 2 192.168.100.1 || echo "Unable to reach AP"

# Keep container running
echo "Client is running. Press Ctrl+C to stop."
tail -f /dev/null