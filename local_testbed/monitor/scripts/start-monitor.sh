#!/bin/bash
set -e

echo "Starting Monitor/Capture Mode..."

# Wait for interface to be available
echo "Waiting for ${MONITOR_INTERFACE} to be available..."
MAX_WAIT=30
COUNT=0
while ! ip link show ${MONITOR_INTERFACE} &>/dev/null; do
    if [ $COUNT -ge $MAX_WAIT ]; then
        echo "ERROR: Interface ${MONITOR_INTERFACE} not found after ${MAX_WAIT} seconds"
        echo "Available interfaces:"
        ip link show
        exit 1
    fi
    echo "Interface ${MONITOR_INTERFACE} not found, waiting... ($COUNT/$MAX_WAIT)"
    sleep 2
    COUNT=$((COUNT + 1))
done
echo "Interface ${MONITOR_INTERFACE} found!"

# Show interface info
echo "Interface information:"
iw dev ${MONITOR_INTERFACE} info || true
iw phy | grep -A 20 "$(iw dev ${MONITOR_INTERFACE} info | grep wiphy | awk '{print $2}')" || true

# Set monitor mode if not already in monitor mode
CURRENT_TYPE=$(iw dev ${MONITOR_INTERFACE} info | grep "type" | awk '{print $2}')
if [ "$CURRENT_TYPE" != "monitor" ]; then
    echo "Setting ${MONITOR_INTERFACE} to monitor mode..."
    ip link set ${MONITOR_INTERFACE} down
    iw dev ${MONITOR_INTERFACE} set type monitor || {
        echo "Failed to set monitor mode, trying to create new monitor interface..."
        PHY=$(iw dev ${MONITOR_INTERFACE} info | grep wiphy | awk '{print $2}')
        iw phy phy${PHY} interface add mon0 type monitor
        MONITOR_INTERFACE=mon0
    }
fi

# Bring interface up
echo "Bringing ${MONITOR_INTERFACE} up..."
ip link set ${MONITOR_INTERFACE} up

# Set channel
echo "Setting channel to ${CAPTURE_CHANNEL}..."
iw dev ${MONITOR_INTERFACE} set channel ${CAPTURE_CHANNEL}

# Verify configuration
echo "Monitor interface configuration:"
iw dev ${MONITOR_INTERFACE} info

# Start packet capture with focus on EAPOL frames (WPA handshake)
echo "Starting packet capture..."
CAPTURE_FILE="/captures/handshake_capture_$(date +%Y%m%d_%H%M%S).pcap"
echo "Capture file: ${CAPTURE_FILE}"

# Capture all 802.11 frames, focusing on EAPOL for handshake
tcpdump -i ${MONITOR_INTERFACE} \
    -w ${CAPTURE_FILE} \
    -s 0 \
    -U \
    '(type mgt) or (type ctl) or (type data) or (ether proto 0x888e)' &
TCPDUMP_PID=$!

# Monitor capture
trap "kill $TCPDUMP_PID 2>/dev/null" EXIT

echo "Monitor mode active on channel ${CAPTURE_CHANNEL}"
echo "Capturing all traffic including WPA handshakes..."
echo "Press Ctrl+C to stop capture."

# Keep container running and show periodic stats
while true; do
    sleep 30
    echo "=== Capture Status at $(date) ==="
    ls -lh ${CAPTURE_FILE} 2>/dev/null || echo "Capture file not yet created"
    echo "Captured packets: $(tcpdump -r ${CAPTURE_FILE} 2>/dev/null | wc -l)" || true
done