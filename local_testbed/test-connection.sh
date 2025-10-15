#!/bin/bash

echo "=== WPA Connection Test ==="
echo ""

# Check if containers are running
echo "1. Checking container status..."
docker ps --filter "name=testbed_" --format "table {{.Names}}\t{{.Status}}"
echo ""

# Wait for services to stabilize
echo "2. Waiting for services to stabilize (10 seconds)..."
sleep 10
echo ""

# Check AP status
echo "3. Checking AP (testbed_ap) status..."
echo "   Interface info:"
docker exec testbed_ap iw dev wlan1 info 2>/dev/null || echo "   ERROR: Cannot get wlan1 info"
echo ""

# Check if AP is broadcasting
echo "4. Checking if AP is broadcasting..."
docker exec testbed_sta iw dev wlan0 scan 2>/dev/null | grep -A 10 "TestbedAP" || echo "   TestbedAP not found in scan"
echo ""

# Check STA connection status
echo "5. Checking STA (testbed_sta) connection status..."
docker exec testbed_sta iw dev wlan0 link 2>/dev/null || echo "   ERROR: Cannot get wlan0 link info"
echo ""

# Check if STA has IP address
echo "6. Checking STA IP address..."
docker exec testbed_sta ip addr show wlan0 2>/dev/null | grep "inet " || echo "   No IP address assigned yet"
echo ""

# Try ping test
echo "7. Testing connectivity (STA -> AP)..."
docker exec testbed_sta ping -c 3 -W 2 192.168.100.1 2>/dev/null && echo "   ✓ Ping successful!" || echo "   ✗ Ping failed"
echo ""

# Check capture status
echo "8. Checking packet capture status..."
if ls captures/*.pcap 1> /dev/null 2>&1; then
    echo "   Capture files found:"
    ls -lh captures/*.pcap
    echo ""

    # Count total packets in all capture files
    TOTAL_PACKETS=0
    for f in captures/*.pcap; do
        if [ -f "$f" ]; then
            COUNT=$(tcpdump -r "$f" 2>/dev/null | wc -l)
            echo "   $(basename $f): $COUNT packets"
            TOTAL_PACKETS=$((TOTAL_PACKETS + COUNT))
        fi
    done
    echo "   Total packets: $TOTAL_PACKETS"
else
    echo "   No capture files yet"
fi
echo ""

# Check for EAPOL frames (handshake)
echo "9. Checking for WPA handshake (EAPOL frames)..."
if ls captures/*.pcap 1> /dev/null 2>&1; then
    TOTAL_EAPOL=0
    for f in captures/*.pcap; do
        if [ -f "$f" ]; then
            EAPOL_COUNT=$(tcpdump -r "$f" -n 'ether proto 0x888e' 2>/dev/null | wc -l)
            if [ "$EAPOL_COUNT" -gt 0 ]; then
                echo "   $(basename $f): $EAPOL_COUNT EAPOL frames"
                TOTAL_EAPOL=$((TOTAL_EAPOL + EAPOL_COUNT))
            fi
        fi
    done

    echo "   Total EAPOL frames: $TOTAL_EAPOL"
    if [ "$TOTAL_EAPOL" -ge 4 ]; then
        echo "   ✓ Full 4-way handshake captured!"
    elif [ "$TOTAL_EAPOL" -gt 0 ]; then
        echo "   ⚠ Partial handshake captured ($TOTAL_EAPOL/4 frames)"
    else
        echo "   ✗ No handshake frames found"
    fi
else
    echo "   No capture files found"
fi
echo ""

echo "=== Test Complete ==="
echo ""
echo "To view logs:"
echo "  make logs-ap       # AP logs"
echo "  make logs-sta      # STA logs"
echo "  make logs-capture  # Capture logs"
echo ""
echo "To analyze captures:"
echo "  make analyze       # Open Wireshark"
