#!/bin/bash

echo "=== Triggering WPA Handshake ==="
echo ""

# Check current connection
echo "1. Current STA connection status:"
docker exec testbed_sta iw dev wlan0 link
echo ""

# Disconnect STA
echo "2. Disconnecting STA from AP..."
docker exec testbed_sta wpa_cli -i wlan0 disconnect
sleep 2
echo "   Disconnected"
echo ""

# Check disconnection
echo "3. Verifying disconnection:"
docker exec testbed_sta iw dev wlan0 link
echo ""

# Wait a bit
echo "4. Waiting 3 seconds..."
sleep 3
echo ""

# Clear old capture to make analysis easier (optional)
echo "5. Archiving old captures..."
timestamp=$(date +%Y%m%d_%H%M%S)
mkdir -p captures/archive 2>/dev/null
mv captures/*.pcap captures/archive/ 2>/dev/null || true
echo "   Old captures moved to captures/archive/"
echo ""

# Restart capture with new file
echo "6. Restarting capture..."
docker exec testbed_capture pkill tcpdump 2>/dev/null || true
sleep 1

# Start new capture in background
docker exec -d testbed_capture bash -c "
    CAPTURE_FILE=\"/captures/handshake_\$(date +%Y%m%d_%H%M%S).pcap\"
    echo \"Starting capture: \$CAPTURE_FILE\"
    tcpdump -i wlan2 -w \$CAPTURE_FILE -s 0 -U '(type mgt) or (type ctl) or (type data) or (ether proto 0x888e)'
"
sleep 2
echo "   Capture restarted"
echo ""

# Reconnect STA
echo "7. Reconnecting STA to AP..."
docker exec testbed_sta wpa_cli -i wlan0 reconnect
echo ""

# Wait for connection
echo "8. Waiting for connection (up to 15 seconds)..."
for i in {1..15}; do
    if docker exec testbed_sta iw dev wlan0 link 2>/dev/null | grep -q "Connected"; then
        echo "   ✓ Connected after $i seconds!"
        break
    fi
    echo -n "."
    sleep 1
done
echo ""
echo ""

# Check final status
echo "9. Final connection status:"
docker exec testbed_sta iw dev wlan0 link
echo ""

# Wait a bit for packets to be captured
echo "10. Waiting 5 seconds for packets to be written..."
sleep 5
echo ""

# Check capture
echo "11. Checking captured packets:"
if ls captures/*.pcap 1> /dev/null 2>&1; then
    for f in captures/*.pcap; do
        if [ -f "$f" ]; then
            TOTAL=$(tcpdump -r "$f" 2>/dev/null | wc -l)
            EAPOL=$(tcpdump -r "$f" -n 'ether proto 0x888e' 2>/dev/null | wc -l)
            echo "   $(basename $f):"
            echo "     Total packets: $TOTAL"
            echo "     EAPOL frames: $EAPOL"

            if [ "$EAPOL" -ge 4 ]; then
                echo "     ✓ Full 4-way handshake captured!"
            elif [ "$EAPOL" -gt 0 ]; then
                echo "     ⚠ Partial handshake ($EAPOL/4)"
            fi
        fi
    done
else
    echo "   No capture files found"
fi
echo ""

echo "=== Handshake Trigger Complete ==="
echo ""
echo "Analyze the capture with:"
echo "  wireshark captures/*.pcap"
echo "  OR"
echo "  tcpdump -r captures/*.pcap -n 'ether proto 0x888e'"
