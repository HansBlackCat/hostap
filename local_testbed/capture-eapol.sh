#!/bin/bash

echo "=== Advanced EAPOL Capture Test ==="
echo ""

# Archive old captures
echo "1. Archiving old captures..."
mkdir -p captures/archive
mv captures/*.pcap captures/archive/ 2>/dev/null || true
echo ""

# Method 1: Capture on STA interface directly with all traffic
echo "2. Starting capture on STA (wlan0) - ALL traffic..."
docker exec -d testbed_sta bash -c "
    tcpdump -i wlan0 -w /captures/sta_all_$(date +%Y%m%d_%H%M%S).pcap -s 0 -n
"
sleep 1

# Method 2: Capture on AP interface directly with all traffic
echo "3. Starting capture on AP (wlan1) - ALL traffic..."
docker exec -d testbed_ap bash -c "
    tcpdump -i wlan1 -w /captures/ap_all_$(date +%Y%m%d_%H%M%S).pcap -s 0 -n
"
sleep 1

# Method 3: Capture on monitor with NO filter
echo "4. Starting capture on Monitor (wlan2) - ALL traffic..."
docker exec testbed_capture pkill tcpdump 2>/dev/null || true
sleep 1
docker exec -d testbed_capture bash -c "
    tcpdump -i wlan2 -w /captures/monitor_all_$(date +%Y%m%d_%H%M%S).pcap -s 0 -n
"
sleep 1

echo "5. All captures started. Waiting 3 seconds..."
sleep 3
echo ""

# Trigger reconnection
echo "6. Disconnecting STA..."
docker exec testbed_sta wpa_cli -i wlan0 disconnect
sleep 3
echo ""

echo "7. Reconnecting STA (handshake should occur now)..."
docker exec testbed_sta wpa_cli -i wlan0 reconnect
sleep 15
echo ""

# Stop all captures
echo "8. Stopping all captures..."
docker exec testbed_sta pkill tcpdump 2>/dev/null || true
docker exec testbed_ap pkill tcpdump 2>/dev/null || true
docker exec testbed_capture pkill tcpdump 2>/dev/null || true
sleep 2
echo ""

# Analyze captures
echo "9. Analyzing captured files..."
echo ""

for f in captures/*.pcap; do
    if [ -f "$f" ]; then
        echo "=== $(basename $f) ==="

        # Total packets
        TOTAL=$(tcpdump -r "$f" 2>/dev/null | wc -l)
        echo "  Total packets: $TOTAL"

        # EAPOL frames (802.1X)
        EAPOL=$(tcpdump -r "$f" -n 'ether proto 0x888e' 2>/dev/null | wc -l)
        echo "  EAPOL (0x888e): $EAPOL"

        # Show first few EAPOL if found
        if [ "$EAPOL" -gt 0 ]; then
            echo "  EAPOL frames:"
            tcpdump -r "$f" -n -v 'ether proto 0x888e' 2>/dev/null | head -20
        fi

        echo ""
    fi
done

echo "=== Analysis Complete ==="
echo ""
echo "If EAPOL frames are still not captured, this is a limitation of mac80211_hwsim"
echo "where EAPOL frames are processed internally by the kernel and not exposed"
echo "to packet capture interfaces."
echo ""
echo "However, you can verify the handshake occurred by checking logs:"
echo "  docker logs testbed_ap | grep EAPOL-4WAY-HS-COMPLETED"
