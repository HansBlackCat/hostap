#!/bin/bash

echo "=== Python EAPOL Capture Test ==="
echo ""

# Copy Python script to containers
echo "1. Copying EAPOL capture script to containers..."
docker cp eapol_capture.py testbed_sta:/tmp/
docker cp eapol_capture.py testbed_ap:/tmp/
echo ""

# Start captures in background
echo "2. Starting EAPOL capture on STA (wlan0)..."
docker exec -d testbed_sta python3 /tmp/eapol_capture.py wlan0 > captures/sta_eapol_log.txt 2>&1 &
STA_PID=$!
sleep 1

echo "3. Starting EAPOL capture on AP (wlan1)..."
docker exec -d testbed_ap python3 /tmp/eapol_capture.py wlan1 > captures/ap_eapol_log.txt 2>&1 &
AP_PID=$!
sleep 2

echo "4. Captures started. Waiting 3 seconds..."
sleep 3
echo ""

# Trigger handshake
echo "5. Triggering handshake - Disconnecting STA..."
docker exec testbed_sta wpa_cli -i wlan0 disconnect
sleep 3
echo ""

echo "6. Reconnecting STA (handshake should occur now)..."
docker exec testbed_sta wpa_cli -i wlan0 reconnect
echo ""

echo "7. Waiting 20 seconds for handshake to complete..."
sleep 20
echo ""

# Stop captures
echo "8. Stopping captures..."
docker exec testbed_sta pkill -f eapol_capture.py 2>/dev/null || true
docker exec testbed_ap pkill -f eapol_capture.py 2>/dev/null || true
sleep 2
echo ""

# Show results
echo "9. Results from STA capture:"
echo "========================================="
cat captures/sta_eapol_log.txt 2>/dev/null || echo "No output from STA"
echo ""

echo "10. Results from AP capture:"
echo "========================================="
cat captures/ap_eapol_log.txt 2>/dev/null || echo "No output from AP"
echo ""

echo "=== Capture Complete ==="
echo ""
echo "If EAPOL frames were captured, they should be shown above."
echo "If not, EAPOL frames are being processed entirely within the kernel"
echo "and not exposed to userspace capture tools in mac80211_hwsim."
