#!/bin/bash
set -e

echo "=== Initializing mac80211_hwsim ==="

# Remove module if already loaded
echo "Removing existing mac80211_hwsim module..."
sudo modprobe -r mac80211_hwsim 2>/dev/null || true
sleep 2

# Load with 3 radios (STA, AP, Monitor)
echo "Loading mac80211_hwsim with 3 radios..."
sudo modprobe mac80211_hwsim radios=3

# Wait for interfaces to be created
sleep 2

# Show created interfaces
echo ""
echo "=== Created Virtual Wireless Interfaces ==="
iw dev

echo ""
echo "=== Virtual PHY Devices ==="
ls -la /sys/class/ieee80211/

echo ""
echo "=== Interface Assignment Plan ==="
echo "wlan0 -> testbed_sta (STA client)"
echo "wlan1 -> testbed_ap (Access Point)"
echo "wlan2 -> testbed_capture (Monitor/Capture)"

echo ""
echo "mac80211_hwsim initialization complete!"
echo "You can now start the containers with: cd local_testbed && docker compose up -d"