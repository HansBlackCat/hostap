#!/bin/bash
set -e

echo "=== Assigning mac80211_hwsim interfaces to containers ==="

# Function to move interface to container network namespace
move_interface_to_container() {
    local INTERFACE=$1
    local CONTAINER=$2
    local CONTAINER_PID

    echo "Moving ${INTERFACE} to ${CONTAINER}..."

    # Get container PID
    CONTAINER_PID=$(docker inspect -f '{{.State.Pid}}' ${CONTAINER})

    if [ -z "$CONTAINER_PID" ] || [ "$CONTAINER_PID" = "0" ]; then
        echo "ERROR: Container ${CONTAINER} is not running or PID not found"
        return 1
    fi

    # Get PHY number for the interface
    PHY=$(iw dev ${INTERFACE} info | grep wiphy | awk '{print $2}')

    if [ -z "$PHY" ]; then
        echo "ERROR: Could not find PHY for interface ${INTERFACE}"
        return 1
    fi

    echo "  Interface: ${INTERFACE}"
    echo "  PHY: phy${PHY}"
    echo "  Container: ${CONTAINER}"
    echo "  PID: ${CONTAINER_PID}"

    # Move the PHY to container's network namespace
    sudo iw phy phy${PHY} set netns ${CONTAINER_PID}

    echo "  ✓ Successfully moved ${INTERFACE} (phy${PHY}) to ${CONTAINER}"
}

# Wait for containers to be running
echo ""
echo "Waiting for containers to start..."
sleep 5

# Check if containers are running
echo ""
echo "Checking container status..."
docker ps --filter "name=testbed_" --format "table {{.Names}}\t{{.Status}}"

# Move interfaces to containers
echo ""
echo "Assigning interfaces..."

# wlan0 -> testbed_sta
if ip link show wlan0 &>/dev/null; then
    move_interface_to_container "wlan0" "testbed_sta"
else
    echo "WARNING: wlan0 not found"
fi

sleep 2

# wlan1 -> testbed_ap
if ip link show wlan1 &>/dev/null; then
    move_interface_to_container "wlan1" "testbed_ap"
else
    echo "WARNING: wlan1 not found"
fi

sleep 2

# wlan2 -> testbed_capture
if ip link show wlan2 &>/dev/null; then
    move_interface_to_container "wlan2" "testbed_capture"
else
    echo "WARNING: wlan2 not found"
fi

echo ""
echo "=== Interface Assignment Complete ==="
echo ""
echo "Verify assignments with:"
echo "  docker exec testbed_sta ip link"
echo "  docker exec testbed_ap ip link"
echo "  docker exec testbed_capture ip link"
echo ""
echo "Check logs with:"
echo "  docker logs testbed_sta"
echo "  docker logs testbed_ap"
echo "  docker logs testbed_capture"