#!/bin/bash
#set -e

echo "Setting up network namespaces for containers..."

# Auto-detect available PHY devices
echo "Detecting available PHY devices..."
AVAILABLE_PHYS=($(iw dev | grep -o 'phy#[0-9]*' | sort -u | sed 's/phy#//'))

if [ ${#AVAILABLE_PHYS[@]} -lt 3 ]; then
    echo "Error: Need at least 3 PHY devices. Found: ${#AVAILABLE_PHYS[@]}"
    echo "Available PHYs: ${AVAILABLE_PHYS[*]}"
    exit 1
fi

# PHY device configuration (use environment variables or auto-detected values)
CLIENT_PHY=${CLIENT_PHY:-phy${AVAILABLE_PHYS[0]}}
AP_PHY=${AP_PHY:-phy${AVAILABLE_PHYS[1]}}
MONITOR_PHY=${MONITOR_PHY:-phy${AVAILABLE_PHYS[2]}}

echo "Using PHY devices:"
echo "  Client: $CLIENT_PHY"
echo "  AP: $AP_PHY"
echo "  Monitor: $MONITOR_PHY"

# Verify PHY devices exist
for phy in "$CLIENT_PHY" "$AP_PHY" "$MONITOR_PHY"; do
    if ! iw phy "$phy" info >/dev/null 2>&1; then
        echo "Error: PHY device $phy not found"
        exit 1
    fi
done

# Wait for containers to be fully ready and stable
echo "Waiting for containers to stabilize..."
sleep 10

# Wait for containers to be in running state
for container in wireless-client wireless-ap wireless-monitor; do
    while [ "$(docker inspect -f '{{.State.Status}}' $container 2>/dev/null)" != "running" ]; do
        echo "Waiting for $container to be running..."
        sleep 2
    done
done

# Get container PIDs and verify they're stable
echo "Getting container PIDs..."
CLIENT_PID=$(docker inspect -f '{{.State.Pid}}' wireless-client)
AP_PID=$(docker inspect -f '{{.State.Pid}}' wireless-ap)
MONITOR_PID=$(docker inspect -f '{{.State.Pid}}' wireless-monitor)

sleep 5
# Re-check PIDs to ensure stability, if changes detected, echo warning
NEW_CLIENT_PID=$(docker inspect -f '{{.State.Pid}}' wireless-client)
NEW_AP_PID=$(docker inspect -f '{{.State.Pid}}' wireless-ap)
NEW_MONITOR_PID=$(docker inspect -f '{{.State.Pid}}' wireless-monitor)
if [ "$CLIENT_PID" != "$NEW_CLIENT_PID" ] || [ "$AP_PID" != "$NEW_AP_PID" ] || [ "$MONITOR_PID" != "$NEW_MONITOR_PID" ]; then
    echo "Warning: Container PIDs changed during wait. Using new PIDs."
    CLIENT_PID=$NEW_CLIENT_PID
    AP_PID=$NEW_AP_PID
    MONITOR_PID=$NEW_MONITOR_PID
fi

# Verify PIDs are valid
for container_pid in "$CLIENT_PID" "$AP_PID" "$MONITOR_PID"; do
    if [ "$container_pid" = "0" ] || [ -z "$container_pid" ]; then
        echo "Error: Invalid PID detected. Container may not be running properly."
        exit 1
    fi
done

echo "Client PID: $CLIENT_PID"
echo "AP PID: $AP_PID"
echo "Monitor PID: $MONITOR_PID"

# Move PHY devices to container namespaces
echo "Moving $CLIENT_PHY to client container... ($CLIENT_PID)"
sudo iw phy $CLIENT_PHY set netns $CLIENT_PID

echo "Moving $AP_PHY to AP container... ($AP_PID)"
sudo iw phy $AP_PHY set netns $AP_PID

echo "Moving $MONITOR_PHY to monitor container... ($MONITOR_PID)"
sudo iw phy $MONITOR_PHY set netns $MONITOR_PID

echo "Namespace setup complete!"

# Show status
echo "client interfaces:"
docker compose exec client iw dev

echo "access-point interfaces:"
docker compose exec access-point iw dev

echo "monitor interfaces:"
docker compose exec monitor iw dev