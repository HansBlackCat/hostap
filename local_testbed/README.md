# WPA Testbed with mac80211_hwsim

This testbed creates a virtualized wireless environment using mac80211_hwsim to test WPA connections and capture handshakes.

## Architecture

The testbed consists of three Docker containers connected via mac80211_hwsim virtual wireless interfaces:

- **testbed_sta** (wlan0): Wireless station (client) that connects to the AP
- **testbed_ap** (wlan1): Wireless Access Point using WPA2-PSK
- **testbed_capture** (wlan2): Monitor mode interface that captures all wireless traffic including handshakes

All containers use **hostapd** and **wpa_supplicant** built from source (`make install`) from the hostap repository, not from apt packages.

## Prerequisites

- Linux system with kernel support for mac80211_hwsim
- Docker and Docker Compose
- Root/sudo access (required for loading kernel modules)
- Build dependencies installed on host (for Docker builds)

## Quick Start

```bash
# Initialize and start the testbed
cd local_testbed
make start

# Monitor logs (shows connection progress)
make logs

# Check status
make status

# View captured packets
make analyze  # Opens Wireshark

# Stop testbed
make stop

# Complete cleanup
make clean
```

## Step-by-Step Setup

### 1. Initialize mac80211_hwsim

```bash
make init
```

This loads the mac80211_hwsim kernel module with 3 virtual radios and creates wlan0, wlan1, wlan2 interfaces.

### 2. Build Docker Images

```bash
make build
```

Builds three Docker images from source:
- Copies the entire hostap repository into each container
- Builds hostapd and wpa_supplicant from source
- Installs binaries to /usr/local/bin

### 3. Start Containers and Assign Interfaces

```bash
make start
```

This:
1. Runs `make init` and `make build`
2. Starts all three containers with `network_mode: "none"`
3. Assigns hwsim interfaces to container namespaces:
   - wlan0 → testbed_sta
   - wlan1 → testbed_ap
   - wlan2 → testbed_capture

### 4. Monitor Operation

```bash
# All logs
make logs

# Individual container logs
make logs-sta
make logs-ap
make logs-capture

# Status check
make status
```

### 5. Access Containers

```bash
# Open shell in containers
make shell-sta
make shell-ap
make shell-capture
```

### 6. Analyze Captures

```bash
# Show capture file info
make capture-status

# Open Wireshark
make analyze
```

## Network Configuration

### Access Point (testbed_ap)
- **SSID**: TestbedAP
- **Password**: testbed2024
- **Channel**: 6
- **Security**: WPA2-PSK with CCMP
- **IP**: 192.168.100.1/24
- **DHCP Range**: 192.168.100.10-100

### Station (testbed_sta)
- **Interface**: wlan0
- **Connects to**: TestbedAP
- **IP**: Assigned via DHCP (or static 192.168.100.50)

### Capture (testbed_capture)
- **Interface**: wlan2 (monitor mode)
- **Channel**: 6 (matches AP)
- **Captures**: All 802.11 frames + EAPOL (handshakes)
- **Output**: `/captures/handshake_capture_*.pcap`

## Capture Analysis

The monitor interface captures:
- **Management frames**: Beacons, probe requests/responses, authentication, association
- **Control frames**: ACK, RTS/CTS
- **Data frames**: Including encrypted data
- **EAPOL frames**: WPA 4-way handshake (critical for analysis)

### Viewing Handshakes in Wireshark

1. Open capture: `make analyze`
2. Filter for EAPOL: `eapol`
3. Look for 4-way handshake frames:
   - Message 1: AP → STA (ANonce)
   - Message 2: STA → AP (SNonce)
   - Message 3: AP → STA (GTK)
   - Message 4: STA → AP (ACK)

## Configuration Files

### AP Configuration
- `ap/config/hostapd.conf`: hostapd configuration template
- Environment variables substituted at runtime:
  - `${WIRELESS_INTERFACE}`: wlan1
  - `${SSID}`: TestbedAP
  - `${PASSPHRASE}`: testbed2024
  - `${CHANNEL}`: 6

### STA Configuration
- `client/config/wpa_supplicant.conf`: wpa_supplicant configuration template
- Environment variables:
  - `${AP_SSID}`: TestbedAP
  - `${AP_PASSWORD}`: testbed2024

## Troubleshooting

### Containers fail to start
```bash
# Check if mac80211_hwsim is loaded
lsmod | grep mac80211_hwsim

# Reinitialize
make stop
make start
```

### Interfaces not assigned
```bash
# Check available interfaces on host before assignment
iw dev

# Manually run interface assignment
./assign-interfaces.sh
```

### STA not connecting to AP
```bash
# Check AP status
make shell-ap
iw dev wlan1 info

# Check STA logs
make logs-sta

# Check if interfaces can see each other (hwsim should allow this)
make shell-sta
iw dev wlan0 scan
```

### No handshake captured
```bash
# Verify monitor is on correct channel
make shell-capture
iw dev wlan2 info

# Check if capture is running
make capture-status

# Restart to trigger new handshake
make restart
```

## Makefile Commands Reference

| Command | Description |
|---------|-------------|
| `make help` | Show all available commands |
| `make init` | Initialize mac80211_hwsim module |
| `make build` | Build Docker images from source |
| `make start` | Full setup (init + build + start + assign) |
| `make stop` | Stop containers and remove hwsim |
| `make clean` | Complete cleanup |
| `make restart` | Stop and start |
| `make logs` | Show all logs (follow mode) |
| `make logs-sta` | Show STA logs only |
| `make logs-ap` | Show AP logs only |
| `make logs-capture` | Show capture logs only |
| `make shell-sta` | Open shell in STA container |
| `make shell-ap` | Open shell in AP container |
| `make shell-capture` | Open shell in capture container |
| `make status` | Show system status |
| `make capture-status` | Show capture files and packet counts |
| `make analyze` | Open Wireshark with captures |
| `make test-connection` | Test STA to AP connectivity |

## Technical Details

### Why network_mode: "none"?

Containers use `network_mode: "none"` because they receive their networking entirely through the assigned hwsim wireless interfaces. They don't need traditional Docker networking.

### How Interface Assignment Works

The `assign-interfaces.sh` script:
1. Gets each container's PID
2. Identifies the PHY (physical layer) for each wlan interface
3. Uses `iw phy phyX set netns <PID>` to move the PHY into the container's network namespace
4. The interface then appears inside the container and disappears from the host

### Why Build from Source?

Building from source ensures:
- Latest code changes are included (vendor-specific extensions, custom features)
- Consistent versions between testbed and development
- Full control over build configuration
- No dependency on distro package versions

## Files Structure

```
local_testbed/
├── docker-compose.yml          # Container definitions
├── init-hwsim.sh              # Initialize mac80211_hwsim
├── assign-interfaces.sh       # Assign interfaces to containers
├── Makefile                   # Management commands
├── README.md                  # This file
├── ap/
│   ├── Dockerfile            # AP image (builds hostapd)
│   ├── config/
│   │   ├── hostapd.conf     # hostapd configuration
│   │   └── dnsmasq.conf     # DHCP server config
│   └── scripts/
│       └── start-ap.sh      # AP startup script
├── client/
│   ├── Dockerfile           # STA image (builds wpa_supplicant)
│   ├── config/
│   │   └── wpa_supplicant.conf  # wpa_supplicant config
│   └── scripts/
│       └── start-client.sh  # STA startup script
├── monitor/
│   ├── Dockerfile           # Monitor image
│   └── scripts/
│       └── start-monitor.sh # Monitor startup script
└── captures/                 # Packet captures (created at runtime)
```

## Development Workflow

1. Make changes to hostap source code in parent directory
2. Rebuild containers: `make build`
3. Restart testbed: `make restart`
4. Test changes with: `make logs` and `make status`
5. Analyze captured packets: `make analyze`

## Security Notes

- This is a **testing environment only**
- Default credentials are intentionally simple (testbed2024)
- All traffic is virtualized within mac80211_hwsim
- No actual wireless hardware is used
- Captures contain full handshakes and can be used for educational security analysis