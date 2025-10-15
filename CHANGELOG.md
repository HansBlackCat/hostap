# CHANGELOG

## 2025-10-15 - Local Testbed Setup and Custom Vendor IE Implementation

### Feature 1: mac80211_hwsim Testbed Infrastructure

**Modified Files:**
- `local_testbed/docker-compose.yml`
- `local_testbed/ap/Dockerfile`
- `local_testbed/client/Dockerfile`
- `local_testbed/capture/Dockerfile`

**Modified Functions/Sections:**
- Docker service definitions: Changed container names to `testbed_ap`, `testbed_sta`, `testbed_capture`
- Network configuration: Changed `network_mode: "none"` for all containers
- Build context: Changed from local directories to parent directory (`context: ..`)
- Volume mounts: Added `/sys/class/ieee80211` and `/sys/kernel/debug` for hwsim access
- Dockerfile build process: Switched from `apt install` to building hostapd/wpa_supplicant from source

**Reason:**
Enable mac80211_hwsim-based wireless testing environment where containers share virtual wireless interfaces without Docker networking conflicts. Building from source allows testing custom modifications to hostapd/wpa_supplicant.

**Result:**
Successfully created isolated testbed with virtual wireless interfaces. Containers can access hwsim PHY devices and establish WPA2-PSK connections.

---

### Feature 2: Interface Assignment and Testing Scripts

**Created Files:**
- `local_testbed/assign-interfaces.sh`
- `local_testbed/test-connection.sh`
- `local_testbed/trigger-handshake.sh`

**Key Functions:**
- `assign-interfaces.sh`: Moves wlan0/wlan1/wlan2 to respective container namespaces using `iw phy`
- `test-connection.sh`: Validates container status, AP broadcasting, STA connection, ping connectivity, and packet capture
- `trigger-handshake.sh`: Forces WPA handshake by disconnecting/reconnecting STA and archiving old captures

**Reason:**
Automate the complex process of assigning virtual wireless interfaces to containers and provide systematic testing and validation of the testbed functionality.

**Result:**
Streamlined testbed operation with automated interface assignment and comprehensive testing. Successfully validates WPA connection and packet capture (excluding EAPOL frames due to hwsim kernel limitation).

---

### Feature 3: Makefile Automation

**Modified Files:**
- `local_testbed/Makefile`

**Added Targets:**
- `make init`: Initializes mac80211_hwsim with 3 radios
- `make start`: Full setup including Docker build, hwsim init, container start, and interface assignment
- `make test`: Runs connection validation tests
- `make trigger-handshake`: Forces new WPA handshake for testing
- `make stop`: Stops all containers
- `make clean`: Removes hwsim module and cleans up

**Reason:**
Provide simple, consistent commands for testbed management instead of requiring manual execution of multiple complex commands.

**Result:**
Reduced testbed setup from multiple manual steps to single `make start` command. Improved developer experience and reduced setup errors.

---

### Feature 4: Startup Script Enhancements

**Modified Files:**
- `local_testbed/ap/scripts/start-ap.sh`
- `local_testbed/client/scripts/start-client.sh`
- `local_testbed/capture/scripts/start-monitor.sh`

**Modified Functions:**
- `start-ap.sh`: Fixed hostapd path from `/usr/local/sbin/hostapd` to `/usr/local/bin/hostapd` (line 42)
- `start-ap.sh`: Added interface waiting logic and better error checking
- `start-client.sh`: Added retry logic for connection attempts
- All scripts: Enhanced logging and error reporting

**Reason:**
**Critical Bug Fix:** hostapd installs to `/usr/local/bin/` not `/usr/local/sbin/`, causing testbed_ap to fail silently. Additional improvements ensure robust startup behavior with proper error handling.

**Result:**
testbed_ap now starts successfully. Improved reliability of all containers with better error detection and automated retries.

---

### Feature 5: Custom Vendor Specific IE Implementation

**Created Files:**
- `wpa_supplicant/vendor_ie_custom.h`
- `wpa_supplicant/vendor_ie_custom.c`

**Created Functions:**
- `build_custom_vendor_ie()`: Builds vendor IE with OUI 0x027a8b, subtype 0xff, data 0xaabb
- `parse_custom_vendor_ie()`: Validates and extracts data from received vendor IEs
- `update_custom_vendor_ie()`: Creates vendor IE with updated 16-bit data value

**Vendor IE Format:**
```
Element ID: 0xDD (Vendor Specific)
Length: 0x07
OUI: 0x02 0x7a 0x8b
OUI Type: 0xff
Data: 0xaa 0xbb (16-bit, big endian)
Padding: 0x00
```

**Reason:**
Implement custom vendor-specific information element as a permanent feature for future protocol extensions and data exchange. Design allows for dynamic data calculations and updates.

**Result:**
Reusable vendor IE framework with build, parse, and update capabilities. Ready for integration into probe and association requests.

---

### Feature 6: Vendor IE Integration into Probe Requests

**Modified Files:**
- `wpa_supplicant/scan.c`

**Modified Functions:**
- `wpa_supplicant_extra_ies()` (around line 820): Added custom vendor IE to probe request IEs

**Code Changes:**
```c
/* Add custom vendor specific IE */
{
    struct wpabuf *custom_ie = build_custom_vendor_ie();
    if (custom_ie) {
        if (wpa_s->drv_max_probe_req_ie_len >= wpabuf_len(custom_ie) &&
            wpabuf_resize(&extra_ie, wpabuf_len(custom_ie)) == 0) {
            wpabuf_put_buf(extra_ie, custom_ie);
            wpa_printf(MSG_DEBUG, "Added custom vendor IE to Probe Request");
        }
        wpabuf_free(custom_ie);
    }
}
```

**Reason:**
Include custom vendor IE in all probe requests to enable AP discovery with vendor-specific information exchange during the scanning phase.

**Result:**
Every probe request frame sent by wpa_supplicant now includes the custom vendor IE with OUI 0x027a8b.

---

### Feature 7: Vendor IE Integration into Association Requests

**Modified Files:**
- `wpa_supplicant/sme.c`

**Modified Functions:**
- `sme_associate()` (around line 2541): Added custom vendor IE to association request IEs

**Code Changes:**
```c
/* Add custom vendor specific IE to Association Request */
{
    struct wpabuf *custom_ie = build_custom_vendor_ie();
    if (custom_ie) {
        size_t custom_ie_len = wpabuf_len(custom_ie);
        if (wpa_s->sme.assoc_req_ie_len + custom_ie_len <=
            sizeof(wpa_s->sme.assoc_req_ie)) {
            os_memcpy(wpa_s->sme.assoc_req_ie + wpa_s->sme.assoc_req_ie_len,
                      wpabuf_head(custom_ie), custom_ie_len);
            wpa_s->sme.assoc_req_ie_len += custom_ie_len;
            wpa_printf(MSG_DEBUG, "Added custom vendor IE to Association Request");
        }
        wpabuf_free(custom_ie);
    }
}
```

**Reason:**
Include custom vendor IE in association requests to enable vendor-specific information exchange during the connection establishment phase.

**Result:**
Every association request frame sent by wpa_supplicant now includes the custom vendor IE with OUI 0x027a8b.

---

### Feature 8: Build System Integration

**Modified Files:**
- `wpa_supplicant/Makefile`

**Modified Sections:**
- Added `OBJS += vendor_ie_custom.o` (line 1798)

**Reason:**
Integrate vendor_ie_custom.c into the wpa_supplicant build process to compile and link the new functionality.

**Result:**
vendor_ie_custom.c successfully compiles and links with wpa_supplicant. Custom vendor IE functionality is now part of the built binary.

---

### Known Limitations

**EAPOL Frame Capture:**
- **Issue:** EAPOL frames (4-way handshake) cannot be captured via tcpdump/monitor interfaces
- **Cause:** mac80211_hwsim processes EAPOL frames internally in kernel space
- **Workaround:** EAPOL handshake completion can be verified through hostapd logs (EAPOL-4WAY-HS-COMPLETED)
- **Impact:** WPA handshake works correctly, but cannot be captured in pcap files for analysis

---
