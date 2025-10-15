# CHANGELOG

## 2025-10-15 - Local Testbed Setup and Custom Vendor IE Implementation
### Feature 1: Custom Vendor Specific IE Implementation

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

### Feature 2: Vendor IE Integration into Probe Requests

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

### Feature 3: Vendor IE Integration into Association Requests

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

### Feature 4: Build System Integration

**Modified Files:**
- `wpa_supplicant/Makefile`

**Modified Sections:**
- Added `OBJS += vendor_ie_custom.o` (line 1798)

**Reason:**
Integrate vendor_ie_custom.c into the wpa_supplicant build process to compile and link the new functionality.

**Result:**
vendor_ie_custom.c successfully compiles and links with wpa_supplicant. Custom vendor IE functionality is now part of the built binary.

---
