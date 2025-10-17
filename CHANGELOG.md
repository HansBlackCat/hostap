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

### Feature 5: AP-Side Vendor IE Parsing and Storage

**Modified Files:**
- `src/ap/ieee802_11.c`

**Modified Functions:**
- `__check_assoc_ies()` (lines 4770-4804): Added custom vendor IE parsing from Association Request

**Code Changes:**
```c
#ifdef CUSTOM_RK
	/* Parse custom vendor specific IE from Association Request */
	if (sta->wpa_sm && !link) {
		const u8 *custom_ie;
		u32 vendor_type = 0x027a8bff;  /* OUI: 0x027a8b, Type: 0xff */

		custom_ie = get_vendor_ie(ies, ies_len, vendor_type);
		if (custom_ie) {
			u8 ie_len = custom_ie[1];
			if (ie_len >= 5) {  /* At least OUI(3) + Type(1) + Data(1) */
				const u8 *data = custom_ie + 2 + 4;
				size_t data_len = ie_len - 4;

				/* Store the payload in wpa_state_machine */
				if (data_len <= WPA_CLIENT_HASH_SECRET) {
					os_memcpy(sta->wpa_sm->client_hash_secret, data, data_len);
					sta->wpa_sm->client_hash_secret_len = data_len;
					wpa_printf(MSG_DEBUG, "Custom Vendor IE: Stored %zu bytes from " MACSTR,
						   data_len, MAC2STR(sta->addr));
					wpa_hexdump(MSG_DEBUG, "Custom Vendor IE payload",
						    sta->wpa_sm->client_hash_secret,
						    sta->wpa_sm->client_hash_secret_len);
				}
			}
		}
	}
#endif /* CUSTOM_RK */
```

**Reason:**
Extract custom vendor IE payload from client Association Requests and store it in the wpa_state_machine for use in future protocol calculations. Enables AP to receive and process client-specific data sent in vendor IE (OUI 0x027a8b, Type 0xff).

**Result:**
AP successfully parses Association Request vendor IEs and stores payload in `wpa_state_machine->client_hash_secret`. Debug logs confirm payload reception with hexdump output. Completes bidirectional custom vendor IE exchange between STA and AP.

---

### Feature 6: AP Custom Vendor IE in Association Response

**Modified Files:**
- `src/ap/ieee802_11.c`

**Modified Functions:**
- `send_assoc_resp()` (lines 5541-5566): Added custom vendor IE to Association Response

**Code Changes:**
```c
#ifdef CUSTOM_RK
	/* Add custom vendor specific IE to Association Response */
	if (sta && sta->wpa_sm && status_code == WLAN_STATUS_SUCCESS &&
	    sta->wpa_sm->client_hash_secret_len > 0) {
		size_t vendor_ie_len = 2 + 4 + sta->wpa_sm->client_hash_secret_len;

		if ((size_t)(buf + buflen - p) >= vendor_ie_len) {
			*p++ = WLAN_EID_VENDOR_SPECIFIC;  /* 0xDD */
			*p++ = 4 + sta->wpa_sm->client_hash_secret_len;  /* OUI(3) + Type(1) + Data */
			*p++ = 0x02; *p++ = 0x7a; *p++ = 0x8b;  /* OUI: 0x027a8b */
			*p++ = 0xff;  /* Type */
			os_memcpy(p, sta->wpa_sm->client_hash_secret, sta->wpa_sm->client_hash_secret_len);
			p += sta->wpa_sm->client_hash_secret_len;
			wpa_printf(MSG_DEBUG, "Custom Vendor IE: Added %zu bytes to Association Response for " MACSTR,
				   sta->wpa_sm->client_hash_secret_len, MAC2STR(sta->addr));
		}
	}
#endif /* CUSTOM_RK */
```

**Reason:**
Echo back the client_hash_secret received from STA's Association Request in the AP's Association Response. This enables bidirectional vendor-specific data exchange and allows the client to verify that the AP received and processed its custom vendor IE correctly.

**Result:**
AP successfully includes custom vendor IE (OUI 0x027a8b, Type 0xff) in Association Response, echoing the exact payload received from the client. Debug logs confirm successful transmission with hexdump. Completes the full handshake: STA sends vendor IE in AssocReq → AP stores it → AP echoes it back in AssocResp.

### Faeture 7: Move `vendor_ie_custom` to common

Move to `src/common`

---

### Feature 8: Vendor IE Ticket Payload Structure Implementation

**Modified Files:**
- `src/common/vendor_ie_custom.c`
- `src/common/vendor_ie_custom.h`
- `wpa_supplicant/Makefile`
- `hostapd/Makefile`
- `wpa_supplicant/sme.c`
- `wpa_supplicant/scan.c`

**Changes:**
- Refactored `build_custom_vendor_ie()` with wpabuf APIs: `wpabuf_put_u8()`, `wpabuf_put_be16()`, `wpabuf_put_data()`
- Added CUSTOM_RK_NO_DEBUG build payload: Client Hash (SHA256, 32 bytes), PMK (32 bytes), 802.1X EAPOL-Key frame
- Defined structures: `custom_vendor_ie_ticket`, `custom_vendor_ie_eapol_key` in header
- Added size macros: `CUSTOM_CLIENT_HASH_SIZE`, `CUSTOM_PMK_SIZE`, `CUSTOM_WPA_NONCE_SIZE`, etc.
- Replaced hardcoded values with sizeof-based calculations
- Added comprehensive documentation with ticket format table
- Updated Makefiles: `../src/common/vendor_ie_custom.o` for both hostapd and wpa_supplicant
- Updated includes: `#include "common/vendor_ie_custom.h"` in sme.c and scan.c

**Reason:**
Enable resumption ticket exchange via vendor IE. Provide structured, documented payload format for AP/STA parsing consistency.

**Result:**
Complete ticket structure with client hash, PMK, and EAPOL-Key frame. Type-safe, maintainable implementation accessible by both hostapd and wpa_supplicant.

---
