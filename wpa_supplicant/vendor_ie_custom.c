/*
 * Custom Vendor Specific IE
 * Copyright (c) 2024, Custom Implementation
 *
 * This software may be distributed under the terms of the BSD license.
 */

#include "includes.h"
#include "common.h"
#include "utils/wpabuf.h"
#include "vendor_ie_custom.h"

/*
 * Build custom vendor specific IE
 * OUI: 0x027a8b
 * Subtype: 0xff
 * Data: 0xaabb
 */
struct wpabuf * build_custom_vendor_ie(void)
{
	struct wpabuf *buf;
	u8 vendor_ie[] = {
		0xdd,           // Element ID (Vendor Specific)
		0x07,           // Length (7 bytes: 3 OUI + 1 type + 2 data + 1 padding)
		0x02, 0x7a, 0x8b,  // OUI
		0xff,           // OUI Type/Subtype
		0xaa, 0xbb,     // Custom data
		0x00            // Padding for alignment
	};

	buf = wpabuf_alloc(sizeof(vendor_ie));
	if (!buf) {
		wpa_printf(MSG_ERROR, "Failed to allocate vendor IE buffer");
		return NULL;
	}

	wpabuf_put_data(buf, vendor_ie, sizeof(vendor_ie));

	wpa_hexdump(MSG_DEBUG, "Custom Vendor IE",
		    wpabuf_head(buf), wpabuf_len(buf));

	return buf;
}

/*
 * Parse custom vendor IE and extract data
 * Returns: 0 on success, -1 on error
 */
int parse_custom_vendor_ie(const u8 *ie, size_t ie_len, u16 *data_out)
{
	const u8 custom_oui[] = {0x02, 0x7a, 0x8b};

	/* Check minimum length: 1 (ID) + 1 (len) + 3 (OUI) + 1 (type) + 2 (data) */
	if (ie_len < 8) {
		wpa_printf(MSG_DEBUG, "Custom vendor IE too short: %zu", ie_len);
		return -1;
	}

	/* Check Element ID */
	if (ie[0] != 0xdd) {
		wpa_printf(MSG_DEBUG, "Not a vendor specific IE: 0x%02x", ie[0]);
		return -1;
	}

	/* Check OUI */
	if (os_memcmp(&ie[2], custom_oui, 3) != 0) {
		wpa_printf(MSG_DEBUG, "OUI mismatch");
		return -1;
	}

	/* Check OUI Type */
	if (ie[5] != 0xff) {
		wpa_printf(MSG_DEBUG, "OUI type mismatch: 0x%02x", ie[5]);
		return -1;
	}

	/* Extract data (2 bytes, big endian) */
	if (data_out) {
		*data_out = (ie[6] << 8) | ie[7];
		wpa_printf(MSG_DEBUG, "Custom vendor IE data: 0x%04x", *data_out);
	}

	return 0;
}

/*
 * Update custom vendor IE data
 * new_data: New 16-bit value to encode
 */
struct wpabuf * update_custom_vendor_ie(u16 new_data)
{
	struct wpabuf *buf;
	u8 vendor_ie[] = {
		0xdd,           // Element ID (Vendor Specific)
		0x07,           // Length
		0x02, 0x7a, 0x8b,  // OUI
		0xff,           // OUI Type/Subtype
		(new_data >> 8) & 0xff,  // Data high byte
		new_data & 0xff,          // Data low byte
		0x00            // Padding
	};

	buf = wpabuf_alloc(sizeof(vendor_ie));
	if (!buf) {
		wpa_printf(MSG_ERROR, "Failed to allocate vendor IE buffer");
		return NULL;
	}

	wpabuf_put_data(buf, vendor_ie, sizeof(vendor_ie));

	wpa_printf(MSG_DEBUG, "Updated custom vendor IE with data: 0x%04x", new_data);
	wpa_hexdump(MSG_DEBUG, "Updated Vendor IE",
		    wpabuf_head(buf), wpabuf_len(buf));

	return buf;
}
