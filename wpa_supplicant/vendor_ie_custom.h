/*
 * Custom Vendor Specific IE
 * Copyright (c) 2024, Custom Implementation
 */

#ifndef VENDOR_IE_CUSTOM_H
#define VENDOR_IE_CUSTOM_H

struct wpabuf;

/**
 * build_custom_vendor_ie - Build custom vendor specific IE
 * Returns: Allocated wpabuf with vendor IE or NULL on failure
 *
 * Builds a vendor specific IE with:
 * - OUI: 0x027a8b
 * - Subtype: 0xff
 * - Data: 0xaabb
 */
struct wpabuf * build_custom_vendor_ie(void);

/**
 * parse_custom_vendor_ie - Parse custom vendor IE
 * @ie: Pointer to IE data (including element ID and length)
 * @ie_len: Length of IE data
 * @data_out: Pointer to store extracted data (can be NULL)
 * Returns: 0 on success, -1 on error
 *
 * Parses custom vendor IE and extracts the 16-bit data field
 */
int parse_custom_vendor_ie(const u8 *ie, size_t ie_len, u16 *data_out);

/**
 * update_custom_vendor_ie - Create vendor IE with updated data
 * @new_data: New 16-bit value to encode
 * Returns: Allocated wpabuf with updated vendor IE or NULL on failure
 */
struct wpabuf * update_custom_vendor_ie(u16 new_data);

#endif /* VENDOR_IE_CUSTOM_H */
