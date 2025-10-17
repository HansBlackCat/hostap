#ifndef VENDOR_IE_CUSTOM_H
#define VENDOR_IE_CUSTOM_H

#include "resumption_ticket.h"

struct wpabuf;

/* Custom Vendor IE OUI and Type */
#define CUSTOM_VENDOR_OUI_0 0x02
#define CUSTOM_VENDOR_OUI_1 0x7a
#define CUSTOM_VENDOR_OUI_2 0x8b
#define CUSTOM_VENDOR_OUI {CUSTOM_VENDOR_OUI_0, CUSTOM_VENDOR_OUI_1, CUSTOM_VENDOR_OUI_2}
#define CUSTOM_VENDOR_IE_TYPE 0xff

/**
 * build_custom_vendor_ie - Build custom vendor specific IE
 * Returns: Allocated wpabuf with vendor IE or NULL on failure
 *
 * Builds a vendor specific IE with resumption ticket payload:
 * - OUI: 0x027a8b
 * - OUI Type: 0xff
 *
 * The returned buffer includes:
 * - Element ID (0xdd)
 * - Length field
 * - OUI (3 bytes)
 * - OUI Type (1 byte)
 * - Resumption ticket payload (variable length based on build configuration)
 */
struct wpabuf * build_custom_vendor_ie(void);

/**
 * parse_custom_vendor_ie - Parse custom vendor IE
 * @ie: Pointer to IE data (including element ID and length)
 * @ie_len: Length of IE data
 * @data_out: Pointer to store extracted data (can be NULL)
 * Returns: 0 on success, -1 on error
 *
 * Parses custom vendor IE and validates OUI/Type.
 * Extracts and validates resumption ticket payload.
 */
int parse_custom_vendor_ie(const u8 *ie, size_t ie_len, u16 *data_out);

#endif /* VENDOR_IE_CUSTOM_H */
