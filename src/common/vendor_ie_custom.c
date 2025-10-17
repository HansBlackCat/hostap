#include "includes.h"
#include "common.h"
#include "wpa_common.h"
#include "utils/wpabuf.h"
#include "resumption_ticket.h"
#include "vendor_ie_custom.h"

/*
 * Vendor IE Structure
 * ============================================================================
 * Field                        | Size      | Description
 * ============================================================================
 * Element ID                   | 1 byte    | 0xdd (Vendor Specific IE)
 * Length                       | 1 byte    | Total IE length (excluding ID/Length)
 * OUI                          | 3 bytes   | 0x027a8b (Custom OUI)
 * OUI Type                     | 1 byte    | 0xff (Custom type)
 * ----------------------------------------------------------------------------
 * Client     Size              | 1 byte    | Size of client raw identifier
 * PMKD-Encrypted Client Raw    | Variable  | Encrypted client raw identifier
 * ----------------------------------------------------------------------------
 * Ticket Size                  | 1 byte    | Size of the ticket
 * RK-Encrypted Ticket          | Variable  | Encrypted resumption ticket
 * 802.1X - Message 2           | Variable  | EAPOL-Key frame for resumption
 * ============================================================================
 */

/**
 * struct resumption_ticket - Resumption Ticket Payload
 *
 * Ticket Structure (CUSTOM_RK_NO_DEBUG build):
 * ============================================================================
 * Field                        | Size      | Description
 * ============================================================================
 * Client Hash Size             | 1 byte    | Size of client hash (32 for SHA256)
 * Client Hash                  | Variable  | SHA256 hash of client identifier
 * PMK Size                     | 1 byte    | Size of PMK (32 bytes)
 * PMK                          | Variable  | Pre-Master Key
 * 802.1X Version               | 1 byte    | 0x02 (802.1X-2004)
 * 802.1X Type                  | 1 byte    | 0x03 (EAPOL-Key)
 * Auth Message Size            | 2 bytes   | Size of EAPOL-Key frame
 * ----------------------------------------------------------------------------
 * EAPOL-Key Descriptor Type    | 1 byte    | 0x02 (RSN Key)
 * EAPOL-Key Information        | 2 bytes   | Key flags (big-endian)
 * EAPOL-Key Length             | 2 bytes   | Key length (big-endian)
 * EAPOL-Key Replay Counter     | 8 bytes   | Replay counter
 * EAPOL-Key Nonce              | 32 bytes  | Key nonce (ANonce or SNonce)
 * EAPOL-Key IV                 | 16 bytes  | EAPOL-Key IV
 * EAPOL-Key RSC                | 8 bytes   | Key RSC
 * EAPOL-Key ID                 | 8 bytes   | Key ID
 * EAPOL-Key MIC                | 16 bytes  | Message Integrity Code
 * EAPOL-Key Data Length        | 2 bytes   | Key data length (big-endian)
 * EAPOL-Key Data               | Variable  | Key data (if length > 0)
 * ============================================================================
 */


/*
 * build_custom_vendor_ie - Build custom vendor specific IE with ticket
 *
 * Constructs a complete vendor IE containing resumption ticket information.
 * The ticket includes client hash, PMK, and EAPOL-Key frame for fast
 * reassociation.
 */
struct wpabuf * build_custom_vendor_ie(void)
{
	struct wpabuf *buf;
	u8 *length_ptr;
	size_t ie_len;

#ifndef CUSTOM_RK_NO_DEBUG
    static const u8 client_raw[] = { 0xca, 0xff, 0xed, 0x20, 0x25};
    static const u8 client_raw_size = sizeof(client_raw);
    static const u8 PMKD_encrypted_client_raw_size = TICKET_CLIENT_RAW_ENCRYPTED_SIZE;
    static const u8 PMKD_encrypted_client_raw[TICKET_CLIENT_RAW_ENCRYPTED_SIZE] = { 0x00 }; /* Example encrypted data */

	/* Client hash from TEST_STA_RAW string */
	static const u8 client_hash[TICKET_CLIENT_HASH_SIZE] = {
		0x34, 0x4f, 0x71, 0x32, 0x77, 0xa1, 0x56, 0x7c,
		0xa3, 0xef, 0x11, 0x0c, 0xbd, 0x77, 0xc4, 0xdf,
		0x01, 0x8a, 0x6a, 0x2c, 0x1d, 0x91, 0x69, 0x26,
		0x6d, 0xc8, 0xbb, 0xa3, 0x05, 0x10, 0xdb, 0x11
	}; /* SHA256 hash of "TEST_STA_RAW" */
	static const u8 client_hash_size = sizeof(client_hash);

	/* PMK (all zeros for testing) */
	static const u8 wpa_pmk[PMK_LEN] = { 0x00 };
	static const u8 wpa_pmk_size = sizeof(wpa_pmk);

	/* 802.1X Authentication Message fields */
	static const u8 auth_version = 0x02; /* 802.1X-2004 */
	static const u8 auth_key = 0x03; /* EAPOL-Key */
	static const u8 auth_key_descriptor_type = 0x02; /* EAPOL RSN Key */
	static const u16 auth_key_information = 0x008a; /* Key flags */
	/* Key Descriptor Version: 2 (AES, HMAC-SHA1 MIC)
	 * Key Type: 1 (Pairwise)
	 * Key ACK: 1 (Set)
	 * Other flags: 0 (Not set)
	 */
	static const u16 auth_key_length = 16; /* AES key length */
	static const u8 auth_replay_counter[TICKET_REPLAY_COUNTER_SIZE] = {
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01
	};
	static const u8 auth_wpa_key_nonce[TICKET_WPA_NONCE_SIZE] = {
		0x6a, 0x9e, 0x0d, 0xa6, 0xbf, 0x66, 0xe0, 0x3f,
		0x74, 0xf0, 0xdf, 0x4d, 0x3c, 0xf9, 0x83, 0xdc,
		0x50, 0x57, 0xef, 0xf9, 0x64, 0x51, 0x8b, 0xf8,
		0x18, 0x9a, 0x7a, 0x2d, 0xa9, 0x63, 0x07, 0xe2
	};
	static const u8 auth_key_iv[TICKET_KEY_IV_SIZE] = { 0x00 };
	static const u8 auth_wpa_key_rsc[TICKET_KEY_RSC_SIZE] = { 0x00 };
	static const u8 auth_wpa_key_id[TICKET_KEY_ID_SIZE] = { 0x00 };
	static const u8 auth_wpa_key_mic[TICKET_KEY_MIC_SIZE] = { 0x00 };
	static const u16 auth_wpa_key_data_length = 0; /* No key data */

	/* Calculate auth message size */
	u16 auth_msg_size = sizeof(auth_key_descriptor_type) +
			    sizeof(auth_key_information) +
			    sizeof(auth_key_length) +
			    sizeof(auth_replay_counter) +
			    sizeof(auth_wpa_key_nonce) +
			    sizeof(auth_key_iv) +
			    sizeof(auth_wpa_key_rsc) +
			    sizeof(auth_wpa_key_id) +
			    sizeof(auth_wpa_key_mic) +
			    sizeof(auth_wpa_key_data_length);

	/* Calculate total IE payload size */
	ie_len = 3 + /* OUI (3 bytes) */
		 1 + /* OUI Type */
         1 + /* Client raw size */
         sizeof(PMKD_encrypted_client_raw) + /*  */
		 sizeof(client_hash_size) +
		 sizeof(client_hash) +
		 sizeof(wpa_pmk_size) +
		 sizeof(wpa_pmk) +
		 sizeof(auth_version) +
		 sizeof(auth_key) +
		 sizeof(u16) + /* auth_msg_size (big-endian) */
		 auth_msg_size;
#else
	/* Minimal IE for non-debug builds */
	ie_len = 3 + /* OUI (3 bytes) */
		 1 + /* OUI Type */
		 2; /* Test data (2 bytes) */
#endif /* CUSTOM_RK_NO_DEBUG */

	/* Allocate buffer: 1 (ID) + 1 (Length) + ie_len */
	buf = wpabuf_alloc(2 + ie_len);
	if (!buf) {
		wpa_printf(MSG_ERROR, "Failed to allocate vendor IE buffer");
		return NULL;
	}

	/* Element ID (Vendor Specific) */
	wpabuf_put_u8(buf, 0xdd);

	/* Length field - will be filled later */
	length_ptr = wpabuf_put(buf, 1);

	/* OUI */
	wpabuf_put_u8(buf, CUSTOM_VENDOR_OUI_0);
	wpabuf_put_u8(buf, CUSTOM_VENDOR_OUI_1);
	wpabuf_put_u8(buf, CUSTOM_VENDOR_OUI_2);

	/* OUI Type */
	wpabuf_put_u8(buf, CUSTOM_VENDOR_IE_TYPE);

#ifndef CUSTOM_RK_NO_DEBUG
    /* Client raw size */
    wpabuf_put_u8(buf, PMKD_encrypted_client_raw_size);

    /* PMKD-Encrypted Client Raw */
    wpabuf_put_data(buf, PMKD_encrypted_client_raw, sizeof(PMKD_encrypted_client_raw));

	/* Client hash size */
	wpabuf_put_u8(buf, client_hash_size);

	/* Client hash */
	wpabuf_put_data(buf, client_hash, client_hash_size);

	/* PMK size */
	wpabuf_put_u8(buf, wpa_pmk_size);

	/* PMK */
	wpabuf_put_data(buf, wpa_pmk, wpa_pmk_size);

	/* 802.1X Authentication Message */
	wpabuf_put_u8(buf, auth_version);
	wpabuf_put_u8(buf, auth_key);

	/* Auth message size (big-endian) */
	wpabuf_put_be16(buf, auth_msg_size);

	/* EAPOL-Key frame */
	wpabuf_put_u8(buf, auth_key_descriptor_type);
	wpabuf_put_be16(buf, auth_key_information);
	wpabuf_put_be16(buf, auth_key_length);
	wpabuf_put_data(buf, auth_replay_counter, sizeof(auth_replay_counter));
	wpabuf_put_data(buf, auth_wpa_key_nonce, sizeof(auth_wpa_key_nonce));
	wpabuf_put_data(buf, auth_key_iv, sizeof(auth_key_iv));
	wpabuf_put_data(buf, auth_wpa_key_rsc, sizeof(auth_wpa_key_rsc));
	wpabuf_put_data(buf, auth_wpa_key_id, sizeof(auth_wpa_key_id));
	wpabuf_put_data(buf, auth_wpa_key_mic, sizeof(auth_wpa_key_mic));
	wpabuf_put_be16(buf, auth_wpa_key_data_length);
#else
	/* Minimal test data for non-debug builds */
	wpabuf_put_u8(buf, 0xaa);
	wpabuf_put_u8(buf, 0xbb);
#endif /* CUSTOM_RK_NO_DEBUG */

	/* Fill in the length field */
	*length_ptr = (u8) (wpabuf_len(buf) - 2);

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
	const u8 custom_oui[] = {CUSTOM_VENDOR_OUI_0,
				 CUSTOM_VENDOR_OUI_1,
				 CUSTOM_VENDOR_OUI_2};

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
	if (ie[5] != CUSTOM_VENDOR_IE_TYPE) {
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

// /*
//  * Update custom vendor IE data
//  * new_data: New 16-bit value to encode
//  */
// struct wpabuf * update_custom_vendor_ie(u16 new_data)
// {
// 	struct wpabuf *buf;
// 	u8 vendor_ie[] = {
// 		0xdd,           // Element ID (Vendor Specific)
// 		0x07,           // Length
// 		0x02, 0x7a, 0x8b,  // OUI
// 		0xff,           // OUI Type/Subtype
// 		(new_data >> 8) & 0xff,  // Data high byte
// 		new_data & 0xff,          // Data low byte
// 		0x00            // Padding
// 	};
//
// 	buf = wpabuf_alloc(sizeof(vendor_ie));
// 	if (!buf) {
// 		wpa_printf(MSG_ERROR, "Failed to allocate vendor IE buffer");
// 		return NULL;
// 	}
//
// 	wpabuf_put_data(buf, vendor_ie, sizeof(vendor_ie));
//
// 	wpa_printf(MSG_DEBUG, "Updated custom vendor IE with data: 0x%04x", new_data);
// 	wpa_hexdump(MSG_DEBUG, "Updated Vendor IE",
// 		    wpabuf_head(buf), wpabuf_len(buf));
//
// 	return buf;
// }
