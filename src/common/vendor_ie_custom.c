#include "includes.h"
#include "common.h"
#include "wpa_common.h"
#include "utils/wpabuf.h"
#include "crypto/aes_wrap.h"
#include "crypto/random.h"
#include "crypto/sha256.h"
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
 * PMKD-Encrypted Raw Size      | 1 byte    | Size of client raw identifier
 * PMKD-Encrypted Client Raw    | Variable  | Encrypted client raw identifier
 * ----------------------------------------------------------------------------
 * Ticket Size                  | 1 byte    | Size of the ticket
 * RTK-Encrypted Res Ticket     | Variable  | Encrypted resumption ticket
 * ----------------------------------------------------------------------------
 * Handshake Payload Size       | 1 byte    | Size of the ticket
 * Handshake Payload            | variable  | Size of the ticket
 * ============================================================================
 */

/**
 * struct resumption_ticket - Resumption Ticket Payload
 *
 * Ticket Structure (CUSTOM_RK_NO_DEBUG build):
 * ============================================================================
 * Field                        | Size      | Description
 * ============================================================================
 * Ticket Random                | 1 byte    | Ticket Random (Nonce for generating TAN)
 * Supplicant Hash Size         | 1 byte    | Size of supplicant hash (32 for SHA256)
 * Supplicant Hash              | Variable  | SHA256 hash of supplicant identifier
 * TAN Hash Size                | 1 byte    | Size of PMK (32 bytes)
 * Resumption Master Key (TAN)  | Variable  | RMK (== TAN Hash)
 * Handshake Payload Size       | 1 byte    | Size of handshake payload
 * Handshake Payload            | Variable  | Handshake Payload
 * Optional                     | Variable  | Optional
 * ============================================================================
 */ 

/**
 * Potential Optional Field
 *  
 * Optional Field Structure
 * ============================================================================
 * Field                        | Size      | Description
 * ============================================================================
 * PMKID                        | 16bytes   | Truncated-128 (HMAC-SHA1 based)
 * ============================================================================
 * 
 */

#define AES_GCM_IV_SIZE 12
#define AES_GCM_TAG_SIZE 16
#define AES_GCM_OVERHEAD (AES_GCM_IV_SIZE + AES_GCM_TAG_SIZE)

/*
 * encrypt_ticket_payload - Encrypt resumption ticket with AES-256-GCM
 * @rtk: Resumption Ticket Key (32 bytes)
 * @plaintext: Ticket plaintext to encrypt
 * @plaintext_len: Length of plaintext
 * @iv_out: Output buffer for 12-byte IV (must be allocated)
 * @ciphertext_out: Output buffer for encrypted data (must be plaintext_len)
 * @tag_out: Output buffer for 16-byte auth tag (must be allocated)
 * Returns: 0 on success, -1 on error
 *
 * Encrypts the ticket payload using AES-256-GCM with the RTK.
 * AAD (Additional Authenticated Data) is empty for now.
 */
static int encrypt_ticket_payload(const u8 *rtk,
				   const u8 *plaintext, size_t plaintext_len,
				   u8 *iv_out, u8 *ciphertext_out, u8 *tag_out)
{
	/* Generate random 12-byte IV for AES-GCM */
	if (random_get_bytes(iv_out, AES_GCM_IV_SIZE) < 0) {
		wpa_printf(MSG_ERROR, "Failed to generate IV for ticket encryption");
		return -1;
	}

	/* Encrypt with AES-256-GCM (RTK is 32 bytes) */
	if (aes_gcm_ae(rtk, 32, /* key, key_len */
		       iv_out, AES_GCM_IV_SIZE, /* iv, iv_len */
		       plaintext, plaintext_len, /* plaintext, plaintext_len */
		       NULL, 0, /* aad, aad_len (no AAD for now) */
		       ciphertext_out, /* encrypted output */
		       tag_out) < 0) { /* authentication tag */
		wpa_printf(MSG_ERROR, "AES-GCM encryption failed for ticket");
		return -1;
	}

	wpa_hexdump_key(MSG_DEBUG, "Ticket IV", iv_out, AES_GCM_IV_SIZE);
	wpa_hexdump_key(MSG_DEBUG, "Ticket Encrypted", ciphertext_out, plaintext_len);
	wpa_hexdump_key(MSG_DEBUG, "Ticket Auth Tag", tag_out, AES_GCM_TAG_SIZE);

	return 0;
}


/*
 * decrypt_ticket_payload - Decrypt resumption ticket with AES-256-GCM
 * @rtk: Resumption Ticket Key (32 bytes)
 * @iv: Initialization Vector / Nonce (12 bytes)
 * @ciphertext: Encrypted ticket data
 * @ciphertext_len: Length of encrypted data
 * @tag: Authentication tag (16 bytes)
 * @plaintext_out: Output buffer for decrypted data (must be ciphertext_len)
 * Returns: 0 on success, -1 on error or authentication failure
 *
 * Decrypts and authenticates the ticket payload using AES-256-GCM with the RTK.
 * If authentication fails, the ticket has been tampered with and should be rejected.
 */
static int decrypt_ticket_payload(const u8 *rtk,
				   const u8 *iv,
				   const u8 *ciphertext, size_t ciphertext_len,
				   const u8 *tag,
				   u8 *plaintext_out)
{
	wpa_hexdump_key(MSG_DEBUG, "Ticket IV", iv, AES_GCM_IV_SIZE);
	wpa_hexdump_key(MSG_DEBUG, "Ticket Encrypted", ciphertext, ciphertext_len);
	wpa_hexdump_key(MSG_DEBUG, "Ticket Auth Tag", tag, AES_GCM_TAG_SIZE);

	/* Decrypt with AES-256-GCM (RTK is 32 bytes) */
	if (aes_gcm_ad(rtk, 32, /* key, key_len */
		       iv, AES_GCM_IV_SIZE, /* iv, iv_len */
		       ciphertext, ciphertext_len, /* ciphertext, ciphertext_len */
		       NULL, 0, /* aad, aad_len (no AAD for now) */
		       tag, /* authentication tag */
		       plaintext_out) < 0) { /* decrypted output */
		wpa_printf(MSG_ERROR, "AES-GCM decryption failed for ticket (authentication failure or invalid tag)");
		return -1;
	}

	wpa_hexdump_key(MSG_DEBUG, "Ticket Decrypted", plaintext_out, ciphertext_len);
	wpa_printf(MSG_DEBUG, "Ticket decryption and authentication successful");

	return 0;
}


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
    size_t ticket_size;

#ifndef CUSTOM_RK_NO_DEBUG
	/* Test RTK for ticket encryption (32 bytes for AES-256-GCM) */
	static const u8 test_rtk[32] = {
		0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef,
		0xfe, 0xdc, 0xba, 0x98, 0x76, 0x54, 0x32, 0x10,
		0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88,
		0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff, 0x00
	};

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

	/* Calculate plaintext ticket size (before encryption) */
	size_t plaintext_ticket_size = 1 + /* client_hash_size */
				       client_hash_size +
				       1 + /* wpa_pmk_size */
				       wpa_pmk_size +
				       1 + /* auth_version */
				       1 + /* auth_key */
				       2 + /* auth_msg_size */
				       auth_msg_size;

	/* Calculate encrypted ticket size (plaintext + AES-GCM overhead) */
	ticket_size = plaintext_ticket_size + AES_GCM_OVERHEAD;

	/* Calculate total IE payload size */
	ie_len = 3 + /* OUI (3 bytes) */
		 1 + /* OUI Type */
		 1 + /* Client raw size */
		 sizeof(PMKD_encrypted_client_raw) +
		 1 + /* Ticket size */
		 ticket_size;
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

	/* Ticket size (total size of RK-encrypted ticket including IV and tag) */
	wpabuf_put_u8(buf, (u8) ticket_size);

    /*Here the ticket should be encrypted */
	/* Build plaintext ticket payload in temporary buffer */
	u8 *plaintext_ticket = os_malloc(plaintext_ticket_size);
	if (!plaintext_ticket) {
		wpa_printf(MSG_ERROR, "Failed to allocate plaintext ticket buffer");
		wpabuf_free(buf);
		return NULL;
	}

	u8 *pos = plaintext_ticket;

	/* Client hash size */
	*pos++ = client_hash_size;
	/* Client hash */
	os_memcpy(pos, client_hash, client_hash_size);
	pos += client_hash_size;

	/* PMK size */
	*pos++ = wpa_pmk_size;
	/* PMK */
	os_memcpy(pos, wpa_pmk, wpa_pmk_size);
	pos += wpa_pmk_size;

	/* 802.1X Authentication Message */
	*pos++ = auth_version;
	*pos++ = auth_key;

	/* Auth message size (big-endian) */
	WPA_PUT_BE16(pos, auth_msg_size);
	pos += 2;

	/* EAPOL-Key frame */
	*pos++ = auth_key_descriptor_type;
	WPA_PUT_BE16(pos, auth_key_information);
	pos += 2;
	WPA_PUT_BE16(pos, auth_key_length);
	pos += 2;
	os_memcpy(pos, auth_replay_counter, sizeof(auth_replay_counter));
	pos += sizeof(auth_replay_counter);
	os_memcpy(pos, auth_wpa_key_nonce, sizeof(auth_wpa_key_nonce));
	pos += sizeof(auth_wpa_key_nonce);
	os_memcpy(pos, auth_key_iv, sizeof(auth_key_iv));
	pos += sizeof(auth_key_iv);
	os_memcpy(pos, auth_wpa_key_rsc, sizeof(auth_wpa_key_rsc));
	pos += sizeof(auth_wpa_key_rsc);
	os_memcpy(pos, auth_wpa_key_id, sizeof(auth_wpa_key_id));
	pos += sizeof(auth_wpa_key_id);
	os_memcpy(pos, auth_wpa_key_mic, sizeof(auth_wpa_key_mic));
	pos += sizeof(auth_wpa_key_mic);
	WPA_PUT_BE16(pos, auth_wpa_key_data_length);
	pos += 2;

	wpa_hexdump_key(MSG_DEBUG, "Plaintext Ticket", plaintext_ticket, plaintext_ticket_size);

	/* Encrypt ticket with AES-256-GCM */
	u8 ticket_iv[AES_GCM_IV_SIZE];
	u8 *encrypted_ticket = os_malloc(plaintext_ticket_size);
	u8 ticket_tag[AES_GCM_TAG_SIZE];

	if (!encrypted_ticket ||
	    encrypt_ticket_payload(test_rtk, plaintext_ticket, plaintext_ticket_size,
				   ticket_iv, encrypted_ticket, ticket_tag) < 0) {
		wpa_printf(MSG_ERROR, "Failed to encrypt ticket");
		os_free(plaintext_ticket);
		os_free(encrypted_ticket);
		wpabuf_free(buf);
		return NULL;
	}

	/* Add encrypted ticket to IE: IV + Encrypted Payload + Tag */
	wpabuf_put_data(buf, ticket_iv, AES_GCM_IV_SIZE);
	wpabuf_put_data(buf, encrypted_ticket, plaintext_ticket_size);
	wpabuf_put_data(buf, ticket_tag, AES_GCM_TAG_SIZE);

	/* Clean up */
	forced_memzero(plaintext_ticket, plaintext_ticket_size);
	os_free(plaintext_ticket);
	forced_memzero(encrypted_ticket, plaintext_ticket_size);
	os_free(encrypted_ticket);
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


/*
 * parse_and_decrypt_vendor_ie_ticket - Parse and decrypt resumption ticket from vendor IE
 * @rtk: Resumption Ticket Key (32 bytes) for decryption
 * @ie: Pointer to vendor IE data (including Element ID and Length)
 * @ie_len: Total length of IE including Element ID and Length fields
 * @client_raw_out: Output buffer for PMKD-encrypted client raw (must be allocated, size based on client_raw_size)
 * @client_raw_size_out: Output pointer for client raw size
 * @ticket_out: Output structure for decrypted ticket data
 * Returns: 0 on success, -1 on error
 *
 * This function:
 * 1. Validates the vendor IE format (OUI, type)
 * 2. Extracts the PMKD-encrypted client raw identifier
 * 3. Extracts the encrypted ticket (IV, ciphertext, tag)
 * 4. Decrypts the ticket with RTK using AES-256-GCM
 * 5. Parses the decrypted ticket into the resumption_ticket structure
 */
int parse_and_decrypt_vendor_ie_ticket(const u8 *rtk,
					const u8 *ie, size_t ie_len,
					u8 *client_raw_out, u8 *client_raw_size_out,
					struct resumption_ticket *ticket_out)
{
	const u8 custom_oui[] = {CUSTOM_VENDOR_OUI_0,
				 CUSTOM_VENDOR_OUI_1,
				 CUSTOM_VENDOR_OUI_2};
	const u8 *pos;
	u8 client_raw_size;
	u8 ticket_size;
	size_t ciphertext_len;
	u8 *plaintext = NULL;
	int ret = -1;

	/* Check minimum length: 1(ID) + 1(len) + 3(OUI) + 1(type) + 1(client_raw_size) + 1(ticket_size) */
	if (ie_len < 8) {
		wpa_printf(MSG_DEBUG, "Vendor IE too short for ticket: %zu", ie_len);
		return -1;
	}

	/* Check Element ID */
	if (ie[0] != 0xdd) {
		wpa_printf(MSG_DEBUG, "Not a vendor specific IE: 0x%02x", ie[0]);
		return -1;
	}

	/* Check OUI */
	if (os_memcmp(&ie[2], custom_oui, 3) != 0) {
		wpa_printf(MSG_DEBUG, "OUI mismatch in vendor IE");
		return -1;
	}

	/* Check OUI Type */
	if (ie[5] != CUSTOM_VENDOR_IE_TYPE) {
		wpa_printf(MSG_DEBUG, "OUI type mismatch: 0x%02x", ie[5]);
		return -1;
	}

	/* Start parsing after OUI Type */
	pos = &ie[6];

	/* Client raw size */
	client_raw_size = *pos++;
	if (client_raw_size_out)
		*client_raw_size_out = client_raw_size;

	/* Check remaining length for client raw */
	if (pos + client_raw_size > ie + ie_len) {
		wpa_printf(MSG_ERROR, "IE too short for client raw (%u bytes)", client_raw_size);
		return -1;
	}

	/* Extract PMKD-encrypted client raw */
	if (client_raw_out)
		os_memcpy(client_raw_out, pos, client_raw_size);
	pos += client_raw_size;

	wpa_hexdump(MSG_DEBUG, "PMKD-Encrypted Client Raw", client_raw_out, client_raw_size);

	/* Ticket size */
	if (pos >= ie + ie_len) {
		wpa_printf(MSG_ERROR, "IE too short for ticket size");
		return -1;
	}
	ticket_size = *pos++;

	/* Check remaining length for encrypted ticket (IV + ciphertext + tag) */
	if (pos + ticket_size > ie + ie_len) {
		wpa_printf(MSG_ERROR, "IE too short for encrypted ticket (%u bytes)", ticket_size);
		return -1;
	}

	/* Calculate ciphertext length (ticket_size - IV - tag) */
	if (ticket_size < AES_GCM_OVERHEAD) {
		wpa_printf(MSG_ERROR, "Ticket size too small for AES-GCM: %u", ticket_size);
		return -1;
	}
	ciphertext_len = ticket_size - AES_GCM_OVERHEAD;

	/* Extract IV (12 bytes) */
	const u8 *iv = pos;
	pos += AES_GCM_IV_SIZE;

	/* Extract ciphertext */
	const u8 *ciphertext = pos;
	pos += ciphertext_len;

	/* Extract tag (16 bytes) */
	const u8 *tag = pos;
	pos += AES_GCM_TAG_SIZE;

	/* Allocate buffer for decrypted plaintext */
	plaintext = os_malloc(ciphertext_len);
	if (!plaintext) {
		wpa_printf(MSG_ERROR, "Failed to allocate plaintext buffer");
		return -1;
	}

	/* Decrypt ticket payload */
	if (decrypt_ticket_payload(rtk, iv, ciphertext, ciphertext_len, tag, plaintext) < 0) {
		wpa_printf(MSG_ERROR, "Failed to decrypt ticket");
		goto cleanup;
	}

	/* Parse decrypted ticket */
	const u8 *ticket_pos = plaintext;

	/* Client hash size */
	ticket_out->client_hash_size = *ticket_pos++;
	if (ticket_out->client_hash_size != TICKET_CLIENT_HASH_SIZE) {
		wpa_printf(MSG_ERROR, "Invalid client hash size: %u (expected %u)",
			   ticket_out->client_hash_size, TICKET_CLIENT_HASH_SIZE);
		goto cleanup;
	}

	/* Client hash */
	os_memcpy(ticket_out->client_hash, ticket_pos, ticket_out->client_hash_size);
	ticket_pos += ticket_out->client_hash_size;

	/* PMK size */
	ticket_out->pmk_size = *ticket_pos++;
	if (ticket_out->pmk_size != PMK_LEN) {
		wpa_printf(MSG_ERROR, "Invalid PMK size: %u (expected %u)",
			   ticket_out->pmk_size, PMK_LEN);
		goto cleanup;
	}

	/* PMK */
	os_memcpy(ticket_out->pmk, ticket_pos, ticket_out->pmk_size);
	ticket_pos += ticket_out->pmk_size;

	/* 802.1X version */
	ticket_out->auth_version = *ticket_pos++;

	/* 802.1X type */
	ticket_out->auth_type = *ticket_pos++;

	/* Auth message size (big-endian) */
	ticket_out->auth_msg_size = WPA_GET_BE16(ticket_pos);
	ticket_pos += 2;

	/* EAPOL-Key frame */
	/* Descriptor type */
	ticket_out->eapol_message.descriptor_type = *ticket_pos++;

	/* Key information (big-endian) */
	ticket_out->eapol_message.key_information = WPA_GET_BE16(ticket_pos);
	ticket_pos += 2;

	/* Key length (big-endian) */
	ticket_out->eapol_message.key_length = WPA_GET_BE16(ticket_pos);
	ticket_pos += 2;

	/* Replay counter */
	os_memcpy(ticket_out->eapol_message.replay_counter, ticket_pos, TICKET_REPLAY_COUNTER_SIZE);
	ticket_pos += TICKET_REPLAY_COUNTER_SIZE;

	/* Nonce */
	os_memcpy(ticket_out->eapol_message.nonce, ticket_pos, TICKET_WPA_NONCE_SIZE);
	ticket_pos += TICKET_WPA_NONCE_SIZE;

	/* IV */
	os_memcpy(ticket_out->eapol_message.iv, ticket_pos, TICKET_KEY_IV_SIZE);
	ticket_pos += TICKET_KEY_IV_SIZE;

	/* RSC */
	os_memcpy(ticket_out->eapol_message.rsc, ticket_pos, TICKET_KEY_RSC_SIZE);
	ticket_pos += TICKET_KEY_RSC_SIZE;

	/* Key ID */
	os_memcpy(ticket_out->eapol_message.key_id, ticket_pos, TICKET_KEY_ID_SIZE);
	ticket_pos += TICKET_KEY_ID_SIZE;

	/* MIC */
	os_memcpy(ticket_out->eapol_message.mic, ticket_pos, TICKET_KEY_MIC_SIZE);
	ticket_pos += TICKET_KEY_MIC_SIZE;

	/* Key data length (big-endian) */
	ticket_out->eapol_message.key_data_length = WPA_GET_BE16(ticket_pos);
	ticket_pos += 2;

	wpa_printf(MSG_DEBUG, "Successfully parsed and decrypted vendor IE ticket");
	wpa_hexdump_key(MSG_DEBUG, "Decrypted Client Hash",
			ticket_out->client_hash, ticket_out->client_hash_size);
	wpa_hexdump_key(MSG_DEBUG, "Decrypted PMK",
			ticket_out->pmk, ticket_out->pmk_size);

	ret = 0;

cleanup:
	if (plaintext) {
		forced_memzero(plaintext, ciphertext_len);
		os_free(plaintext);
	}
	return ret;
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

#ifndef CUSTOM_RK_NO_DEBUG
/* Global test ticket data */
u8 test_supplicant_raw[TICKET_SUPPLICANT_RAW_MAX];
u8 test_supplicant_hash[TICKET_SUPPLICANT_HASH_MAX];
u8 test_supplicant_hash_size = 0;

/**
 * test_build_ticket - Build test resumption ticket from placeholder values
 * Returns: 0 on success, -1 on error
 *
 * Computes SHA256 hash of TEST_SUPPLICANT_RAW and stores in global variable
 */
int test_build_ticket(void)
{
	u8 raw_data[] = TEST_SUPPLICANT_RAW;
	size_t raw_len = sizeof(raw_data);

	/* Store supplicant raw identifier */
	os_memcpy(test_supplicant_raw, raw_data, TICKET_SUPPLICANT_RAW_MAX);

	/* Compute SHA256 hash of supplicant raw identifier */
	if (sha256_vector(1, (const u8 **) &raw_data, &raw_len,
			  test_supplicant_hash) < 0) {
		wpa_printf(MSG_ERROR, "Failed to compute supplicant hash");
		return -1;
	}

	test_supplicant_hash_size = TICKET_SUPPLICANT_HASH_MAX;

	wpa_printf(MSG_DEBUG, "Test ticket: Supplicant hash computed");
	wpa_hexdump_key(MSG_DEBUG, "Supplicant Raw", test_supplicant_raw, TICKET_SUPPLICANT_RAW_MAX);
	wpa_hexdump_key(MSG_DEBUG, "Supplicant Hash",
			test_supplicant_hash, test_supplicant_hash_size);

	return 0;
}
#endif /* CUSTOM_RK_NO_DEBUG */
