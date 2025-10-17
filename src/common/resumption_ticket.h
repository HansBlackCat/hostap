#ifndef RESUMPTION_TICKET_H
#define RESUMPTION_TICKET_H


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

struct wpabuf;

/* Fixed field sizes for resumption ticket */
#define TICKET_CLIENT_HASH_SIZE 32
#define TICKET_CLIENT_RAW_ENCRYPTED_SIZE 32 /* SHA256 **/
#define TICKET_WPA_NONCE_SIZE 32
#define TICKET_ENCRYPTED_PMK_SIZE 32
#define TICKET_REPLAY_COUNTER_SIZE 8
#define TICKET_KEY_IV_SIZE 16
#define TICKET_KEY_RSC_SIZE 8
#define TICKET_KEY_ID_SIZE 8
#define TICKET_KEY_MIC_SIZE 16

#ifndef CUSTOM_RK_NO_DEBUG
#define TEST_STA_RAW 0xcaffed2025
#define TEST_STA_HASH 0x344f713277a1567ca3ef110cbd77c4df018a6a2c1d9169266dc8bba30510db11
#endif /* CUSTOM_RK_NO_DEBUG */

// TODO May.. dynamic sizes for some fields such ash SHA384 and 512...

struct resumption_ticket_eapol_message {
	u8 descriptor_type;           /* Key descriptor type (0x02 for RSN) */
	u16 key_information;          /* Key information flags (big-endian) */
	u16 key_length;               /* Key length in bytes (big-endian) */
	u8 replay_counter[TICKET_REPLAY_COUNTER_SIZE]; /* Replay counter */
	u8 nonce[TICKET_WPA_NONCE_SIZE]; /* Key nonce (ANonce or SNonce) */
	u8 iv[TICKET_KEY_IV_SIZE];    /* EAPOL-Key IV */
	u8 rsc[TICKET_KEY_RSC_SIZE];  /* Key RSC */
	u8 key_id[TICKET_KEY_ID_SIZE]; /* Key ID */
	u8 mic[TICKET_KEY_MIC_SIZE];  /* Message Integrity Code */
	u16 key_data_length;          /* Key data length (big-endian) */
	/* Followed by key_data if key_data_length > 0 */
} __attribute__((packed));

struct resumption_ticket {
	u8 client_hash_size;          /* Client hash size in bytes */
	u8 client_hash[TICKET_CLIENT_HASH_SIZE]; /* SHA256 hash of client identifier */
	u8 pmk_size;                  /* PMK size in bytes */
	u8 pmk[TICKET_ENCRYPTED_PMK_SIZE];      /* Encrypted-PMK */
	u8 auth_version;              /* 802.1X version (0x02 for 802.1X-2004) */
	u8 auth_type;                 /* 802.1X packet type (0x03 for EAPOL-Key) */
	u16 auth_msg_size;            /* Size of auth message in bytes */
    struct resumption_ticket_eapol_message eapol_message;
	/* Followed by EAPOL-Key frame (struct resumption_ticket_eapol_key) */
} __attribute__((packed));
#endif /* RESUMPTION_TICKET_H */
