#ifndef VENDOR_IE_CUSTOM_H
#define VENDOR_IE_CUSTOM_H

struct wpabuf;

/* Custom Vendor IE OUI and Type */
#define CUSTOM_VENDOR_OUI_0 0x02
#define CUSTOM_VENDOR_OUI_1 0x7a
#define CUSTOM_VENDOR_OUI_2 0x8b
#define CUSTOM_VENDOR_OUI {CUSTOM_VENDOR_OUI_0, CUSTOM_VENDOR_OUI_1, CUSTOM_VENDOR_OUI_2}
#define CUSTOM_VENDOR_IE_TYPE 0xff

/* Field size definitions */
#define TICKET_SUPPLICANT_HASH_MAX 32
#define TICKET_SUPPLICANT_RAW_MAX 32
#define TICKET_TAN_HASH_MAX 32
#define TICKET_HANDSHAKE_PAYLOAD_MAX 256

#ifndef CUSTOM_RK_NO_DEBUG
    /* Test placeholder values for resumption ticket */
    #define TEST_TICKET_RANDOM 0xdeadbeefcafe2025ULL  /* 8 bytes */
    #define TEST_SUPPLICANT_RAW \
        {0x34, 0x4f, 0x71, 0x32, 0x77, 0xa1, 0x56, 0x7c, \
        0xa3, 0xef, 0x11, 0x0c, 0xbd, 0x77, 0xc4, 0xdf, \
        0x01, 0x8a, 0x6a, 0x2c, 0x1d, 0x91, 0x69, 0x26, \
        0x6d, 0xc8, 0xbb, 0xa3, 0x05, 0x10, 0xdb, 0x11}  /* 32 bytes raw identifier */
#endif /* CUSTOM_RK_NO_DEBUG */

/**
 * struct resumption_ticket - Resumption Ticket Payload
 * Encrypted with RTK using AES-256-GCM
 */
struct resumption_ticket {
	u8 ticket_random;                           /* Ticket Random (Nonce for TAN) */
	u8 supplicant_hash_size;                    /* Size of supplicant hash */
	u8 supplicant_hash[TICKET_SUPPLICANT_HASH_MAX]; /* SHA256 hash of supplicant */
	u8 tan_hash_size;                           /* Size of TAN */
	u8 tan[TICKET_TAN_HASH_MAX];                /* Resumption Master Key (TAN) */
	u8 handshake_payload_size;                  /* Size of handshake payload */
	u8 handshake_payload[TICKET_HANDSHAKE_PAYLOAD_MAX]; /* Handshake data */
	/* Optional field (PMKID, etc.) can follow */
} __attribute__((packed));

/**
 * struct vendor_ie_custom_data - Custom Vendor IE Structure
 * Format: Element ID | Length | OUI | Type | Data fields
 */
struct vendor_ie_custom_data {
	u8 element_id;                              /* 0xDD (Vendor Specific IE) */
	u8 length;                                  /* Total IE length */
	u8 oui[3];                                  /* 0x027a8b */
	u8 oui_type;                                /* 0xff */
	u8 pmkd_encrypted_raw_size;                 /* Size of encrypted client raw */
	u8 *pmkd_encrypted_client_raw;              /* Variable: PMKD-encrypted client raw */
	u8 ticket_size;                             /* Size of encrypted ticket */
	u8 *rtk_encrypted_ticket;                   /* Variable: RTK-encrypted ticket */
	u8 handshake_payload_size;                  /* Size of handshake payload */
	u8 *handshake_payload;                      /* Variable: Handshake data */
} __attribute__((packed));

struct wpabuf * build_custom_vendor_ie(void);

int parse_custom_vendor_ie(const u8 *ie, size_t ie_len, u16 *data_out);

int parse_and_decrypt_vendor_ie_ticket(const u8 *rtk,
					const u8 *ie, size_t ie_len,
					u8 *client_raw_out, u8 *client_raw_size_out,
					struct resumption_ticket *ticket_out);

int encrypt_resumption_ticket(const struct resumption_ticket *ticket,
                             const u32 *rk, size_t rk_len,
                             struct wpabuf **vendor_ie);

#ifndef CUSTOM_RK_NO_DEBUG
/* Global test ticket data */
extern u8 test_supplicant_raw[TICKET_SUPPLICANT_RAW_MAX];
extern u8 test_supplicant_hash[TICKET_SUPPLICANT_HASH_MAX];
extern u8 test_supplicant_hash_size;

int test_build_ticket(void);
#endif /* Custom_RK_NO_DEBUG */

#endif /* VENDOR_IE_CUSTOM_H */
