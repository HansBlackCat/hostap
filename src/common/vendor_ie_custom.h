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

// TODO Raw RK for testing
#define TEST_RK_32 0xdeadbeefcaffed202520252025202500

struct vendor_ie_custom_data {
    u8 element_id;
    u8 length;
    u8 oui[3];
    u8 oui_type;
    // -----------------------------------
    u8 client_raw_size;
    u8 pmkd_encrypted_client_raw[TICKET_CLIENT_RAW_ENCRYPTED_SIZE];
    // -----------------------------------
    u8 ticket_size;
    u8 *ticket_data; // Resumption ticket data (RK-encrypted)
    u8 *eapol_message; // EAPOL-Key frame for resumption
};

struct wpabuf * build_custom_vendor_ie(void);

int parse_custom_vendor_ie(const u8 *ie, size_t ie_len, u16 *data_out);

int parse_and_decrypt_vendor_ie_ticket(const u8 *rtk,
					const u8 *ie, size_t ie_len,
					u8 *client_raw_out, u8 *client_raw_size_out,
					struct resumption_ticket *ticket_out);

int encrypt_resumption_ticket(const struct resumption_ticket *ticket,
                             const u32 *rk, size_t rk_len,
                             struct wpabuf **vendor_ie);

#endif /* VENDOR_IE_CUSTOM_H */
