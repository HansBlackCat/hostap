#include "resumption_ticket.h"

u8 *resumption_ticket_generate_client_secret(u8 *client_secret) {
    // Placeholder implementation
    // Debug print
    wpa_printf(MSG_DEBUG, "Generating client secret for resumption ticket");
    wpa_printf(MSG_DEBUG, "Not implemented yet");
    return client_secret;
}

resumption_ticket *resumption_ticket_create(const u8 *aa, const u8 *spa,
                                            int s_timeout, const u8 *ip_addr,
                                            const u8 *rtk, const u8 *cs) {
    struct resumption_ticket *ticket;
    ticket = (struct resumption_ticket *)os_zalloc(sizeof(*ticket));

    if (ticket == NULL) {
        wpa_printf(MSG_ERROR, "Failed to allocate memory for resumption ticket");
        return NULL;
    }
    wpa_printf(MSG_DEBUG, "Resumption ticket created");

    // Allocate parameters to the generated ticket
    // TODO Consider safe copy
    memcpy(ticket->authenticator_address, aa, ETH_ALEN);
    memcpy(ticket->supplicant_address, spa, ETH_ALEN);
    memcpy(ticket->ip_address, ip_addr, 16);
    memcpy(ticket->resumption_temporal_key, rtk, WPA_TK_MAX_LEN);
    memcpy(ticket->client_secret, cs, WPA_CLIENT_HASH_SECRET);   
    ticket->session_timeout = s_timeout;

    return ticket;
}

void resumption_ticket_deinit(resumption_ticket *ticket) {
    if (ticket) {
        os_free(ticket);
        wpa_printf(MSG_DEBUG, "Resumption ticket deinitialized and memory freed");
    } else {
        wpa_printf(MSG_WARNING, "Attempted to deinitialize a NULL resumption ticket");
    }
}
