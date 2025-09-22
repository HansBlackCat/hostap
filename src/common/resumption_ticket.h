#ifndef RESUMPTION_TICKET_H
#define RESUMPTION_TICKET_H

struct resumption_ticket {
  u8 authenticator_address[ETH_ALEN];
  u8 supplicant_address[ETH_ALEN];
  int session_timeout;

  IP u8 ip_address[16]; /* Cover both IPv4 and IPv6 */
  u8 resumption_temporal_key[WPA_TK_MAX_LEN];
  u8 client_secret[WPA_CLIENT_HASH_SECRET];
};

/**
 * @brief resumption_ticket_generate_client_secret - Generate client secret for
 * resumption ticket
 *
 * @param client_secret
 * @return u8*
 */
u8 *resumption_ticket_generate_client_secret(u8 *client_secret);

/**
 * @brief resumption_ticket_create - Create a resumption ticket
 *
 * @param aa Authenticator address
 * @param spa Supplicant address
 * @param session_timeout Session timeout in seconds
 * @param ip_addr Ip address (IPv4 or IPv6), design to allocate same IP address
 *                when resumption ticket is used
 * @param rtk Resumption Temporal Key
 * @param cs Client secret, for verify client-side integrity of the ticket
 * @return struct resumption_ticket*
 */
struct resumption_ticket *resumption_ticket_create(const u8 *aa, const u8 *spa,
                                                   int s_timeout,
                                                   const u8 *ip_addr,
                                                   const u8 *rtk, const u8 *cs);

/**
 * @brief resumption_ticket_deinit - Deinitialize resumption ticket and free up
 * space
 *
 * @param ticket
 */
void resumption_ticket_deinit(struct resumption_ticket *ticket);

#endif /* RESUMPTION_TICKET_H */