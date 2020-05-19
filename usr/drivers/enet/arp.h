#ifndef ARP_H_
#define ARP_H_

#define ARP_DEBUG_OPTION 1

#if defined(ARP_DEBUG_OPTION)
#    define ARP_DEBUG(x...) debug_printf("[arp] " x);
#else
#    define ARP_DEBUG(fmt, ...) ((void)0)
#endif

#include <errno.h>
#include <netutil/etharp.h>

errval_t arp_init(uint64_t mac);

errval_t arp_handle_package(struct arp_hdr *package);

/**
 * \brief Send an ARP broadcast probe for the static ip address.
 */
errval_t arp_send_probe(void);

/**
 * \brief Send an ARP broadcast request for the given ip address from the static ip
 * adress. The ip address has to be in host byte order.
 */
errval_t arp_send(uint32_t ip_addr);

/**
 * \brief Lookup ip in arp cache. The ip address has to be in host byte order.
 */
bool arp_lookup_ip(uint32_t ip, struct eth_addr **ret_addr);

/**
 * \brief Print the arp cache table to the standard output.
 */
void arp_print_cache(void);

#endif  // ARP_H_