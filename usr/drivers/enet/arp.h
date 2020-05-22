#ifndef ARP_H_
#define ARP_H_

#include <errno.h>
#include <netutil/etharp.h>
#include <netutil/ip.h>

errval_t arp_init(void);

/**
 * \brief Handle incoming arp package.
 */
errval_t arp_handle_package(struct arp_hdr *package);

/**
 * \brief Send an ARP broadcast probe for the static ip address.
 */
errval_t arp_send_probe(void);

/**
 * \brief Send an ARP broadcast request for the given ip address from the static ip
 * adress. The ip address has to be in host byte order.
 */
errval_t arp_send(ip_addr_t ip_addr);

/**
 * \brief Lookup ip in arp cache. The ip address has to be in host byte order.
 */
struct eth_addr *arp_lookup_ip(ip_addr_t ip);

/**
 * \brief Print the arp cache table to the standard output.
 */
void arp_print_cache(void);

#endif  // ARP_H_