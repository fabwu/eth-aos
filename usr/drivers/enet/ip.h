#ifndef ENET_IP_H_
#define ENET_IP_H_

#include <errno.h>
#include <netutil/ip.h>

#define IP_MAX_WAITING_NODES 100

struct ip_package_id;

errval_t ip_init(void);

/**
 * \brief Handle incoming ip package.
 */
errval_t ip_handle_package(struct ip_hdr *ip);

/**
 * \brief Send all packages that are pending on the ethernet address for given ip address
 * to the given ethernet address. This is mainly used by the arp implementation to notify
 * address resolutions.
 * The ip address has to be in host byte order, while the hardware address has to be in
 * network byte order.
 */
void ip_send_waiting_packages(ip_addr_t dest_ip, struct eth_addr dest_eth);

/**
 * \brief Fetches or creates a buffer to which the data of an ip package can be written
 * to. The ip address has to be in host byte order.
 */
errval_t ip_start_send_package(ip_addr_t dest_ip, struct ip_package_id **ret_package,
                               void **ret_data);

/**
 * \brief Sends an ip package which was started with ip_start_send_package. In case the
 * ethernet address of the target is not known, the ip package will be added to a pending
 * list.
 */
errval_t ip_send_package(struct ip_package_id *package, size_t size);

#endif  // ENET_IP_H_