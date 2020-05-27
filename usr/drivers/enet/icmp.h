#ifndef ENET_ICMP_H_
#define ENET_ICMP_H_

#include <errno.h>
#include <netutil/icmp.h>

/**
 * \brief Handle incoming icmp package. Source ip address has to be in host byte order.
 */
errval_t icmp_handle_package(struct icmp_echo_hdr *icmp, ip_addr_t src, uint16_t size);

#endif  // ENET_ICMP_H_