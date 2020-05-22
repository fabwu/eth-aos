#ifndef UDP_H_
#define UDP_H_

#include <errno.h>
#include <netutil/ip.h>
#include <netutil/udp.h>
#include "ip.h"

struct udp_datagram_id {
    struct ip_package_id package;
    struct udp_hdr *udp;
};

errval_t udp_init(void);

/**
 * \brief Handle incoming udp package.
 */
errval_t udp_handle_package(struct udp_hdr *package, ip_addr_t src);

/**
 * \brief Start sending udp datagram. The ip address has to be in host byte order.
 */
errval_t udp_start_send_datagram(ip_addr_t dest_ip, uint16_t dest_port, uint16_t src_port,
                                 struct udp_datagram_id *datagram, void **ret_data);

/**
 * \brief Sends an udp datagram which was started with udp_start_send_datagram.
 */
errval_t udp_send_datagram(struct udp_datagram_id *datagram, size_t size);

#endif  // UDP_H_