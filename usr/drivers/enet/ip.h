#ifndef ENET_IP_H_
#define ENET_IP_H_

#include <errno.h>
#include <netutil/ip.h>

#define IP_MAX_WAITING_NODES 100

struct ip_package_id;

errval_t ip_init(void);

errval_t ip_handle_package(struct ip_hdr *ip);

void ip_send_waiting_packages(ip_addr_t dest_ip, struct eth_addr dest_eth);

errval_t ip_start_send_package(ip_addr_t dest_ip, struct ip_package_id **ret_package,
                               void **ret_data);

errval_t ip_send_package(struct ip_package_id *package, size_t size);

#endif  // ENET_IP_H_