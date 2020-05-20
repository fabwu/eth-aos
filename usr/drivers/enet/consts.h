#ifndef CONSTS_H_
#define CONSTS_H_

#include <netutil/etharp.h>

#define ENET_STATIC_IP 0x0a000002
#define ENET_STATIC_SUBNET 0xffffff00

/**
 * \brief Hardware broadcast address in network byte order.
 */
extern struct eth_addr consts_eth_broadcast;

/**
 * \brief Hardware address of network interface in network byte order.
 */
extern struct eth_addr consts_eth_self;

void consts_init(uint64_t mac);

#endif  // CONSTS_H_