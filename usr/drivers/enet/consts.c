#include <netutil/etharp.h>

#include "consts.h"

struct eth_addr consts_eth_broadcast;
struct eth_addr consts_eth_self;
struct eth_addr consts_eth_zeros;

void consts_init(uint64_t mac) {
    // Convert mac to network byte order
    for (int i = ETH_ADDR_LEN - 1; i >= 0; --i) {
        consts_eth_self.addr[i] = mac & 0xff;
        mac >>= 8;
    }

    for (int i = 0; i < ETH_ADDR_LEN; ++i) {
        consts_eth_broadcast.addr[i] = 0xff;
    }

    for (int i = 0; i < ETH_ADDR_LEN; ++i) {
        consts_eth_zeros.addr[i] = 0x00;
    }
}
