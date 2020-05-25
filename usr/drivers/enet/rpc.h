#ifndef ENET_RPC_H_
#define ENET_RPC_H_

#include <errno.h>
#include <stdlib.h>
#include <aos/aos.h>


#define ENET_RPC_DEBUG_OPTION 1

#if defined(ENET_RPC_DEBUG_OPTION)
#define ERPC_DEBUG(x...) debug_printf("[enet rpc] " x);
#else
#define ERPC_DEBUG(fmt, ...) ((void)0)
#endif

#define ENET_UDP_SERVICE_NAME "udp"

errval_t enet_rpc_init(void);

void enet_rpc_udp_handler(void *st, void *message, size_t bytes, void **response,
                          size_t *response_bytes, struct capref tx_cap,
                          struct capref *rx_cap);

#endif  // ENET_RPC_H_