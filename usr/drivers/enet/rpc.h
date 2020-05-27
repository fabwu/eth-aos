#ifndef ENET_RPC_H_
#define ENET_RPC_H_

#include <errno.h>
#include <stdlib.h>
#include <aos/aos.h>
#include <netutil/udp.h>


#define ENET_RPC_DEBUG_OPTION 1

#if defined(ENET_RPC_DEBUG_OPTION)
#define ERPC_DEBUG(x...) debug_printf("[enet rpc] " x);
#else
#define ERPC_DEBUG(fmt, ...) ((void)0)
#endif

errval_t enet_rpc_init(void);

errval_t enet_rpc_handle_udp(struct udp_hdr *udp, ip_addr_t src);

#endif  // ENET_RPC_H_