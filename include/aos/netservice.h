#ifndef INCLUDE_NETSERVICE_H_
#define INCLUDE_NETSERVICE_H_

#include <errno.h>
#include <aos/aos.h>
#include <netutil/etharp.h>
#include <netutil/ip.h>
#include <netutil/udp.h>

#define NETSERVICE_DEBUG_OPTION 1

#if defined(NETSERVICE_DEBUG_OPTION)
#    define NETS_DEBUG(x...) debug_printf("[net service] " x);
#else
#    define NETS_DEBUG(fmt, ...) ((void)0)
#endif

#define ENET_UDP_SERVICE_NAME "udp"
#define ENET_ARP_SERVICE_NAME "arp"
#define ENET_UDP_LISTEN_PREFIX "_udp"
#define ENET_MAX_PKT_SIZE 1536
#define ENET_UDP_MAX_DATA (ENET_MAX_PKT_SIZE - ETH_HLEN - IP_HLEN - UDP_HLEN)

/**
 * UDP service message types
 */
#define AOS_UDP_LISTEN      0x11  // Start listening on given port
#define AOS_UDP_CLOSE       0x12  // Stop listening on given port
#define AOS_UDP_SEND        0x21  // Send udp datagram
#define AOS_ARP_PRINT_CACHE 0x31  // Print arp ip to ethernet translation table

#define AOS_UDP_CALLBACK_MAX_LEN 10

struct rpc_udp_listen {
    uint8_t type;
    char listen_service[AOS_UDP_CALLBACK_MAX_LEN + 1];  ///< Name of the service to which
                                                        ///< incoming datagrams should be
                                                        ///< sent to.
    uint16_t port;
};

struct rpc_udp_close {
    uint8_t type;
    uint16_t port;
};

struct rpc_udp_send {
    uint8_t type;
    uint16_t src_port;
    uint16_t dest_port;
    uint32_t dest_ip;
};

struct rpc_udp_response {
    uint8_t type;
    bool success;
};

struct rpc_udp_header {
    uint8_t _reserved;
    uint16_t length;
    uint16_t src_port;
    uint16_t dest_port;
    uint32_t src_ip;
};

/**
 * \brief Function prototype that has to be implemented to receive udp datagrams.
 */
typedef void (*netservice_udp_handler_t)(void *state, struct rpc_udp_header *header,
                                         void *data);

/**
 * \brief Send a single udp datagram.
 *
 * \param message  The rpc_udp_send struct and the data which starts with the
 *                 byte after the struct.
 * \param size     The size of the rpc_udp_send struct plus the
 *                 size of the data bytes.
 */
errval_t netservice_udp_send_single(struct rpc_udp_send *message, size_t size);

/**
 * \brief Start listening for udp datagrams on the given port.
 *
 * \param port               Port to receive datagrams on.
 * \param udp_handler        Callback handler that is called when
 *                           receiving datagrams on given port.
 * \param udp_handler_state  State handed to callback handler.
 */
errval_t netservice_udp_listen(uint16_t port, netservice_udp_handler_t udp_handler,
                               void *udp_handler_state);

/**
 * \brief Try to close udp listener. This asks for an ack on the udp_handler before
 * closing, so only the listener can close.
 *
 * \param port               Port to close.
 */
errval_t netservice_udp_close(uint16_t port);

errval_t netservice_arp_print_cache(void);

#endif /* INCLUDE_NETSERVICE_H_ */
