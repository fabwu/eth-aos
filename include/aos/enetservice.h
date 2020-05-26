#ifndef INCLUDE_ENETSERVICE_H_
#define INCLUDE_ENETSERVICE_H_

#include <aos/aos.h>

/**
 * UDP service message types
 */
#define AOS_UDP_LISTEN 0x11  // Start listening on given port
#define AOS_UDP_CLOSE 0x12  // Stop listening on given port
#define AOS_UDP_SEND 0x21  // Send udp datagram


#define AOS_UDP_CALLBACK_MAX_LEN 10

struct rpc_udp_listen {
    uint8_t type;
    char listen_service[AOS_UDP_CALLBACK_MAX_LEN + 1];  ///< Name of the service to which incoming
                                                    ///< datagrams should be sent to.
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

#endif /* INCLUDE_ENETSERVICE_H_ */
