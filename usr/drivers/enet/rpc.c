#include <assert.h>
#include <errno.h>
#include <aos/nameservice.h>
#include <netutil/etharp.h>
#include <netutil/ip.h>
#include <netutil/udp.h>
#include "enet.h"
#include "udp.h"

#include "rpc.h"

#define ENET_UDP_MAX_DATA (ENET_MAX_PKT_SIZE - ETH_HLEN - IP_HLEN - UDP_HLEN)

errval_t enet_rpc_init(void)
{
    return nameservice_register(ENET_UDP_SERVICE_NAME, enet_rpc_udp_handler, NULL);
}

// static errval_t enet_rpc_handle_udp_listen(void)
// {
//     return SYS_ERR_NOT_IMPLEMENTED;
// }

static errval_t enet_rpc_udp_send(struct rpc_send_udp *message, size_t bytes,
                                  void **response, size_t *response_bytes)
{
    errval_t err;

    struct rpc_udp_response *udp_response = malloc(sizeof(struct rpc_udp_response));
    if (udp_response == NULL) {
        return LIB_ERR_MALLOC_FAIL;
    }
    *response = udp_response;
    *(uint8_t *)udp_response = *(uint8_t *)message;
    udp_response->success = false;
    *response_bytes = sizeof(struct rpc_udp_response);

    size_t size = bytes - sizeof(struct rpc_send_udp);
    if (size > ENET_UDP_MAX_DATA) {
        ERPC_DEBUG("Discarding udp send request: Message too large (%ld)\n", bytes);
        return SYS_ERR_OK;
    }

    struct udp_datagram_id datagram;
    char *data;
    err = udp_start_send_datagram(message->dest_ip, message->dest_port, message->src_port, &datagram,
                                  (void **)&data);
    if (err_is_fail(err)) {
        return err;
    }

    memcpy(data, (void *)(message + 1), size);

    err = udp_send_datagram(&datagram, (uint16_t)size);
    if (err_is_fail(err)) {
        return err;
    }

    udp_response->success = false;
    ERPC_DEBUG("Sent udp datagram\n");
    return SYS_ERR_OK;
}

void enet_rpc_udp_handler(void *st, void *message, size_t bytes, void **response,
                          size_t *response_bytes, struct capref tx_cap,
                          struct capref *rx_cap)
{
    assert(message != NULL);

    errval_t err;
    // Setting empty response in advance for all error cases
    *response_bytes = 0;

    if (bytes <= 0) {
        ERPC_DEBUG("Discarding empty rpc message\n");
        return;
    }

    switch (*(uint8_t *)message) {
    case AOS_UDP_LISTEN:

        break;
    case AOS_UDP_CLOSE:
        break;
    case AOS_UDP_SEND:
        ERPC_DEBUG("UDP send request\n");
        err = enet_rpc_udp_send((struct rpc_send_udp *)message, bytes, response,
                                response_bytes);
        if (err_is_fail(err)) {
            DEBUG_ERR(err, "Failed to handle udp send request");
        }
        break;
    default:
        ERPC_DEBUG("Discarding message of unkown tpye: 0x%x\n", *(uint8_t *)message);
        return;
    }
}