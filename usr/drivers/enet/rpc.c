#include <assert.h>
#include <errno.h>
#include <aos/nameservice.h>
#include <aos/netservice.h>
#include <collections/hash_table.h>
#include <netutil/udp.h>
#include <netutil/htons.h>
#include "enet.h"
#include "udp.h"

#include "rpc.h"

struct enet_rpc_state {
    collections_hash_table *listeners;
};

static struct enet_rpc_state state;

static errval_t enet_rpc_udp_listen(struct rpc_udp_listen *message, size_t bytes,
                                    void **response, size_t *response_bytes)
{
    errval_t err;

    // Static so it stays valid after returning from this function
    static struct rpc_udp_response udp_response;
    udp_response.type = message->type;
    udp_response.success = false;
    *response = &udp_response;
    *response_bytes = sizeof(struct rpc_udp_response);

    nameservice_chan_t chan = collections_hash_find(state.listeners, (uint64_t)message->port);
    if (chan != NULL) {
        ERPC_DEBUG("Discarding udp listen request: Port is already in use\n", bytes);
        return SYS_ERR_OK;
    }

    size_t service_length = 0;
    while (service_length <= AOS_UDP_CALLBACK_MAX_LEN
           && message->listen_service[service_length] != '\0') {
        ++service_length;
    }

    if (service_length > AOS_UDP_CALLBACK_MAX_LEN) {
        ERPC_DEBUG("Discarding udp listen request: Invalid service\n", bytes);
        return SYS_ERR_OK;
    }

    err = nameservice_lookup(message->listen_service, &chan);
    if (err_is_fail(err)) {
        ERPC_DEBUG("Discarding udp listen request: "
                   "Could not connect to listener service\n",
                   bytes);
        return err;
    }

    collections_hash_insert(state.listeners, (uint64_t)message->port, (void *)chan);
    udp_response.success = true;
    ERPC_DEBUG("Start listening on port %d\n", message->port);
    return SYS_ERR_OK;
}

static errval_t enet_rpc_udp_send(struct rpc_udp_send *message, size_t bytes,
                                  void **response, size_t *response_bytes)
{
    errval_t err;

    // Static so it stays valid after returning from this function
    static struct rpc_udp_response udp_response;
    udp_response.type = message->type;
    udp_response.success = false;
    *response = &udp_response;
    *response_bytes = sizeof(struct rpc_udp_response);

    size_t size = bytes - sizeof(struct rpc_udp_send);
    if (size > ENET_UDP_MAX_DATA) {
        ERPC_DEBUG("Discarding udp send request: Message too large (%ld)\n", bytes);
        return SYS_ERR_OK;
    }

    struct udp_datagram_id datagram;
    char *data;
    err = udp_start_send_datagram(message->dest_ip, message->dest_port, message->src_port,
                                  &datagram, (void **)&data);
    if (err_is_fail(err)) {
        return err;
    }

    memcpy(data, (void *)(message + 1), size);

    err = udp_send_datagram(&datagram, (uint16_t)size);
    if (err_is_fail(err)) {
        return err;
    }

    udp_response.success = true;
    ERPC_DEBUG("Sent udp datagram\n");
    return SYS_ERR_OK;
}

static void enet_rpc_udp_handler(void *st, void *message, size_t bytes, void **response,
                          size_t *response_bytes, struct capref tx_cap,
                          struct capref *rx_cap)
{
    assert(message != NULL);

    errval_t err = SYS_ERR_OK;
    // Setting empty response in advance for all error cases
    *response_bytes = 0;

    if (bytes <= 0) {
        ERPC_DEBUG("Discarding empty rpc message\n");
        return;
    }

    switch (*(uint8_t *)message) {
    case AOS_UDP_LISTEN:
        ERPC_DEBUG("UDP listen request\n");
        err = enet_rpc_udp_listen((struct rpc_udp_listen *)message, bytes, response,
                                  response_bytes);
        break;
    case AOS_UDP_CLOSE:
        ERPC_DEBUG("UDP close request\n");
        break;
    case AOS_UDP_SEND:
        ERPC_DEBUG("UDP send request\n");
        err = enet_rpc_udp_send((struct rpc_udp_send *)message, bytes, response,
                                response_bytes);
        break;
    default:
        ERPC_DEBUG("Discarding message of unkown tpye: 0x%x\n", *(uint8_t *)message);
        return;
    }

    if (err_is_fail(err)) {
        DEBUG_ERR(err, "Failed to handle udp service request");
    }
}

errval_t enet_rpc_init(void)
{
    collections_hash_create(&state.listeners, NULL);
    assert(state.listeners != NULL);

    return nameservice_register(ENET_UDP_SERVICE_NAME, enet_rpc_udp_handler, NULL);
}

errval_t enet_rpc_handle_udp(struct udp_hdr *udp, ip_addr_t src)
{
    nameservice_chan_t chan = collections_hash_find(state.listeners,
                                                    (uint64_t)ntohs(udp->dest));
    if (chan == NULL) {
        ERPC_DEBUG("Dropping udp datagram: Not listening destination port (%d)\n",
                   ntohs(udp->dest));
        return SYS_ERR_OK;
    }

    // Storing the header behind the udp datagram
    // This always works, because udp is a pointer into the original frame from the
    // ethernet driver and this is padded to be always ("a lot") bigger than a max sized
    // ethernet frame could be.
    struct rpc_udp_header *header = (struct rpc_udp_header *)ROUND_UP(
        (lvaddr_t)udp + ntohs(udp->len), sizeof(struct rpc_udp_header));

    header->_reserved = AOS_UDP_SEND;
    header->length = ntohs(udp->len) - sizeof(struct udp_hdr);
    header->src_port = ntohs(udp->src);
    header->dest_port = ntohs(udp->dest);
    header->src_ip = src;

    void *response;
    size_t response_bytes;
    ERPC_DEBUG("Sending udp datagram for port %d\n", ntohs(udp->dest));
    errval_t err = nameservice_rpc(chan, udp + 1,
                                   (lvaddr_t)(header + 1) - (lvaddr_t)(udp + 1),
                                   &response, &response_bytes, NULL_CAP, NULL_CAP);
    return err;
}